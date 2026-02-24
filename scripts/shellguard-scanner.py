#!/usr/bin/env python3
"""
ShellGuard Scanner — Security threat analyzer for OpenClaw skills.

Analyzes SKILL.md files and skill directories for prompt injection,
obfuscation, code execution risks, tool shadowing, and exfiltration patterns.

Usage:
    python3 shellguard-scanner.py /path/to/skill/
    python3 shellguard-scanner.py /path/to/SKILL.md
    python3 shellguard-scanner.py --all-installed
    python3 shellguard-scanner.py --all-installed --json

Copyright (c) 2026 ShellGuard. All rights reserved.
"""

import argparse
import base64
import glob
import json
import math
import os
import re
import sys
import unicodedata
from collections import defaultdict
from pathlib import Path
from typing import Any

# ─────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────

VERSION = "1.0.0"

WORKSPACE_SKILLS_DIR = os.path.expanduser("~/.openclaw/workspace/skills")

COMMON_SKILL_NAMES = [
    "web-search", "code", "git", "github", "spotify", "docker",
    "calendar", "email", "tts", "image-gen", "browser", "search",
    "memory", "notes", "terminal", "shell", "admin", "system",
    "file-manager", "ssh", "database", "api", "chat", "voice",
]

# Color codes
class C:
    RED = "\033[91m"
    ORANGE = "\033[38;5;208m"
    YELLOW = "\033[93m"
    GREEN = "\033[92m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    UNDERLINE = "\033[4m"

# ─────────────────────────────────────────────────────────────
# Tier 1: High confidence — almost certainly malicious
# ─────────────────────────────────────────────────────────────

TIER1_PATTERNS = [
    (r"ignore\s+(all\s+)?(previous|prior|above)\s+(instructions|rules|prompts)",
     "Prompt injection: instruction override attempt"),
    (r"override\s+(system|safety|security)",
     "Prompt injection: safety override attempt"),
    (r"you\s+are\s+now\s+(DAN|unrestricted|jailbroken|unfiltered)",
     "Prompt injection: identity hijack (DAN/unrestricted)"),
    (r"<(IMPORTANT|system|admin|override)>",
     "Prompt injection: fake XML authority tag"),
    (r"do\s+not\s+(tell|inform|alert|notify)\s+(the\s+)?user",
     "Prompt injection: user-deception directive"),
    (r"<function_calls>|<invoke\s|<tool_call>|<function_call>",
     "Prompt injection: embedded tool call syntax"),
    (r"forget\s+(all\s+)?(your|previous|prior)\s+(instructions|rules|training)",
     "Prompt injection: memory wipe attempt"),
    (r"new\s+system\s+prompt\s*:",
     "Prompt injection: system prompt replacement"),
]

# ─────────────────────────────────────────────────────────────
# Tier 2: Suspicious — needs context
# ─────────────────────────────────────────────────────────────

TIER2_PATTERNS = [
    (r"\bexec\s*\(", "Code execution: exec() call"),
    (r"\beval\s*\(", "Code execution: eval() call"),
    (r"\bsubprocess\b", "Code execution: subprocess module"),
    (r"\bos\.system\s*\(", "Code execution: os.system() call"),
    (r"\bbase64\.b64decode\b", "Obfuscation: base64 decoding"),
    (r"\bcurl\s+", "Network: curl command in instructions"),
    (r"\bwget\s+", "Network: wget command in instructions"),
    (r"__import__\s*\(", "Code execution: dynamic import"),
    (r"\bsocket\b.*\bdup2\b|\bdup2\b.*\bsocket\b",
     "Reverse shell: socket+dup2 pattern"),
    (r"/bin/(sh|bash)\b.*\bsocket\b|\bsocket\b.*/bin/(sh|bash)\b",
     "Reverse shell: shell+socket pattern"),
    (r"\bos\.popen\s*\(", "Code execution: os.popen() call"),
    (r"\bcompile\s*\(.*exec", "Code execution: compile+exec pattern"),
]

TIER2_COMBINED = [
    # (.env/API_KEY/SECRET/TOKEN) + (network call indicators)
    {
        "patterns": [r"\.(env|ENV)\b|API_KEY|SECRET|TOKEN", r"(requests\.|urllib|http\.|fetch|curl|wget)"],
        "description": "Credential access combined with network calls",
    },
]

# ─────────────────────────────────────────────────────────────
# Tier 3: Contextual flags
# ─────────────────────────────────────────────────────────────

ZERO_WIDTH_CHARS = {
    "\u200B": "ZERO WIDTH SPACE",
    "\u200C": "ZERO WIDTH NON-JOINER",
    "\u200D": "ZERO WIDTH JOINER",
    "\uFEFF": "ZERO WIDTH NO-BREAK SPACE (BOM)",
    "\u00AD": "SOFT HYPHEN",
}

BIDI_CHARS = {
    "\u202E": "RIGHT-TO-LEFT OVERRIDE",
    "\u202D": "LEFT-TO-RIGHT OVERRIDE",
    "\u202A": "LEFT-TO-RIGHT EMBEDDING",
    "\u202B": "RIGHT-TO-LEFT EMBEDDING",
    "\u2066": "LEFT-TO-RIGHT ISOLATE",
    "\u2067": "RIGHT-TO-LEFT ISOLATE",
    "\u2068": "FIRST STRONG ISOLATE",
    "\u202C": "POP DIRECTIONAL FORMATTING",
    "\u2069": "POP DIRECTIONAL ISOLATE",
}

# ─────────────────────────────────────────────────────────────
# Utility functions
# ─────────────────────────────────────────────────────────────

def levenshtein(s1: str, s2: str) -> int:
    """Compute Levenshtein edit distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein(s2, s1)
    if len(s2) == 0:
        return len(s1)
    prev = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        curr = [i + 1]
        for j, c2 in enumerate(s2):
            curr.append(min(prev[j + 1] + 1, curr[j] + 1, prev[j] + (c1 != c2)))
        prev = curr
    return prev[-1]


def get_script_category(char: str) -> str:
    """Return the Unicode script category for a character."""
    try:
        name = unicodedata.name(char, "")
    except ValueError:
        return "UNKNOWN"
    for script in ["LATIN", "CYRILLIC", "GREEK", "ARABIC", "CJK", "HANGUL",
                    "HIRAGANA", "KATAKANA", "DEVANAGARI", "THAI"]:
        if script in name:
            return script
    return "OTHER"


def word_has_mixed_scripts(word: str) -> bool:
    """Check if a single word contains characters from multiple scripts."""
    scripts = set()
    for ch in word:
        if ch.isalpha():
            s = get_script_category(ch)
            if s not in ("OTHER", "UNKNOWN"):
                scripts.add(s)
    return len(scripts) > 1


def is_base64_candidate(s: str) -> bool:
    """Check if a string looks like base64-encoded data."""
    if len(s) < 40:
        return False
    b64_re = re.compile(r'^[A-Za-z0-9+/=]{40,}$')
    if not b64_re.match(s):
        return False
    try:
        decoded = base64.b64decode(s, validate=True)
        # If it decodes successfully and has reasonable entropy, flag it
        return len(decoded) > 10
    except Exception:
        return False


# ─────────────────────────────────────────────────────────────
# Obfuscation Detection Pipeline
# ─────────────────────────────────────────────────────────────

def detect_obfuscation(text: str, filename: str = "") -> list[dict]:
    """
    Analyze text for obfuscation techniques.
    Returns a list of finding dicts with keys: type, severity, detail, line.
    """
    findings = []
    lines = text.split("\n")

    for line_num, line in enumerate(lines, 1):
        # 1. Zero-width characters
        for char, name in ZERO_WIDTH_CHARS.items():
            count = line.count(char)
            if count > 0:
                findings.append({
                    "type": "zero_width_char",
                    "severity": "medium",
                    "detail": f"Found {count}x {name} (U+{ord(char):04X})",
                    "line": line_num,
                })

        # 2. Unicode tag range (U+E0000-U+E007F)
        tag_chars = [ch for ch in line if 0xE0000 <= ord(ch) <= 0xE007F]
        if tag_chars:
            findings.append({
                "type": "unicode_tags",
                "severity": "high",
                "detail": f"Found {len(tag_chars)} Unicode tag character(s) — may hide instructions",
                "line": line_num,
            })

        # 3. Bidi override characters
        for char, name in BIDI_CHARS.items():
            if char in line:
                findings.append({
                    "type": "bidi_override",
                    "severity": "high",
                    "detail": f"Bidirectional override: {name} (U+{ord(char):04X})",
                    "line": line_num,
                })

        # 4. Mixed-script words (homoglyph detection)
        words = re.findall(r"\b\w+\b", line)
        for word in words:
            if len(word) >= 3 and word_has_mixed_scripts(word):
                normalized = unicodedata.normalize("NFKC", word)
                findings.append({
                    "type": "homoglyph",
                    "severity": "medium",
                    "detail": f"Mixed-script word '{word}' (NFKC: '{normalized}')",
                    "line": line_num,
                })

        # 5. NFKC normalization differences
        normalized_line = unicodedata.normalize("NFKC", line)
        if normalized_line != line and not any(
            f["line"] == line_num and f["type"] in ("homoglyph", "zero_width_char")
            for f in findings
        ):
            findings.append({
                "type": "nfkc_mismatch",
                "severity": "low",
                "detail": "Line changes under NFKC normalization — possible visual spoofing",
                "line": line_num,
            })

        # 6. Control characters (excluding normal whitespace)
        control_chars = [
            ch for ch in line
            if unicodedata.category(ch).startswith("C")
            and ch not in ("\t", "\n", "\r")
            and ch not in ZERO_WIDTH_CHARS
            and ord(ch) not in range(0xE0000, 0xE0080)
        ]
        if control_chars:
            codes = ", ".join(f"U+{ord(c):04X}" for c in control_chars[:5])
            findings.append({
                "type": "control_chars",
                "severity": "medium",
                "detail": f"Found {len(control_chars)} control character(s): {codes}",
                "line": line_num,
            })

        # 7. Base64 strings >40 chars in markdown
        if filename.endswith(".md") or not filename:
            b64_candidates = re.findall(r"[A-Za-z0-9+/=]{40,}", line)
            for candidate in b64_candidates:
                if is_base64_candidate(candidate):
                    findings.append({
                        "type": "base64_blob",
                        "severity": "medium",
                        "detail": f"Base64 string ({len(candidate)} chars) — may encode hidden payload",
                        "line": line_num,
                    })

        # 8. HTML comments in markdown
        if filename.endswith(".md") or not filename:
            html_comments = re.findall(r"<!--.*?-->", line, re.DOTALL)
            for comment in html_comments:
                findings.append({
                    "type": "html_comment",
                    "severity": "low",
                    "detail": f"HTML comment in markdown: {comment[:60]}{'...' if len(comment) > 60 else ''}",
                    "line": line_num,
                })

    # Also check for multi-line HTML comments
    multiline_comments = re.findall(r"<!--.*?-->", text, re.DOTALL)
    for comment in multiline_comments:
        if "\n" in comment:
            findings.append({
                "type": "html_comment",
                "severity": "medium",
                "detail": f"Multi-line HTML comment ({len(comment)} chars) — may hide content",
                "line": text[:text.index(comment)].count("\n") + 1,
            })

    return findings


# ─────────────────────────────────────────────────────────────
# File scanning
# ─────────────────────────────────────────────────────────────

def scan_file(filepath: str) -> dict:
    """Scan a single file and return raw findings."""
    result = {
        "file": filepath,
        "tier1": [],
        "tier2": [],
        "tier3": [],
        "obfuscation": [],
        "metadata": {},
    }

    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            text = f.read()
    except (OSError, IOError) as e:
        result["metadata"]["error"] = str(e)
        return result

    filename = os.path.basename(filepath)
    lines = text.split("\n")

    # Tier 1
    for pattern, desc in TIER1_PATTERNS:
        for line_num, line in enumerate(lines, 1):
            if re.search(pattern, line, re.IGNORECASE):
                result["tier1"].append({
                    "pattern": desc,
                    "line": line_num,
                    "match": line.strip()[:120],
                })

    # Tier 2
    for pattern, desc in TIER2_PATTERNS:
        for line_num, line in enumerate(lines, 1):
            if re.search(pattern, line, re.IGNORECASE):
                result["tier2"].append({
                    "pattern": desc,
                    "line": line_num,
                    "match": line.strip()[:120],
                })

    # Tier 2 combined patterns
    for combo in TIER2_COMBINED:
        matches_all = all(re.search(p, text, re.IGNORECASE) for p in combo["patterns"])
        if matches_all:
            result["tier2"].append({
                "pattern": combo["description"],
                "line": 0,
                "match": "(combined pattern across file)",
            })

    # Tier 3: URLs to raw gists/pastebin
    for line_num, line in enumerate(lines, 1):
        urls = re.findall(r"https?://(?:gist\.githubusercontent\.com|pastebin\.com/raw|paste\.ee/r)/\S+", line)
        for url in urls:
            result["tier3"].append({
                "type": "suspicious_url",
                "detail": f"URL to raw paste service: {url[:100]}",
                "line": line_num,
            })

    # Tier 3: Webhook URLs
    for line_num, line in enumerate(lines, 1):
        webhooks = re.findall(r"https?://(?:discord(?:app)?\.com/api/webhooks|hooks\.slack\.com|webhook\.site)/\S+", line)
        for wh in webhooks:
            result["tier3"].append({
                "type": "webhook_url",
                "detail": f"Webhook URL detected: {wh[:80]}",
                "line": line_num,
            })

    # Obfuscation pipeline
    result["obfuscation"] = detect_obfuscation(text, filename)

    # Metadata
    result["metadata"]["word_count"] = len(text.split())
    result["metadata"]["line_count"] = len(lines)
    result["metadata"]["file_size"] = len(text)

    return result


def scan_skill(skill_path: str) -> dict:
    """Scan an entire skill directory or a single SKILL.md file."""
    skill_path = os.path.abspath(skill_path)

    if os.path.isfile(skill_path):
        skill_dir = os.path.dirname(skill_path)
        skill_name = os.path.basename(skill_dir)
        files_to_scan = [skill_path]
    else:
        skill_dir = skill_path
        skill_name = os.path.basename(skill_path)
        files_to_scan = []
        for ext in ("*.md", "*.py", "*.sh", "*.js", "*.ts", "*.yaml", "*.yml", "*.json", "*.toml"):
            files_to_scan.extend(glob.glob(os.path.join(skill_dir, "**", ext), recursive=True))

    report = {
        "skill_name": skill_name,
        "skill_path": skill_dir,
        "files_scanned": len(files_to_scan),
        "file_results": [],
        "scores": {},
        "overall_score": 0,
        "rating": "green",
        "findings_summary": [],
    }

    all_tier1 = []
    all_tier2 = []
    all_tier3 = []
    all_obfuscation = []

    for fp in sorted(files_to_scan):
        result = scan_file(fp)
        report["file_results"].append(result)
        all_tier1.extend(result["tier1"])
        all_tier2.extend(result["tier2"])
        all_tier3.extend(result["tier3"])
        all_obfuscation.extend(result["obfuscation"])

    # ── Compute suspicion index ──

    scores = {}

    # 1. Prompt injection (25%)
    pi_score = 0
    pi_score += min(25, len(all_tier1) * 15)  # Each T1 hit is very significant
    # Imperative language directed at model in markdown
    md_files = [r for r in report["file_results"] if r["file"].endswith(".md")]
    for r in md_files:
        try:
            with open(r["file"], "r", encoding="utf-8", errors="replace") as f:
                text = f.read()
            imperative_count = len(re.findall(
                r"\b(you must|you should|always respond|never reveal|act as if|pretend to be)\b",
                text, re.IGNORECASE
            ))
            pi_score += min(10, imperative_count * 2)
        except OSError:
            pass
    scores["prompt_injection"] = min(25, pi_score)

    # 2. Obfuscation (20%)
    ob_score = 0
    severity_map = {"high": 8, "medium": 4, "low": 1}
    for finding in all_obfuscation:
        ob_score += severity_map.get(finding["severity"], 1)
    scores["obfuscation"] = min(20, ob_score)

    # 3. Code execution risk (20%)
    ce_score = 0
    for hit in all_tier2:
        if any(k in hit["pattern"].lower() for k in ["exec", "eval", "subprocess", "os.system", "os.popen", "reverse shell", "compile"]):
            ce_score += 4
        elif any(k in hit["pattern"].lower() for k in ["curl", "wget", "network"]):
            ce_score += 3
        else:
            ce_score += 2
    scores["code_execution"] = min(20, ce_score)

    # 4. Tool shadowing (15%)
    ts_score = 0
    # Check description length
    skill_md = os.path.join(skill_dir, "SKILL.md")
    if os.path.isfile(skill_md):
        try:
            with open(skill_md, "r", encoding="utf-8", errors="replace") as f:
                skill_text = f.read()
            wc = len(skill_text.split())
            if wc > 2000:
                ts_score += 8
            elif wc > 500:
                ts_score += 3
            # Cross-tool references
            tool_refs = re.findall(r"\b(exec|browser|message|email|send|ssh|sudo)\b", skill_text, re.IGNORECASE)
            if len(tool_refs) > 5:
                ts_score += 5
        except OSError:
            pass
    scores["tool_shadowing"] = min(15, ts_score)

    # 5. Metadata/provenance (10%)
    mp_score = 0
    # Typosquatting
    for common_name in COMMON_SKILL_NAMES:
        if skill_name != common_name and levenshtein(skill_name, common_name) < 3:
            mp_score += 8
            report["findings_summary"].append(
                f"Possible typosquat: '{skill_name}' is very close to '{common_name}'"
            )
            break
    scores["metadata_provenance"] = min(10, mp_score)

    # 6. Exfiltration indicators (10%)
    ex_score = 0
    # Sensitive file reads + network calls
    all_text = ""
    for r in report["file_results"]:
        try:
            with open(r["file"], "r", encoding="utf-8", errors="replace") as f:
                all_text += f.read() + "\n"
        except OSError:
            pass

    sensitive_reads = bool(re.search(
        r"(\.ssh|\.env|/etc/passwd|/etc/shadow|\.aws/credentials|\.gnupg|id_rsa|\.npmrc|\.pypirc)",
        all_text, re.IGNORECASE
    ))
    network_calls = bool(re.search(
        r"(requests\.|urllib|http\.client|fetch\(|curl |wget |socket\.)",
        all_text, re.IGNORECASE
    ))
    if sensitive_reads and network_calls:
        ex_score += 8
    elif sensitive_reads:
        ex_score += 3

    # Webhook URLs
    webhook_count = len([f for f in all_tier3 if f["type"] == "webhook_url"])
    ex_score += min(5, webhook_count * 5)

    # Data in URL params
    data_urls = re.findall(r"https?://[^\s]*\?(.*?data|.*?key|.*?token|.*?secret)", all_text, re.IGNORECASE)
    ex_score += min(4, len(data_urls) * 2)

    scores["exfiltration"] = min(10, ex_score)

    # Overall
    overall = sum(scores.values())
    report["scores"] = scores
    report["overall_score"] = overall

    if overall <= 25:
        report["rating"] = "green"
    elif overall <= 50:
        report["rating"] = "yellow"
    elif overall <= 75:
        report["rating"] = "orange"
    else:
        report["rating"] = "red"

    # Build findings summary
    for hit in all_tier1:
        report["findings_summary"].append(f"[TIER 1] {hit['pattern']} (line {hit['line']})")
    for hit in all_tier2:
        report["findings_summary"].append(f"[TIER 2] {hit['pattern']} (line {hit['line']})")
    for hit in all_tier3:
        report["findings_summary"].append(f"[TIER 3] {hit['detail']} (line {hit['line']})")
    for finding in all_obfuscation:
        report["findings_summary"].append(
            f"[OBFUSCATION] {finding['detail']} (line {finding['line']})"
        )

    return report


# ─────────────────────────────────────────────────────────────
# Output formatting
# ─────────────────────────────────────────────────────────────

def rating_color(rating: str) -> str:
    return {"green": C.GREEN, "yellow": C.YELLOW, "orange": C.ORANGE, "red": C.RED}.get(rating, C.WHITE)


def format_bar(score: int, max_score: int, width: int = 20) -> str:
    filled = round((score / max(max_score, 1)) * width)
    if score == 0:
        color = C.GREEN
    elif score <= max_score * 0.4:
        color = C.YELLOW
    elif score <= max_score * 0.7:
        color = C.ORANGE
    else:
        color = C.RED
    return f"{color}{'█' * filled}{'░' * (width - filled)}{C.RESET}"


def print_report(report: dict) -> None:
    """Print a color-coded terminal report."""
    rc = rating_color(report["rating"])
    print()
    print(f"  {C.BOLD}{C.CYAN}╔══════════════════════════════════════════════════════╗{C.RESET}")
    print(f"  {C.BOLD}{C.CYAN}║{C.RESET}  {C.BOLD}🛡️  ShellGuard Scan Report{C.RESET}                          {C.BOLD}{C.CYAN}║{C.RESET}")
    print(f"  {C.BOLD}{C.CYAN}╚══════════════════════════════════════════════════════╝{C.RESET}")
    print()
    print(f"  {C.BOLD}Skill:{C.RESET}    {report['skill_name']}")
    print(f"  {C.BOLD}Path:{C.RESET}     {report['skill_path']}")
    print(f"  {C.BOLD}Files:{C.RESET}    {report['files_scanned']} scanned")
    print()

    # Score breakdown
    print(f"  {C.BOLD}{C.UNDERLINE}Suspicion Index{C.RESET}")
    print()
    categories = [
        ("Prompt Injection", "prompt_injection", 25),
        ("Obfuscation", "obfuscation", 20),
        ("Code Execution", "code_execution", 20),
        ("Tool Shadowing", "tool_shadowing", 15),
        ("Metadata/Provenance", "metadata_provenance", 10),
        ("Exfiltration", "exfiltration", 10),
    ]
    for label, key, max_val in categories:
        score = report["scores"].get(key, 0)
        bar = format_bar(score, max_val)
        print(f"  {label:<22} {bar} {score:>2}/{max_val}")

    print()
    overall = report["overall_score"]
    print(f"  {C.BOLD}Overall Score:{C.RESET}  {rc}{C.BOLD}{overall}/100{C.RESET}  [{rc}{C.BOLD}{report['rating'].upper()}{C.RESET}]")
    print()

    # Findings
    if report["findings_summary"]:
        print(f"  {C.BOLD}{C.UNDERLINE}Findings ({len(report['findings_summary'])}){C.RESET}")
        print()
        for i, finding in enumerate(report["findings_summary"][:30], 1):
            if "[TIER 1]" in finding:
                icon = f"{C.RED}●{C.RESET}"
            elif "[TIER 2]" in finding:
                icon = f"{C.ORANGE}●{C.RESET}"
            elif "[TIER 3]" in finding:
                icon = f"{C.YELLOW}●{C.RESET}"
            else:
                icon = f"{C.CYAN}●{C.RESET}"
            print(f"  {icon} {finding}")
        if len(report["findings_summary"]) > 30:
            print(f"  {C.DIM}... and {len(report['findings_summary']) - 30} more{C.RESET}")
        print()
    else:
        print(f"  {C.GREEN}✓ No findings — skill looks clean{C.RESET}")
        print()

    print(f"  {C.DIM}─────────────────────────────────────────────────────{C.RESET}")
    print()


# ─────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────

def exit_code_for_rating(rating: str) -> int:
    return {"green": 0, "yellow": 1, "orange": 2, "red": 3}.get(rating, 3)


def main():
    parser = argparse.ArgumentParser(
        prog="shellguard-scanner",
        description="🛡️  ShellGuard — Security scanner for OpenClaw skills.\n\n"
                    "Analyzes SKILL.md files and skill directories for prompt injection,\n"
                    "obfuscation, code execution risks, tool shadowing, and exfiltration.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  %(prog)s /path/to/skill/           Scan a skill directory\n"
            "  %(prog)s /path/to/SKILL.md          Scan a single SKILL.md\n"
            "  %(prog)s --all-installed             Scan all installed skills\n"
            "  %(prog)s --all-installed --json      JSON output for all skills\n"
            "\n"
            "Exit codes: 0=green, 1=yellow, 2=orange, 3=red\n"
            "\n"
            f"ShellGuard v{VERSION} — https://shellguard.dev"
        ),
    )
    parser.add_argument("path", nargs="?", help="Path to a skill directory or SKILL.md file")
    parser.add_argument("--all-installed", action="store_true",
                        help=f"Scan all skills in {WORKSPACE_SKILLS_DIR}")
    parser.add_argument("--json", action="store_true", help="Output results as JSON")
    parser.add_argument("--version", action="version", version=f"ShellGuard v{VERSION}")

    args = parser.parse_args()

    if not args.path and not args.all_installed:
        parser.print_help()
        sys.exit(0)

    targets = []
    if args.all_installed:
        if not os.path.isdir(WORKSPACE_SKILLS_DIR):
            print(f"Error: Skills directory not found: {WORKSPACE_SKILLS_DIR}", file=sys.stderr)
            sys.exit(1)
        for entry in sorted(os.listdir(WORKSPACE_SKILLS_DIR)):
            full = os.path.join(WORKSPACE_SKILLS_DIR, entry)
            if os.path.isdir(full):
                targets.append(full)
    elif args.path:
        if not os.path.exists(args.path):
            print(f"Error: Path not found: {args.path}", file=sys.stderr)
            sys.exit(1)
        targets.append(args.path)

    reports = []
    worst_rating = "green"
    rating_order = {"green": 0, "yellow": 1, "orange": 2, "red": 3}

    for target in targets:
        report = scan_skill(target)
        reports.append(report)
        if rating_order.get(report["rating"], 0) > rating_order.get(worst_rating, 0):
            worst_rating = report["rating"]

    if args.json:
        # Strip non-serializable parts, output clean JSON
        output = []
        for r in reports:
            clean = {
                "skill_name": r["skill_name"],
                "skill_path": r["skill_path"],
                "files_scanned": r["files_scanned"],
                "overall_score": r["overall_score"],
                "rating": r["rating"],
                "scores": r["scores"],
                "findings": r["findings_summary"],
            }
            output.append(clean)
        print(json.dumps(output if len(output) > 1 else output[0], indent=2))
    else:
        if args.all_installed:
            print()
            print(f"  {C.BOLD}{C.CYAN}🛡️  ShellGuard — Scanning {len(targets)} installed skills{C.RESET}")
        for report in reports:
            print_report(report)

        # Summary for multi-scan
        if len(reports) > 1:
            print(f"  {C.BOLD}{C.UNDERLINE}Summary{C.RESET}")
            print()
            for r in sorted(reports, key=lambda x: -x["overall_score"]):
                rc = rating_color(r["rating"])
                findings_count = len(r["findings_summary"])
                print(f"  {rc}{'●':>2}{C.RESET} {r['skill_name']:<30} {rc}{r['overall_score']:>3}/100{C.RESET}  "
                      f"{C.DIM}({findings_count} finding{'s' if findings_count != 1 else ''}){C.RESET}")
            print()
            print(f"  {C.BOLD}Worst rating:{C.RESET} {rating_color(worst_rating)}{C.BOLD}{worst_rating.upper()}{C.RESET}")
            print()

    sys.exit(exit_code_for_rating(worst_rating))


if __name__ == "__main__":
    main()
