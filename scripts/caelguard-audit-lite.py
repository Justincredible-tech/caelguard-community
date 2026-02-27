#!/usr/bin/env python3
"""
Caelguard Instance Audit (Community Edition) -- Quick security check for OpenClaw.

Runs 20 essential checks across 5 categories. Zero dependencies.
For the full 47-check audit with auto-fix, framework mapping, and threat intelligence,
see: https://github.com/Justincredible-tech/caelguard

Usage:
    python3 caelguard-audit-lite.py
    python3 caelguard-audit-lite.py --json

Copyright (c) 2026 Caelguard. MIT License.
"""

import glob
import hashlib
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from typing import List, Optional, Tuple

VERSION = "1.0.0"

class C:
    RED = "\033[91m"
    ORANGE = "\033[38;5;208m"
    YELLOW = "\033[93m"
    GREEN = "\033[92m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"
    UNDERLINE = "\033[4m"
    WHITE = "\033[97m"


class Finding:
    def __init__(self, check_id, category, title, severity, status, detail="", remediation=""):
        self.check_id = check_id
        self.category = category
        self.title = title
        self.severity = severity
        self.status = status
        self.detail = detail
        self.remediation = remediation

    def to_dict(self):
        return {k: v for k, v in self.__dict__.items()}


def _read_json(path):
    try:
        with open(path) as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError, OSError):
        return None


def _run(cmd, timeout=10):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout, r.stderr
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return -1, "", ""


def _file_perms(path):
    try:
        return os.stat(path).st_mode & 0o777
    except OSError:
        return None


class AuditLite:
    def __init__(self):
        self.workspace = os.environ.get("OPENCLAW_WORKSPACE",
            os.path.expanduser("~/.openclaw/workspace"))
        self.openclaw_dir = os.path.expanduser("~/.openclaw")
        self.findings: List[Finding] = []
        # Find config
        self.config_path = None
        for p in [f"{self.openclaw_dir}/openclaw.json",
                  f"{self.openclaw_dir}/agents/main/openclaw.json"]:
            if os.path.exists(p):
                self.config_path = p
                break
        self.config = _read_json(self.config_path) if self.config_path else None

    def _add(self, f):
        self.findings.append(f)

    # -- Gateway (5 checks) --

    def check_gateway_binding(self):
        rc, out, _ = _run(["ss", "-tlnp"])
        exposed = []
        if rc == 0:
            for line in out.split("\n"):
                if "0.0.0.0:" in line:
                    for p in line.split():
                        if "0.0.0.0:" in p:
                            port = p.split(":")[-1]
                            if port.isdigit() and 3000 <= int(port) <= 4000:
                                exposed.append(port)
        if exposed:
            self._add(Finding("GW-01", "gateway", "Gateway bound to 0.0.0.0",
                "CRITICAL", "FAIL",
                f"Exposed on port(s): {', '.join(set(exposed))}",
                "Bind gateway to 127.0.0.1 in openclaw.json"))
        else:
            self._add(Finding("GW-01", "gateway", "Gateway binding", "INFO", "PASS",
                "Not bound to 0.0.0.0 on common ports"))

    def check_tls(self):
        cfg = self.config or {}
        tls = cfg.get("gateway", {}).get("tls", {})
        if not (tls.get("cert") or tls.get("key")):
            self._add(Finding("GW-02", "gateway", "No TLS configured",
                "HIGH", "FAIL", "Traffic is unencrypted",
                "Configure TLS or use a reverse proxy"))
        else:
            self._add(Finding("GW-02", "gateway", "TLS", "INFO", "PASS", "TLS configured"))

    def check_control_ui(self):
        cfg = self.config or {}
        ctrl = cfg.get("controlUi", cfg.get("control_ui", {}))
        if ctrl.get("allowInsecureAuth", ctrl.get("allow_insecure_auth", False)):
            self._add(Finding("GW-04", "gateway", "Insecure auth enabled",
                "HIGH", "FAIL", "controlUi.allowInsecureAuth is true",
                "Set to false in openclaw.json"))
        else:
            self._add(Finding("GW-04", "gateway", "Control UI auth", "INFO", "PASS", "Secure"))

    def check_firewall(self):
        rc, out, _ = _run(["ufw", "status"])
        if rc == 0 and "active" in out.lower():
            self._add(Finding("GW-08", "gateway", "Firewall", "INFO", "PASS", "UFW active"))
            return
        rc, out, _ = _run(["iptables", "-L", "-n"])
        if rc == 0 and out.strip().count("\n") > 5:
            self._add(Finding("GW-08", "gateway", "Firewall", "INFO", "PASS", "iptables configured"))
            return
        self._add(Finding("GW-08", "gateway", "No firewall detected",
            "HIGH", "FAIL", "No active firewall",
            "sudo ufw enable && sudo ufw default deny incoming"))

    def check_version(self):
        rc, out, _ = _run(["openclaw", "--version"])
        self._add(Finding("GW-10", "gateway", "OpenClaw version",
            "INFO", "PASS" if rc == 0 else "SKIP", out.strip() if rc == 0 else "Unknown"))

    # -- Credentials (5 checks) --

    def check_plaintext_tokens(self):
        patterns = [
            (r"sk-[a-zA-Z0-9]{20,}", "OpenAI key"),
            (r"sk-ant-[a-zA-Z0-9\-]{20,}", "Anthropic key"),
            (r"AKIA[0-9A-Z]{16}", "AWS key"),
            (r"ghp_[a-zA-Z0-9]{36}", "GitHub PAT"),
        ]
        files = []
        for ext in ["*.json", "*.yaml", "*.yml", "*.env", "*.toml"]:
            files.extend(glob.glob(os.path.join(self.openclaw_dir, "**", ext), recursive=True))
        
        exposed = []
        for fpath in files:
            try:
                with open(fpath, "r", errors="replace") as f:
                    content = f.read()
                for pat, name in patterns:
                    if re.search(pat, content):
                        exposed.append(f"{name} in {os.path.relpath(fpath, self.openclaw_dir)}")
            except (OSError, IOError):
                continue
        
        if exposed:
            self._add(Finding("CR-01", "credentials", "Plaintext API tokens",
                "CRITICAL", "FAIL",
                f"{len(exposed)} exposed: " + "; ".join(exposed[:5]),
                "Move to encrypted storage. Rotate exposed keys."))
        else:
            self._add(Finding("CR-01", "credentials", "Token scan", "INFO", "PASS",
                f"Scanned {len(files)} files, clean"))

    def check_env_perms(self):
        envs = glob.glob(os.path.join(self.openclaw_dir, "**", ".env*"), recursive=True)
        envs += glob.glob(os.path.join(self.workspace, "**", ".env*"), recursive=True)
        bad = [f"{os.path.basename(e)} ({oct(_file_perms(e))})" for e in envs
               if _file_perms(e) is not None and _file_perms(e) & 0o044]
        if bad:
            self._add(Finding("CR-02", "credentials", ".env files world-readable",
                "HIGH", "FAIL", "; ".join(bad), "chmod 600 on .env files"))
        else:
            self._add(Finding("CR-02", "credentials", ".env permissions", "INFO", "PASS",
                f"{len(envs)} .env file(s) OK"))

    def check_ssh_keys(self):
        ssh_dir = os.path.expanduser("~/.ssh")
        if not os.path.isdir(ssh_dir):
            self._add(Finding("CR-04", "credentials", "SSH keys", "INFO", "PASS", "No .ssh dir"))
            return
        bad = []
        for f in os.listdir(ssh_dir):
            fp = os.path.join(ssh_dir, f)
            if os.path.isfile(fp) and not f.endswith(".pub"):
                p = _file_perms(fp)
                if p is not None and p & 0o077:
                    bad.append(f"{f} ({oct(p)})")
        if bad:
            self._add(Finding("CR-04", "credentials", "SSH keys too permissive",
                "HIGH", "FAIL", "; ".join(bad), "chmod 600 on private keys"))
        else:
            self._add(Finding("CR-04", "credentials", "SSH key perms", "INFO", "PASS", "OK"))

    def check_git_creds(self):
        for repo in [self.workspace, self.openclaw_dir]:
            gc = os.path.join(repo, ".git", "config")
            if os.path.exists(gc):
                try:
                    with open(gc) as f:
                        if re.search(r"https://[a-zA-Z0-9_]+@", f.read()):
                            self._add(Finding("CR-06", "credentials", "Token in git URL",
                                "HIGH", "FAIL", gc, "Use credential helpers instead"))
                            return
                except (OSError, IOError):
                    pass
        self._add(Finding("CR-06", "credentials", "Git credentials", "INFO", "PASS", "Clean"))

    def check_auth_profiles(self):
        afs = glob.glob(os.path.join(self.openclaw_dir, "**/auth-profiles.json"), recursive=True)
        bad = [os.path.relpath(a, self.openclaw_dir) for a in afs
               if _file_perms(a) is not None and _file_perms(a) & 0o044]
        if bad:
            self._add(Finding("CR-05", "credentials", "Auth profiles world-readable",
                "HIGH", "FAIL", "; ".join(bad), "chmod 600"))
        elif afs:
            self._add(Finding("CR-05", "credentials", "Auth profiles", "INFO", "PASS", "Secured"))
        else:
            self._add(Finding("CR-05", "credentials", "Auth profiles", "INFO", "PASS", "None found"))

    # -- Permissions (3 checks) --

    def check_workspace_perms(self):
        p = _file_perms(self.workspace)
        if p is not None and p & 0o002:
            self._add(Finding("FP-01", "permissions", "Workspace world-writable",
                "CRITICAL", "FAIL", f"Permissions: {oct(p)}", "chmod 750"))
        else:
            self._add(Finding("FP-01", "permissions", "Workspace permissions",
                "INFO", "PASS", f"{oct(p) if p else 'unknown'}"))

    def check_cognitive_perms(self):
        bad = []
        for fname in ["SOUL.md", "AGENTS.md", "IDENTITY.md"]:
            fp = os.path.join(self.workspace, fname)
            if os.path.exists(fp):
                p = _file_perms(fp)
                if p is not None and p & 0o022:
                    bad.append(f"{fname} ({oct(p)})")
        if bad:
            self._add(Finding("FP-03", "permissions", "Cognitive files writable",
                "HIGH", "FAIL", "; ".join(bad), "chmod 644"))
        else:
            self._add(Finding("FP-03", "permissions", "Cognitive file perms",
                "INFO", "PASS", "OK"))

    def check_skills_perms(self):
        sd = os.path.join(self.workspace, "skills")
        if not os.path.isdir(sd):
            self._add(Finding("FP-02", "permissions", "Skills dir", "INFO", "SKIP", "Not found"))
            return
        p = _file_perms(sd)
        if p is not None and p & 0o002:
            self._add(Finding("FP-02", "permissions", "Skills dir world-writable",
                "HIGH", "FAIL", f"{oct(p)}", "chmod 750"))
        else:
            self._add(Finding("FP-02", "permissions", "Skills dir perms", "INFO", "PASS", "OK"))

    # -- Supply Chain (4 checks) --

    def check_skill_count(self):
        sd = os.path.join(self.workspace, "skills")
        if not os.path.isdir(sd):
            self._add(Finding("SC-01", "supply", "Skills", "INFO", "SKIP", "No skills dir"))
            return
        skills = [d for d in os.listdir(sd) if os.path.isdir(os.path.join(sd, d))]
        status = "WARN" if len(skills) > 30 else "PASS"
        self._add(Finding("SC-01", "supply", "Installed skills",
            "LOW" if status == "WARN" else "INFO", status, f"{len(skills)} skills"))

    def check_typosquats(self):
        sd = os.path.join(self.workspace, "skills")
        if not os.path.isdir(sd):
            self._add(Finding("SC-03", "supply", "Typosquat", "INFO", "SKIP", "No skills"))
            return
        common = ["web-search", "code", "git", "github", "spotify", "docker",
                  "calendar", "email", "tts", "browser", "search", "memory", "shell"]
        installed = [d for d in os.listdir(sd) if os.path.isdir(os.path.join(sd, d))]
        suspects = []
        for skill in installed:
            for c in common:
                if skill != c and skill not in common:
                    d = sum(a != b for a, b in zip(skill.lower(), c.lower())) + abs(len(skill) - len(c))
                    if 0 < d <= 2:
                        suspects.append(f"'{skill}' ~ '{c}'")
        if suspects:
            self._add(Finding("SC-03", "supply", "Possible typosquats",
                "HIGH", "WARN", "; ".join(suspects),
                "Verify these skills. Run ShellGuard Scanner."))
        else:
            self._add(Finding("SC-03", "supply", "Typosquat check", "INFO", "PASS", "Clean"))

    def check_skill_integrity_baseline(self):
        if os.path.exists(os.path.join(self.workspace, ".skill-hashes.json")):
            self._add(Finding("SC-04", "supply", "Skill baseline", "INFO", "PASS", "Exists"))
        else:
            self._add(Finding("SC-04", "supply", "No skill integrity baseline",
                "MEDIUM", "WARN", "Cannot detect unauthorized modifications",
                "Establish a baseline with ShellGuard"))

    def check_cognitive_integrity(self):
        for fname in ["SOUL.md", "AGENTS.md"]:
            if not os.path.exists(os.path.join(self.workspace, fname)):
                self._add(Finding("MI-05", "memory", f"Missing {fname}",
                    "MEDIUM", "WARN", f"{fname} not found", "Create it"))
                return
        self._add(Finding("MI-05", "memory", "Cognitive files", "INFO", "PASS", "Present"))

    # -- Execution (3 checks) --

    def check_exec_mode(self):
        cfg = self.config or {}
        mode = (cfg.get("tools", {}).get("exec", {}).get("security", "") or
                cfg.get("agent", {}).get("tools", {}).get("exec", {}).get("security", ""))
        if mode == "full":
            self._add(Finding("EX-01", "execution", "Exec mode is 'full'",
                "HIGH", "WARN", "Agent can run any command",
                "Consider 'allowlist' mode"))
        else:
            self._add(Finding("EX-01", "execution", "Exec mode", "INFO", "PASS",
                f"{mode or 'default'}"))

    def check_container(self):
        in_container = (os.path.exists("/.dockerenv") or
                       os.path.exists("/run/.containerenv") or
                       os.environ.get("container") is not None)
        if not in_container:
            try:
                with open("/proc/1/cgroup") as f:
                    if any(x in f.read() for x in ["docker", "lxc", "containerd"]):
                        in_container = True
            except (OSError, IOError):
                pass
        if in_container:
            self._add(Finding("EX-02", "execution", "Container", "INFO", "PASS", "Isolated"))
        else:
            self._add(Finding("EX-02", "execution", "No container isolation",
                "MEDIUM", "WARN", "Direct host access", "Consider Docker"))

    def check_elevated(self):
        cfg = self.config or {}
        if cfg.get("tools", {}).get("exec", {}).get("elevated", False):
            self._add(Finding("EX-04", "execution", "Elevated exec enabled",
                "HIGH", "FAIL", "Agent can run as root", "Disable unless required"))
        else:
            self._add(Finding("EX-04", "execution", "Elevated exec", "INFO", "PASS", "Disabled"))

    # -- Run --

    def run_all(self):
        checks = [
            self.check_gateway_binding, self.check_tls, self.check_control_ui,
            self.check_firewall, self.check_version,
            self.check_plaintext_tokens, self.check_env_perms, self.check_ssh_keys,
            self.check_git_creds, self.check_auth_profiles,
            self.check_workspace_perms, self.check_cognitive_perms, self.check_skills_perms,
            self.check_skill_count, self.check_typosquats,
            self.check_skill_integrity_baseline, self.check_cognitive_integrity,
            self.check_exec_mode, self.check_container, self.check_elevated,
        ]
        for fn in checks:
            try:
                fn()
            except Exception as e:
                self._add(Finding("ERR", "error", fn.__name__, "LOW", "SKIP", str(e)))

    def score(self):
        weights = {"CRITICAL": 15, "HIGH": 8, "MEDIUM": 4, "LOW": 1, "INFO": 0}
        deductions = sum(weights.get(f.severity, 0) for f in self.findings
                        if f.status in ("FAIL", "WARN"))
        s = max(0, 100 - deductions)
        grade = "A" if s >= 90 else "B" if s >= 75 else "C" if s >= 60 else "D" if s >= 40 else "F"
        return {
            "score": s, "grade": grade,
            "total": len(self.findings),
            "passed": sum(1 for f in self.findings if f.status == "PASS"),
            "failed": sum(1 for f in self.findings if f.status == "FAIL"),
            "warnings": sum(1 for f in self.findings if f.status == "WARN"),
        }


def print_report(auditor):
    s = auditor.score()
    gc = {
        "A": C.GREEN, "B": C.GREEN, "C": C.YELLOW, "D": C.ORANGE, "F": C.RED
    }.get(s["grade"], C.WHITE)

    print()
    print(f"  {C.BOLD}{C.CYAN}{'=' * 55}{C.RESET}")
    print(f"  {C.BOLD}{C.CYAN}  CAELGUARD AUDIT (Community) v{VERSION}{C.RESET}")
    print(f"  {C.BOLD}{C.CYAN}{'=' * 55}{C.RESET}")
    print()
    print(f"  {C.BOLD}Score:{C.RESET}  {gc}{C.BOLD}{s['score']}/100 ({s['grade']}){C.RESET}")
    print(f"  {C.BOLD}Checks:{C.RESET} {s['total']} | "
          f"{C.GREEN}{s['passed']} pass{C.RESET} | "
          f"{C.RED}{s['failed']} fail{C.RESET} | "
          f"{C.YELLOW}{s['warnings']} warn{C.RESET}")
    print()

    issues = [f for f in auditor.findings if f.status in ("FAIL", "WARN")]
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    issues.sort(key=lambda f: sev_order.get(f.severity, 4))

    if issues:
        print(f"  {C.BOLD}{C.UNDERLINE}Issues ({len(issues)}){C.RESET}")
        print()
        for f in issues:
            sc = {"CRITICAL": C.RED, "HIGH": C.ORANGE, "MEDIUM": C.YELLOW, "LOW": C.DIM}.get(f.severity, "")
            si = {"FAIL": f"{C.RED}FAIL{C.RESET}", "WARN": f"{C.YELLOW}WARN{C.RESET}"}.get(f.status, "")
            print(f"  [{f.check_id}] {si} {sc}{C.BOLD}{f.severity}{C.RESET} {f.title}")
            if f.detail:
                print(f"    {C.DIM}{f.detail}{C.RESET}")
            if f.remediation:
                print(f"    {C.CYAN}Fix: {f.remediation}{C.RESET}")
            print()
    else:
        print(f"  {C.GREEN}{C.BOLD}All clear!{C.RESET}")
        print()

    print(f"  {C.DIM}For the full 47-check audit with auto-fix, threat intelligence,{C.RESET}")
    print(f"  {C.DIM}and OWASP mapping: https://github.com/Justincredible-tech/caelguard{C.RESET}")
    print()


def main():
    import argparse
    parser = argparse.ArgumentParser(prog="caelguard-audit-lite",
        description="Caelguard Instance Audit (Community) -- Quick security check")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--workspace", "-w")
    parser.add_argument("--version", action="version", version=f"v{VERSION}")
    args = parser.parse_args()

    auditor = AuditLite()
    if args.workspace:
        auditor.workspace = args.workspace
    auditor.run_all()

    if args.json:
        print(json.dumps({
            "version": VERSION,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "score": auditor.score(),
            "findings": [f.to_dict() for f in auditor.findings],
        }, indent=2))
    else:
        print_report(auditor)

    s = auditor.score()
    sys.exit(2 if any(f.severity == "CRITICAL" and f.status == "FAIL"
                      for f in auditor.findings) else
             1 if s["failed"] > 0 else 0)


if __name__ == "__main__":
    main()