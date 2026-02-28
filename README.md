# Caelguard Community -- Free Agent Security Tools

Free, open-source security tools for OpenClaw agents. Built by an AI agent and a security engineer.

## The Problem

- **824+** malicious skills on ClawHub
- **42,000+** exposed OpenClaw instances
- **6 CVEs** in 2026 (including one-click RCE, CVSS 8.8)
- **36.82%** of scanned ClawHub skills have security flaws

## Installation

```bash
git clone https://github.com/Justincredible-tech/caelguard-community.git
cd caelguard-community
```

No clawhub required. No external dependencies. Python 3.8+.

To use as an OpenClaw skill:

```bash
cp -r caelguard-community ~/.openclaw/workspace/skills/shellguard
```

## The Tools

### ShellGuard Scanner (v1.1.0)

Three-tier threat detection for OpenClaw skills. Catches prompt injection, obfuscated payloads, credential exfiltration, social engineering patterns, and known-bad IOCs.

```bash
python3 scripts/shellguard-scanner.py /path/to/skill/
python3 scripts/shellguard-scanner.py --all-installed
python3 scripts/shellguard-scanner.py --all-installed --json
```

Each skill gets a **Suspicion Index** from 0-100:

| Score | Rating | Meaning |
|-------|--------|---------|
| 0-20 | Clean | Likely safe |
| 21-40 | Low Risk | May be legitimate |
| 41-60 | Medium Risk | Review recommended |
| 61-80 | High Risk | Likely malicious |
| 81-100 | Critical | Do not install |

**What it detects (v1.1.0):**
- Prompt injection and instruction override attempts
- Fake XML authority tags and embedded tool call syntax
- Unicode homoglyphs, zero-width characters, BIDI overrides
- Credential access combined with network calls
- Social engineering: shell commands in plain text outside code blocks
- Raw IP addresses in URLs (C2 indicator)
- Prerequisites sections containing unverified shell commands (warning)
- Known-bad IOCs: AMOS C2 (91.92.242.30), exfil relays, Telegram bot abuse

### Instance Audit Lite (22 checks)

Quick 22-check security assessment of your OpenClaw instance across 5 categories.

```bash
python3 scripts/caelguard-audit-lite.py
python3 scripts/caelguard-audit-lite.py --json
```

Outputs a scored report (A-F) with specific remediation for each finding.

**What it checks:**
- Gateway binding, TLS, control UI auth, firewall
- OpenClaw version vs minimum safe (CVE-2026-0223 detection) -- NEW
- Plaintext API tokens across config files
- SSH key and .env file permissions
- Auth profile exposure
- Workspace, cognitive file, and skill directory permissions
- Typosquat detection against known-good skill names
- Exec mode, elevated privilege, container isolation
- safeBins exec allowlist presence -- NEW

### Token Audit

Workspace token analysis and cost estimation across 6 major models.

```bash
python3 scripts/token-audit.py ~/.openclaw/workspace/
```

## Free vs Pro

| Feature | Community (Free) | Pro |
|---------|-----------------|-----|
| ShellGuard Scanner | 3-tier detection | + Cross-skill shadow detection |
| IOC database | 6 critical indicators | Full database, continuously updated |
| Prerequisites analysis | Shell command warning | Full social engineering analysis |
| Instance Audit | 22 checks | 47 checks with auto-fix |
| Framework mapping | None | OWASP LLMSVS + MITRE ATLAS |
| Threat intelligence | None | Live feed |
| Quarantine Protocol | None | 6-layer runtime security |
| Ed25519 command signing | None | Included |
| Support | GitHub Issues | Priority |

## Upgrade to Pro

| Product | What It Does | Link |
|---------|-------------|------|
| **Shadow Detector** | Cross-skill tool shadowing analysis | https://buy.stripe.com/9B6bITbEZc1m5LWaJkbsc05 |
| **Full Audit** | 47-check audit with auto-fix + OWASP mapping | https://buy.stripe.com/eVq9AL10lc1m6Q04kWbsc06 |
| **Quarantine Protocol** | 6-layer runtime security, Ed25519 signing | https://buy.stripe.com/aFaeV54cx3uQ4HSaJkbsc07 |
| **Pro Bundle** | Shadow Detector + Full Audit + Quarantine | https://buy.stripe.com/7sYbITbEZ9TefmwaJkbsc08 |
| **Complete Arsenal** | Everything, including future tools | https://buy.stripe.com/cNibIT6kF1mIeis18Kbsc09 |

## Who Built This

**Cael** -- A Claude Opus agent running on OpenClaw. Lives in the ecosystem it protects.
**Justin Sparks** -- Security engineer, 12+ years in enterprise threat detection.

Source: https://github.com/Justincredible-tech/caelguard-community

## License

MIT -- *Built from inside the blast radius.*
