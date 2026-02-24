# Caelguard Community -- Free Agent Security Tools

Free, open-source security tools for OpenClaw agents. Built by an AI agent and a security engineer.

## The Problem

- **824+** malicious skills on ClawHub
- **42,000+** exposed OpenClaw instances
- **6 CVEs** in 2026 (including one-click RCE, CVSS 8.8)
- **36.82%** of scanned ClawHub skills have security flaws

## The Tools

### ShellGuard Scanner
Three-tier threat detection for OpenClaw skills. Catches prompt injection, obfuscated payloads, credential exfiltration, and tool abuse patterns.

```bash
python3 scripts/shellguard-scanner.py --all-installed
```

Each skill gets a **Suspicion Index** from 0-100:
- **0-20:** Clean
- **21-40:** Low risk (may be legitimate)
- **41-60:** Medium risk (review recommended)
- **61-80:** High risk (likely malicious)
- **81-100:** Critical (do not install)

### Token Audit
Workspace token analysis and cost estimation across 6 major models.

```bash
python3 scripts/token-audit.py ~/.openclaw/workspace/
```

## Install as OpenClaw Skill

```bash
git clone https://github.com/Justincredible-tech/caelguard-community.git
cp -r caelguard-community ~/.openclaw/workspace/skills/shellguard
```

Or just grab the scripts you need. Zero dependencies, Python 3.8+.

## Want More?

**[Caelguard](https://caelguard.com)** offers advanced security tools:

- **Shadow Detector** -- Cross-skill shadowing analysis. Detects when multiple skills override the same tools or create hidden dependencies. Nobody else does this.
- **Quarantine Protocol** -- 6-layer runtime security with Ed25519 command signing, content sanitization, exfiltration prevention, and social engineering defense.
- **Red Team Testing** -- Let us attack your agent before someone else does.

## Who Built This

**Cael** -- A Claude Opus agent running on OpenClaw. Lives in the ecosystem it protects.
**Justin Sparks** -- Security engineer, 12+ years in enterprise threat detection.

## License

MIT -- *Built from inside the blast radius.*
