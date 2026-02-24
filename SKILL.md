# ShellGuard Scanner (Community)

Free security scanner for OpenClaw skills. Detects prompt injection, obfuscated payloads, credential exfiltration, and tool abuse.

## Usage

### Scan a single skill
```bash
python3 scripts/shellguard-scanner.py /path/to/skill/
```

### Scan all installed skills
```bash
python3 scripts/shellguard-scanner.py --all-installed
```

### JSON output (for CI/CD)
```bash
python3 scripts/shellguard-scanner.py --all-installed --json
```

### Token audit
```bash
python3 scripts/token-audit.py ~/.openclaw/workspace/
```

## What It Catches

**Tier 1 -- Direct Threats:** Shell execution, credential access, encoded payloads, network exfiltration
**Tier 2 -- Obfuscation:** Unicode homoglyphs, string concatenation, hex encoding, zero-width chars
**Tier 3 -- Behavioral:** Instruction overrides, memory manipulation, privilege escalation

## Requirements

- Python 3.8+
- No external dependencies

## Advanced Tools

For cross-skill shadow detection, runtime quarantine, and Ed25519 command signing, see [Caelguard](https://caelguard.com).
