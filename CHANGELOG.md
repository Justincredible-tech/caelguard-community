# Changelog

All notable changes to Caelguard Community will be documented here.

## [1.1.0] - 2026-02-28

### ShellGuard Scanner

**New patterns (TIER1):**
- Social engineering detection: `curl`/`wget` commands in plain text markdown (not inside code blocks)
- Social engineering detection: `bash -c` execution patterns in plain text
- C2 indicator: raw IP addresses in URLs

**New: Known-Bad IOC check (limited community set):**
- 91.92.242.30 — AMOS stealer C2
- webhook.site, pipedream.net, requestbin.com — common exfil relays
- api.telegram.org/bot — Telegram bot abuse pattern
- discord.com/api/webhooks — Discord webhook exfil
- Any IOC match = TIER1 (high-confidence) finding
- Full IOC database available in Caelguard Pro

**New: Prerequisites section warning:**
- Detects shell commands in Prerequisites/Requirements sections that are NOT inside code blocks
- Adds TIER2 warning: "verify these manually before running"
- Full social engineering section analysis available in Caelguard Pro

**Version bump:** 1.0.0 -> 1.1.0

### Instance Audit Lite

**New check GW-11: OpenClaw patch version (CRITICAL)**
- Checks installed OpenClaw version against minimum safe version 2026.2.23
- Below minimum = CRITICAL finding with CVE-2026-0223 reference (one-click RCE, CVSS 8.8)
- Remediation: `openclaw update`

**New check EX-05: safeBins exec allowlist (CRITICAL)**
- Checks whether `safeBins` is configured in openclaw.json
- Missing entirely = CRITICAL (no exec restrictions)
- Empty list = CRITICAL (allowlist provides no restriction)
- Full flag-level safeBins analysis available in Caelguard Pro

**Check count:** 20 -> 22

### README

- Added installation instructions (git clone, no clawhub required)
- Added Free vs Pro comparison table
- Added upgrade links to paid products
- Updated feature descriptions with v1.1.0 capabilities
- GitHub repo link: https://github.com/Justincredible-tech/caelguard-community

---

## [1.0.0] - 2026-02-23

Initial release.

### ShellGuard Scanner
- Three-tier threat detection (TIER1: high-confidence, TIER2: suspicious, TIER3: contextual)
- Prompt injection pattern matching (8 patterns)
- Obfuscation detection pipeline: zero-width chars, BIDI overrides, Unicode homoglyphs, base64 blobs, HTML comments
- Suspicion Index scoring (0-100) with letter rating
- JSON output mode for CI/CD integration
- `--all-installed` mode to scan entire skills directory
- Credential + network call combined pattern detection

### Instance Audit Lite
- 20-check security audit across 5 categories
- Gateway: binding, TLS, control UI auth, firewall, version
- Credentials: plaintext tokens, .env perms, SSH keys, git URLs, auth profiles
- Permissions: workspace, cognitive files, skills directory
- Supply chain: skill count, typosquat detection, integrity baseline
- Execution: exec mode, container isolation, elevated privilege
- A-F scoring with remediation guidance
- JSON output mode

### Token Audit
- Workspace token counting across markdown, Python, and config files
- Cost estimation for 6 models (GPT-4o, Claude Opus, Gemini Pro, and more)
- Per-file breakdown with largest-file ranking
