---
name: trufflehog
description: Usage of TruffleHog for scanning git repositories and files for high-entropy secrets and exposed API keys, utilizing built-in credential verification.
---

# TruffleHog - Secret Scanning & Verification

TruffleHog is an extremely powerful open-source tool designed to dig into Git repositories or filesystem directories to find leaked credentials, API keys, and sensitive tokens.

What distinguishes TruffleHog from other scanners is its ability to **dynamically verify** the discovered secrets. If it finds an AWS Key or a GitHub token, it automatically makes a safe API call to verify if the token is actually active/live, eliminating false positives.

## Core Commands

### 1. Scanning a Public Git Repository
If targeting an open-source project or exposed `.git` directory:
```bash
trufflehog git https://github.com/target-org/repository.git
```

### 2. Scanning a Private Git Repository
If you have access via a specific credential or token:
```bash
trufflehog git https://<username>:<token>@github.com/org/repo.git
```

### 3. Scanning a Local Directory
When you have downloaded source code or extracted an archive (e.g., an unpacked APK, a reverse-engineered Node.js app, or decompiled `.jar`):
```bash
trufflehog filesystem /path/to/source/code/
```

## Advanced Flags

### 1. Output as JSON
For programmatic parsing or exporting findings:
```bash
trufflehog filesystem /path/to/code --json > secrets_found.json
```

### 2. Scanning without Verification (Fail-fast)
If the target machine running TruffleHog doesn't have internet access, or if you want speed over precision and don't want to tip off the target via API calls:
```bash
trufflehog filesystem /path/to/code --no-verification
```

## Pentesting Strategy
*   **Javascript Files:** In Web Pentesting, always download massive JS bundles (`app.js`, `chunk.js`) and run TruffleHog on them to find hardcoded Stripe, Firebase, or AWS keys.
*   **Commits History:** Developers often accidentally commit a password and then "delete" it in the next commit. Since TruffleHog scans git history, it will find secrets that are no longer in the current visible code.
