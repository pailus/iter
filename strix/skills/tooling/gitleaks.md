---
name: gitleaks
description: Usage of Gitleaks to statically identify hardcoded secrets like passwords, api keys, and tokens in git repositories and files. Extremely fast and regex-driven.
---

# Gitleaks - Fast Static Secret Scanning

Gitleaks is a highly efficient, regex-driven static analysis tool designed specifically for discovering hardcoded secrets (API keys, passwords, database URIs) in codebases.

Unlike TruffleHog which focuses heavily on verifying the keys by making outbound internet requests, Gitleaks excels in **speed, customizability, and strict static regex rules**.

## Basic Commands

### 1. Scan a Local Git Repository
To scan the entire history of a cloned git repository:
```bash
gitleaks detect --source=/path/to/repo -v
```
*(The `-v` or `--verbose` flag shows the exact secret and the line it was found on).*

### 2. Scan a Raw Filesystem Directory
To scan a folder containing code without `.git` history (e.g., downloaded source code):
```bash
gitleaks detect --no-git --source=/path/to/code -v
```

## Advanced Filtering

### 1. Output Parsing
Save findings in JSON format for the agent to parse later or CSV:
```bash
gitleaks detect --source=/path/to/repo -v --report-format json --report-path findings.json
```

### 2. Scanning specific Extensions / Path Ignoring
Sometimes you want to ignore large vendor folders (like `node_modules` or `venv`) or test sets to cut out noise. While Gitleaks ignores some by default, if needed, you can pipe output through `grep -v` or utilize an `.gitleaksignore` file when available.
```bash
# E.g., fast scan output
gitleaks detect --source=/app/src --no-git -v | grep "Secret:"
```

## Strategy Use-Case in Agent Workflows
If an agent attains arbitrary file read (Path Traversal/LFI) or unpacks a binary/archive, running `gitleaks detect --no-git` against the folder provides rapid enumeration of `.env` patterns, hardcoded PostgreSQL connection strings, and JWT signing keys that developers left behind.
