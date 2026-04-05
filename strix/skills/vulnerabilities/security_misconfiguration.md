---
name: security-misconfiguration
description: Security misconfiguration testing — default credentials, exposed admin interfaces, cloud storage, unnecessary services, verbose errors, and hardening gaps
---

# Security Misconfiguration

Security misconfiguration is the most common finding in web applications. Every layer of the stack — server, framework, database, cloud, container — ships with insecure defaults. Enumerate broadly, validate quickly, and chain access.

## Attack Surface

**Default Credentials**
- Admin panels, CMS backends, database UIs, monitoring dashboards
- Network devices, IoT, CI/CD tools (Jenkins, GitLab, Grafana, Kibana, Flower)
- Default combos: `admin:admin`, `admin:password`, `admin:`, `root:root`, `test:test`

**Exposed Admin Interfaces**
- `/admin`, `/administrator`, `/wp-admin`, `/manager`, `/console`, `/_admin`
- `/phpmyadmin`, `/adminer`, `/pgadmin`, `/redis-commander`
- Tomcat Manager (`/manager/html`), JBoss, GlassFish, WebLogic consoles
- Spring Boot Actuator: `/actuator`, `/actuator/env`, `/actuator/beans`, `/actuator/heapdump`
- Django debug: `/admin/`, error pages with `DEBUG=True`
- Laravel Telescope: `/telescope`, Horizon: `/horizon`
- Kubernetes dashboard, Docker API (`:2375`/`:2376`)

**Cloud Storage Misconfiguration**
- AWS S3: `s3://<bucket>`, `https://<bucket>.s3.amazonaws.com/`
- GCS: `https://storage.googleapis.com/<bucket>/`
- Azure Blob: `https://<account>.blob.core.windows.net/<container>/`
- Public bucket enumeration: list objects, download sensitive files
- Writable buckets: upload arbitrary files, overwrite static assets

**Verbose Error Messages**
- Stack traces exposing framework, version, file paths, DB schema
- Full SQL errors showing table/column names and queries
- Exception handlers returning internal IP addresses or hostnames

**Unnecessary Services & Features**
- Debug endpoints left enabled in production
- CORS set to `*` across all origins and methods
- Directory listing enabled (Apache, nginx autoindex)
- Server banners: `Server:`, `X-Powered-By:`, `X-AspNet-Version:` headers
- HTTP TRACE/TRACK methods enabled (can aid XSS via header reflection)
- Unused HTTP methods (PUT/DELETE) on endpoints that should be read-only

**Certificate & TLS Issues**
- Self-signed certs accepted in production
- Mixed content (HTTP resources on HTTPS pages)
- Missing HSTS header or short max-age

## Key Vulnerabilities

### Default & Weak Credentials

```
Common targets: Jenkins, Grafana, Kibana, Portainer, RabbitMQ, Flower
Test: HTTP Basic Auth, form-based login, API key headers
Tools: hydra, medusa, custom scripts with wordlists
```

### Spring Boot Actuator Exposure

High-value endpoints when `/actuator` is reachable:
- `/actuator/env` — environment variables including secrets, DB passwords
- `/actuator/heapdump` — full JVM heap dump (extract creds, tokens, PII)
- `/actuator/loggers` — change log level to TRACE to expose sensitive data
- `/actuator/mappings` — full route map of the application
- `/actuator/beans` — Spring context beans (reveals internal structure)

### Directory Traversal via Misconfiguration

```nginx
# nginx alias misconfiguration
location /static {
    alias /var/www/app/;
}
# → /static../secret.conf leaks /var/www/secret.conf
```

### CORS Wildcard

```
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true  # this combination is invalid per spec but some browsers allow it
```
Test: can credentials (cookies, auth headers) cross origins?

### Security Header Gaps

Check for absence of:
- `Content-Security-Policy`
- `X-Frame-Options` or `frame-ancestors`
- `X-Content-Type-Options: nosniff`
- `Strict-Transport-Security`
- `Permissions-Policy`

## Testing Methodology

1. **Fingerprint stack** — server header, error pages, default paths, JS bundle comments
2. **Enumerate admin paths** — ffuf/feroxbuster with admin wordlists
3. **Test default credentials** — per technology detected (Jenkins, Grafana, etc.)
4. **Cloud storage** — construct bucket names from app/org name, try list/download
5. **Actuator & debug endpoints** — tech-specific sensitive endpoints
6. **Check HTTP methods** — OPTIONS on each endpoint, try PUT/DELETE/TRACE
7. **Review response headers** — security headers present and correct
8. **Error triggering** — send malformed input to provoke verbose errors
9. **TLS audit** — check cert validity, HSTS, protocol versions

## High-Value Findings

- **Default creds on admin panel** → full application compromise
- **Actuator `/heapdump`** → plaintext secrets extracted from memory
- **S3 public write** → supply chain attack via static asset replacement
- **Directory listing** → source code, config files, backup archives
- **Spring `DEBUG=True` in prod** → interactive debugger PIN bypass → RCE

## Impact

- Full admin access via default credentials
- Secret/credential leakage from environment endpoints or heap dumps
- Data exfiltration from misconfigured cloud storage
- Supply chain compromise via writable public assets
- Information disclosure that enables chained attacks

## Pro Tips

1. Always check `/actuator` on Java apps — even partial exposure is critical
2. Construct S3 bucket names: `<appname>-prod`, `<appname>-backup`, `<company>-assets`
3. Apache Struts, GlassFish, JBoss have well-known default admin paths — always try them
4. `DEBUG=True` in Django shows the settings file in error pages — look for `SECRET_KEY`, DB creds
5. Check `/.git/config`, `/.env`, `/config.yml`, `/backup.sql` — misconfigured deployments leave these public
6. TRACE method enables XSS via `Cross-Site Tracing` on older apps — check if enabled
