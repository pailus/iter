---
name: authentication-weakness
description: Authentication weakness testing — password reset flaws, account enumeration, brute force, MFA bypass, credential stuffing, and OAuth/SSO misconfigurations
---

# Authentication Weaknesses

Authentication is the first gate. Bypass it and the rest of the application's security controls are irrelevant. Test every mechanism: passwords, tokens, OTP, MFA, OAuth, SSO — they each have distinct attack patterns.

## Attack Surface

**Username/Password Authentication**
- Account enumeration via different error messages or response times
- No rate limiting on login endpoint → brute force / credential stuffing
- Default or weak credential acceptance (`admin:admin`, `user:password`)
- Password policy bypassable (spaces, unicode normalization tricks)
- Username case-insensitive but password check case-sensitive inconsistency

**Password Reset Flow**
- Predictable reset tokens (timestamp, sequential, short)
- Reset token not invalidated after use (single-use enforcement)
- Reset token with long or no expiry
- Host header injection in password reset email → token sent to attacker domain
- Reset link sent via HTTP or token in URL (logged in proxy/access logs)
- Security questions with guessable answers

**Multi-Factor Authentication**
- OTP not rate-limited → brute-forceable 6-digit code (10^6 attempts)
- OTP reuse — same TOTP code valid for multiple requests
- OTP bypass by skipping MFA step (directly hitting post-MFA endpoint)
- Backup codes with insufficient entropy
- Remember-device token not tied to IP or user-agent — portable
- SMS OTP interception (SIM swap, SS7) — note as architectural weakness

**OAuth 2.0 / SSO**
- `state` parameter missing or not validated → CSRF on OAuth flow
- Redirect URI not strictly validated → token leakage to attacker domain
- `code` reuse — authorization code valid multiple times
- Implicit flow with `access_token` in URL fragment
- Open redirector in redirect_uri → token exfiltration via Referer

**Account Enumeration**
- Login: "Invalid password" vs "User not found"
- Password reset: "Reset email sent" vs "Email not registered"
- Registration: "Username taken" vs successful registration
- Response time difference (DB lookup hit vs miss)

## Key Vulnerabilities

### Credential Brute Force

```
# No rate limit test: send 50 requests rapidly, observe if any are blocked
for i in $(seq 1 50); do
  curl -s -X POST /login -d 'username=admin&password=test' -o /dev/null -w '%{http_code}\n'
done

# Tools
hydra -l admin -P /usr/share/wordlists/rockyou.txt <target> http-post-form "/login:username=^USER^&password=^PASS^:Invalid"
```

### Password Reset Token Analysis

```
1. Request password reset → capture token in email/response
2. Request 5 more tokens — do they have a pattern? (length, charset, incrementing)
3. Request reset → use token after 25 hours → still valid?
4. Request reset → use token twice → second use succeeds?
5. Request two resets → does first token invalidate when second is requested?
```

### Host Header Injection in Password Reset

```
POST /forgot-password HTTP/1.1
Host: attacker.com   ← inject attacker-controlled domain

If app uses Host header to construct reset URL:
→ reset link in email points to attacker.com
→ victim clicks → token delivered to attacker
```

Test: intercept reset request in Burp, modify `Host:` header, check email for injected URL.

### MFA OTP Brute Force

```
# TOTP is 6 digits = 1,000,000 possibilities
# Rate-limited at 5/min → brute force takes ~138 days
# Unrated-limited → ~17 minutes at 1000 req/s

# Test rate limiting:
POST /mfa/verify  {"otp": "000001"}
POST /mfa/verify  {"otp": "000002"}
... repeat 20 times, observe if rate limiting kicks in
```

### MFA Step Skip

```
1. Login with valid credentials → redirected to /mfa step
2. Directly access /dashboard or /api/user without completing MFA
3. If 200 → MFA step not enforced server-side
```

### OAuth state Parameter Missing

```
1. Initiate OAuth flow: GET /oauth/authorize?client_id=...&redirect_uri=...
2. Check URL for &state=<random> parameter
3. If absent: CSRF attack possible → trick victim's browser into completing OAuth with attacker-controlled code
```

### OAuth Redirect URI Bypass

```
Registered URI: https://app.com/callback
Test variations:
  https://app.com.evil.com/callback      (subdomain)
  https://app.com/callback/../redirect   (path traversal)
  https://app.com/callback?x=           (query string append)
  https://app.com%2Fcallback            (URL encoding)
```

### Account Enumeration Timing

```python
import time, requests

def check_timing(username):
    start = time.perf_counter()
    requests.post('/login', json={'username': username, 'password': 'x'})
    return time.perf_counter() - start

# Valid user: consistent timing (DB hit, bcrypt check)
# Invalid user: shorter timing (DB miss, no hash check)
# Difference > 100ms is exploitable
```

## Testing Methodology

1. **Enumeration** — test login, reset, and registration for different error messages
2. **Rate limiting** — send 20+ rapid login attempts; test per-IP vs per-account limiting
3. **Lockout logic** — trigger lockout on target account (confirm lockout exists, but also confirm attacker can't DoS accounts)
4. **Reset flow** — request token, analyze entropy, test expiry, test single-use, test Host header injection
5. **MFA testing** — OTP rate limit, step-skip, backup code entropy, remember-device portability
6. **OAuth/SSO** — state param, redirect_uri validation, code reuse, implicit flow
7. **Default creds** — try `admin:admin`, `admin:password`, email-as-username with company name as password
8. **Password policy** — test accepted passwords: `a`, `11111111`, common passwords if no blocklist

## Impact

- Full account takeover via credential brute force or stuffing
- Account takeover via predictable reset tokens
- MFA bypass → credentials are the only factor actually checked
- OAuth token theft → silent account linkage to attacker-controlled identity
- Mass account enumeration → targeted phishing list

## Pro Tips

1. Always test `X-Forwarded-For: 127.0.0.1` on rate-limited login — some apps trust this header for IP allowlisting
2. Password reset tokens: use `hashcat --example-hashes` to identify algorithm if you find a hash-like token
3. `ffuf -w /tmp/users.txt -u /api/user/FUZZ -mc 200,400` for account enumeration via endpoint response codes
4. OAuth `state` missing → combine with XSS for one-click account takeover: XSS triggers OAuth flow, attacker receives code via state-less callback
5. TOTP backup codes are often 8-digit numeric — that's only 10^8 permutations: brute-forceable offline if leaked
6. `jwt_tool.py --crack` for weak HS256 JWT secrets; `rockyou.txt` covers most weak secrets
7. Check if app accepts `Authorization: Bearer <old_token>` after password change — token invalidation on password change is commonly missed
8. `nuclei -t exposures/tokens/` scans for hardcoded tokens that may bypass auth entirely
