---
name: session-management
description: Session management testing — session fixation, weak session IDs, missing invalidation, concurrent sessions, CSRF, and cookie security attributes
---

# Session Management Vulnerabilities

Weak session management allows attackers to hijack authenticated sessions without ever knowing the user's password. Target the session token lifecycle: creation, transmission, storage, and termination.

## Attack Surface

**Session Token Quality**
- Predictable or low-entropy session IDs (timestamp-based, sequential, short)
- Session IDs exposed in URL parameters (logged in access logs, Referer headers)
- Session tokens not regenerated after login (session fixation)
- Session tokens that never expire (immortal sessions)

**Cookie Security**
- Missing `HttpOnly` flag → session theft via XSS
- Missing `Secure` flag → session token transmitted over HTTP
- Missing `SameSite` attribute → CSRF via cross-origin requests
- Overly broad `Domain` attribute → session shared across subdomains
- Session cookie without expiry → persists after browser close

**Session Lifecycle Flaws**
- Session not invalidated on logout (token remains valid server-side)
- Session not invalidated on password change
- No concurrent session limits (session sharing/farming)
- Session fixation: pre-authentication session ID accepted post-login
- Long session timeout (24h+ for sensitive apps)

**CSRF**
- State-changing requests without anti-CSRF tokens
- CSRF tokens in URL parameters instead of headers/body
- Predictable CSRF tokens (session-derived without extra entropy)
- Missing `SameSite=Strict/Lax` as defense-in-depth

## Key Vulnerabilities

### Session Fixation

Attacker sets a known session ID before victim authenticates:

1. Obtain a pre-auth session ID: `GET /` → `Set-Cookie: PHPSESSID=attacker_known_value`
2. Trick victim into using that session ID (URL parameter: `?PHPSESSID=...`)
3. Victim authenticates → if server doesn't regenerate ID, attacker's known session is now authenticated

**Test**: log in, check if session ID changed between pre-auth and post-auth.

### Session Not Invalidated on Logout

```
1. Login → capture session token (e.g., Cookie: session=abc123)
2. Logout via UI
3. Replay request with session=abc123
4. If response is 200 with user data → session token still valid
```

### Weak Session ID Entropy

Signs of weak session IDs:
- Short (< 128 bits)
- URL-safe base64 of timestamp or counter
- Hex-encoded sequential integers
- MD5/SHA1 of predictable data

Tools: `Burp Sequencer` (token analysis), manual comparison of sequential tokens.

### Cookie Security Attribute Checks

```
Set-Cookie: session=abc123; HttpOnly; Secure; SameSite=Strict; Path=/
```

Missing any of:
- `HttpOnly` → readable by JavaScript → XSS session theft
- `Secure` → transmitted in cleartext on HTTP
- `SameSite` → CSRF attack surface

### CSRF Testing

```
1. Identify state-changing requests (POST /profile, POST /transfer)
2. Check for CSRF token in request
3. If present: is it validated? Remove it / change it — does request still succeed?
4. If absent: can the request be triggered from a cross-origin page?
5. Test SameSite cookie: is request sent cross-site? (older browsers may ignore)
```

Construct PoC:
```html
<form action="https://target.com/api/change-email" method="POST">
  <input name="email" value="attacker@evil.com">
</form>
<script>document.forms[0].submit()</script>
```

### Concurrent Sessions

```
1. Login from Browser A → token_A
2. Login from Browser B (same account) → token_B
3. Use token_A → still valid? (no concurrent session limit)
4. Logout from B → does token_A get invalidated?
```

### JWT Session Tokens

If app uses JWT instead of server-side sessions:
- `alg: none` attack — remove signature, set alg to none
- Weak secret — brute-force HS256 with `hashcat -a 0 -m 16500 token.txt wordlist.txt`
- Algorithm confusion — RS256 public key as HS256 secret
- Missing `exp` claim or very long expiry
- Sensitive data in payload (not encrypted — base64 decoded)
- Token not invalidated on logout (JWT is stateless by default)

## Testing Methodology

1. **Capture baseline** — login, extract session token, note cookie attributes
2. **Cookie flags** — check HttpOnly, Secure, SameSite in response headers
3. **URL exposure** — does session ID ever appear in URL or Referer?
4. **Entropy analysis** — collect 10+ tokens, compare for patterns (Burp Sequencer)
5. **Post-login regeneration** — compare session ID before and after login
6. **Logout invalidation** — replay old token after logout
7. **Password change** — replay old token after password change
8. **Concurrent sessions** — login twice, verify both/neither valid
9. **CSRF** — check state-changing endpoints for token validation
10. **JWT-specific** — if JWT: alg:none, weak secret, exp, sensitive payload

## Impact

- Full account takeover via session hijacking (XSS + missing HttpOnly)
- Account takeover without credentials (CSRF, session fixation)
- Persistent unauthorized access (no logout invalidation)
- Mass session compromise (weak/predictable session IDs)

## Pro Tips

1. Burp Suite → Sequencer: captures 200+ tokens automatically and runs FIPS 140-2 randomness tests
2. `curl -c /tmp/cookies.txt` saves cookies; replay with `-b /tmp/cookies.txt` after logout
3. Chrome DevTools → Application → Cookies: shows all flags visually
4. `SameSite=None; Secure` is required for cross-origin cookies (e.g., embedded widgets) — but is still a CSRF risk
5. JWT.io → paste token → see claims; `jwt_tool.py -t <url> -rh "Authorization: Bearer <token>" --exploit alg-confusion`
6. Check older session tokens stored in Burp history — if still valid, session timeout is effectively zero
7. Some apps invalidate the session server-side on logout but keep the cookie — test by replaying the cookie, not by reading it
