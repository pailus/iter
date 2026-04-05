---
name: cryptographic-failures
description: Cryptographic failure testing — weak algorithms, broken TLS, insecure key storage, hardcoded secrets, weak hashing, and sensitive data in transit/at rest
---

# Cryptographic Failures

Cryptographic failures occur when data is transmitted or stored without adequate protection — or when the protection itself is broken. Look for sensitive data in cleartext, weak algorithms still in use, hardcoded secrets, and implementation flaws that bypass the math entirely.

## Attack Surface

**Data in Transit**
- HTTP (not HTTPS) for login, payment, or sensitive data submission
- Mixed content: HTTPS page loading HTTP resources
- Weak TLS versions (TLS 1.0, TLS 1.1, SSLv3)
- Weak cipher suites (RC4, DES, 3DES, NULL, EXPORT)
- Missing HSTS or short max-age
- Certificate pinning absent in mobile/API clients

**Data at Rest**
- Passwords stored in plaintext or with reversible encoding (Base64)
- Weak hashing: MD5, SHA-1, unsalted SHA-256 for passwords
- Sensitive data in browser storage (`localStorage`, `sessionStorage`, `IndexedDB`)
- PII in URL parameters (logged in server/proxy access logs)
- Unencrypted database backups exposed via misconfigured cloud storage

**Hardcoded Secrets**
- API keys, tokens, passwords in HTML source, JS bundles, or mobile apps
- `.env` files publicly accessible
- Git history containing secrets (`git log -p`)
- Exposed source maps → original source with secret strings

**Weak Cryptographic Implementation**
- Predictable random values (weak PRNGs for tokens, OTPs, reset links)
- ECB mode block cipher (produces patterns in ciphertext)
- Reused IVs/nonces in CBC or CTR mode
- Padding oracle vulnerabilities (CBC with PKCS#7)
- Timing attacks on MAC/signature comparison

## Key Vulnerabilities

### TLS Audit

Test for weak TLS configurations:
```
Check: TLS 1.0/1.1 supported (should be disabled)
Check: SSLv3 supported (POODLE)
Check: RC4 cipher suites (RFC 7465 prohibits)
Check: EXPORT-grade ciphers (FREAK/LOGJAM)
Check: NULL/anonymous cipher suites
Check: Forward secrecy (DHE/ECDHE key exchange)
Check: Certificate validity, CN/SAN match, chain trust
```

Tools: `testssl.sh`, `sslscan`, `nmap --script ssl-enum-ciphers`

### Heartbleed (CVE-2014-0160)

OpenSSL 1.0.1 through 1.0.1f — send malformed heartbeat to leak up to 64KB of server memory per request. May expose private keys, session tokens, plaintext credentials.

```
nmap -p 443 --script ssl-heartbleed <target>
```

### POODLE / BEAST / DROWN

- **POODLE**: SSLv3 CBC padding oracle → decrypt traffic
- **BEAST**: TLS 1.0 CBC with predictable IV → session hijack
- **DROWN**: SSLv2 enabled → RSA key compromise affects TLS sessions on same key

### Padding Oracle (CBC)

If application uses CBC mode encryption and returns different errors for padding vs MAC failures, attacker can decrypt/forge ciphertext one byte at a time.

Signs:
- Encrypted data in cookies or URL params (not JWT)
- Error responses differ between "invalid padding" and "invalid MAC"
- `ASP.NET_SessionId` + ViewState (classic ASPX padding oracle)

Tool: `padbuster`, `python-paddingoracle`

### Weak Password Hashing

Acceptable hashing: bcrypt, scrypt, argon2, PBKDF2 with high iterations.
Broken hashing (crack with hashcat/john):
```
MD5($pass)           → trivially cracked
SHA1($pass)          → trivially cracked
MD5(MD5($pass))      → still fast, defeated by rainbow tables
SHA256($pass)        → fast hash, no work factor
Base64(password)     → not a hash — reversible encoding
```

Test: register account with known password, request password reset to see if reset link contains plaintext password (stored in plaintext), or check API response for hashed value.

### Hardcoded Secrets Detection

Search in JS source and source maps:
```
/api[_-]?key/i
/secret[_-]?key/i
/password/i
/bearer [a-z0-9]{20,}/i
/AKIA[0-9A-Z]{16}/      ← AWS Access Key ID
/ghp_[a-zA-Z0-9]{36}/  ← GitHub PAT
/sk-[a-zA-Z0-9]{48}/   ← OpenAI API key
```

Check these paths:
- `/.env`, `/.env.production`, `/.env.local`
- `/config.js`, `/config.json`, `/settings.py`
- `/<appname>.config`, `/appsettings.json`
- `sourceMappingURL` → fetch source map → search original source

### Sensitive Data in URLs

PII/tokens in URLs end up in:
- Server access logs
- Browser history
- Referrer headers to third-party domains
- CDN and proxy logs

Look for: `?token=`, `?api_key=`, `?email=`, `?ssn=`, `?password_reset_token=`

### Predictable Tokens

Test password reset tokens, email verification links, session IDs:
1. Request multiple tokens in sequence
2. Analyze for sequential patterns (timestamp-based, counter-based)
3. Check entropy (length < 16 bytes is suspicious)
4. Test if tokens expire (use 24h-old token)
5. Test if tokens are single-use (reuse after successful reset)

## Testing Methodology

1. **TLS audit** — run `testssl.sh` or `sslscan` against all HTTPS endpoints
2. **HTTP detection** — any page that accepts credentials over HTTP?
3. **Secret search** — crawl JS files, source maps, HTML source for API keys/tokens
4. **Cookie analysis** — are sensitive values in cookies encrypted? Check for ECB patterns (repeating blocks)
5. **Password reset flow** — analyze token entropy, expiry, single-use enforcement
6. **Storage audit** — check `localStorage`/`sessionStorage` for sensitive data via browser console
7. **URL audit** — any sensitive data appearing in query strings?
8. **Error-based oracle** — test encrypted params for padding oracle (different error responses)

## Impact

- Private key recovery → complete TLS traffic decryption (Heartbleed)
- Password database cracking → mass account compromise (weak hashing)
- Account takeover via predictable reset tokens
- Secret key extraction → full API/cloud access
- MITM via weak TLS → credential interception

## Pro Tips

1. `testssl.sh --full <host>` gives comprehensive TLS posture in one command
2. Regex search JS bundles: `grep -Eo 'AKIA[0-9A-Z]{16}' bundle.js` for AWS keys
3. ECB mode cookies repeat 16-byte blocks — encrypt the same input twice and compare ciphertext
4. Password reset tokens shorter than 20 characters or URL-safe base64 of 8 bytes are suspicious
5. Check the `Referrer-Policy` header — sensitive URL params may leak to analytics/CDN via Referer
6. `truffleHog`, `gitleaks`, `git-secrets` for history scanning when source access is available
7. Any form that POSTs over HTTP (even on an HTTPS page) is a finding — action attribute matters
