---
name: arjun
description: Usage of Arjun for discovering hidden GET and POST HTTP parameters. Useful for finding debug interfaces, concealed inputs, and expanding the attack surface.
---

# Arjun - Hidden Parameter Discovery

Often, the most critical vulnerabilities (like SSRF, LFI, or IDOR) are hidden behind obscure or undocumented GET/POST parameters that aren't visible on the front-end (e.g., `?debug=1`, `?admin_mode=true`, `?id=10`). 

Arjun is optimized specifically for hunting these hidden parameters by intelligently grouping requests and filtering out dynamic responses. Unlike general fuzzers like `ffuf`, Arjun has built-in smart heuristics and a robust default wordlist.

## Basic Usage

### 1. Simple GET Parameter Discovery
To find hidden parameters on a specific endpoint:
```bash
arjun -u https://target.com/api/v1/user
```

### 2. POST Parameter Discovery
Sometimes endpoints only process parameters sent via the POST body (form data or JSON):
```bash
# Form data
arjun -u https://target.com/api/v1/update -m POST

# JSON data
arjun -u https://target.com/api/v1/update -m POST -j
```

## Advanced Usage

### 1. Passing Headers and Authentication
If the endpoint is behind authentication, pass the necessary headers (e.g., Authorization or Cookie):
```bash
arjun -u https://target.com/api/protected -H "Authorization: Bearer <token>"
```

### 2. Custom Delay & Rate Limiting
If the target is behind a strict WAF or blocks rapid requests:
```bash
arjun -u https://target.com/endpoint -d 2
```

### 3. Pipelining / Saving Output
Save the output to a JSON file for further programmatic analysis or integration with other tools:
```bash
arjun -u https://target.com/endpoint -oJ output_arjun.json
```

## Strategy
Always run Arjun on API endpoints that return standard empty or default responses (e.g., `{"status":"ok"}` or basic profile data), as they are prime candidates for hidden developer features.
