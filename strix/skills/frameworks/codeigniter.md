---
name: codeigniter
description: Specialized techniques for exploiting CodeIgniter applications (CI3 & CI4), focusing on session manipulation, loose routing, and predictable configurations.
---

# CodeIgniter Exploitation & Pentesting

CodeIgniter (especially CI v3 and the newer CI v4) is a lightweight PHP framework heavily used in legacy and enterprise systems. Its architecture provides speed but relies heavily on the developer properly utilizing its security tools.

## 1. Session Manipulation & Deserialization

### CodeIgniter 3
CI3 typically handled sessions via cookies (in older configurations) or files/database. 
*   **Cookie Forgery:** If sessions are stored entirely in a cookie and the `$config['encryption_key']` is leaked (often found in `application/config/config.php` via an LFI), you can reconstruct and modify the session payload to escalate privileges.
*   **Deserialization Risks:** CI3 utilizes PHP serialization for object storage. If user data is blindly passed to `unserialize()` (common in legacy plugins), it is vulnerable to PHP Object Injection if you map the application's magic methods (`__destruct`, `__wakeup`).

## 2. Insecure Direct Object References (IDOR) & Routing 

CodeIgniter's default routing allows direct mapping of URLs to Controllers and Methods (`/controller/method/param1`).
*   **Attack Vector:** Developers often create administrative or test functions within a public controller without applying access controls. Actively bruteforce Controller names and guess method names (e.g., `/user/deleteUser/12`, `/admin/backup_db`).

## 3. Local File Inclusion (LFI) via Views

A classic mistake in CodeIgniter implementations is dynamically loading views based on user input:
```php
// Vulnerable Controller Example:
$this->load->view('templates/'.$_GET['page']);
```
*   **Attack Vector:** Exploit this by passing directory traversal strings (e.g., `../../../../etc/passwd`). CI3 doesn't automatically protect `load->view()` from traversal. 

## 4. CodeIgniter 4 Differences

CI4 introduces a `.env` file system similar to Laravel.
*   **Leakage:** Always check `/.env`, `/writable/logs/log-*.log` for sensitive configurations, API keys, and test endpoints. CI4 default error handling (development mode) visually dumps the stack trace to the browser.
