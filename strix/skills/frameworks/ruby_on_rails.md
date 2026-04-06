---
name: ruby_on_rails
description: Specialized techniques for exploiting Ruby on Rails applications, including secret_key_base extraction to RCE, Mass Assignment, and Active Storage SSRF.
---

# Ruby on Rails Exploitation & Pentesting

Ruby on Rails prioritizes "Convention over Configuration". While secure by default in modern iterations, legacy configurations or developers bypassing its conventions often create critical RCE vectors.

## 1. The `secret_key_base` RCE

Like Django's `SECRET_KEY`, Rails relies on a `secret_key_base` (or `secret_token` in Rails 3) to sign and encrypt cookies.
*   **Extraction:** Find this key via LFI or repo leaks at `/config/credentials.yml.enc` (plus the `master.key`), `/config/secrets.yml`, or `/config/initializers/secret_token.rb`.
*   **Exploitation:** Rails sessions (if stored in cookies) are sometimes serialized using Ruby's `Marshal` library. If you have the key, you can serialize a malicious Ruby object (using tools that abstract Ruby gadgets), sign it with the leaked key, and send it back as your session cookie. When Rails calls `Marshal.load()`, it results in instant Remote Code Execution.

## 2. Mass Assignment (Strong Parameters Bypass)

Historically, Rails had massive issues with Mass Assignment (where `Model.update(params)` allows users to inject arbitrary fields like `is_admin=1`).
*   **Modern Mitigation:** Rails now uses Strong Parameters (`params.require(:user).permit(:name)`).
*   **Exploitation:** Check if developers missed permitting specific models. Send extra parameters in POST/PUT requests (e.g., adding `&user[admin]=1` or `{"user": {"name": "test", "role_id": 1}}`) and check if the application blindly saves them.

## 3. Server-Side Request Forgery via Active Storage

Rails' `Active Storage` simplifies file uploads. A known architectural flaw allows SSRF.
*   **Vector:** When an endpoint expects an image or file, you can often supply a URL rather than an uploaded file (e.g., substituting the image payload with `{"avatar": {"url": "http://169.254.169.254/latest/meta-data/"}}`). 
*   Rails will instruct the server to download the resource, causing an SSRF which can pivot into internal networks or cloud metadata APIs.

## 4. Route Exposure & Debug Modes

If a Rails application encounters a routing error while in Development Mode:
*   It exposes a detailed debug page listing all valid application routes (`rake routes` equivalent in browser) and current configurations.
*   Test for this by requesting unmapped HTTP methods (e.g., sending `PATCH /login` when it only accepts `POST`) to forcefully trigger routing mismatch exceptions.
