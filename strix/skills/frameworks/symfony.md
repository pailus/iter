---
name: symfony
description: Specialized techniques for exploiting Symfony PHP applications, focusing on the Symfony Profiler, Fragment routing injections, and `.env` exposures.
---

# Symfony Exploitation & Pentesting

Symfony is the enterprise PHP framework powering robust systems like Magento, Drupal 8+, and PrestaShop. It is highly modular and relies heavily on environment configurations.

## 1. Symfony Web Profiler Exposure

The Symfony Web Profiler is an unparalleled developer tool that tracks every detail of an HTTP request. If accidentally left accessible in production, it is a catastrophic information leak.
*   **Discovery:** Typically found at `/_profiler/` or `/_profiler/empty/search/results`.
*   **Exploitation:** 
    *   **Env Variables:** Check the profile for any request; the 'Configuration' tab dumps the entire `$_ENV` array, revealing database passwords and API keys.
    *   **Authentication & Tokens:** The 'Security' or 'Request' tabs will expose active CSRF tokens, session IDs, and authenticated user objects.
    *   **SQL Queries:** The 'Doctrine' tab exposes all plaintext SQL queries sent during the request, accelerating SQLi development.

## 2. Environment File Leaks

Like Laravel, Symfony utilizes `.env` files.
*   **Vector:** Frequently, developers misconfigure the Nginx/Apache document root to point to the base repository folder rather than the `/public` folder.
*   **Exploitation:** Check `/.env`, `/.env.local`, `/.env.test`, `/.env.prod`. Look for the `APP_SECRET` parameter, which is used for CSRF generation and "Remember Me" cookie signing.

## 3. Path Traversal & File Uploads

*   **Public Directory:** Uploaded files usually map to `/public/uploads/`.
*   **Path Traversal Resiliency:** Symfony's built-in File components are generally secure against traversal, but custom developer logic often fails. Test LFI explicitly against `../config/services.yaml` or `../config/packages/security.yaml` to decipher internal routing and firewall rules.

## 4. Fragment Injection / ESI (Edge Side Includes)

Symfony applications utilizing caching (via Varnish or internal HttpCache) often rely on ESI to load dynamic parts of a caching page.
*   **Vector:** Sometimes handled via the `/_fragment` route.
*   **Exploitation:** If the `/_fragment` URL is exposed without a proper HMAC signature validation (or if the secret is leaked), attackers can invoke internal controllers and methods that were never meant to be publicly accessible, allowing deep business logic manipulation.
