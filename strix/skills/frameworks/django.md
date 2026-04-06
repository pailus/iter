---
name: django
description: Specialized techniques for exploiting Django applications, including SECRET_KEY abuse, settings exposure, and ORM manipulation.
---

# Django Exploitation & Pentesting

Django is an extremely robust Python framework, but when its built-in security features are bypassed or misconfigured, the impact is severe.

## 1. Exposed Debug Mode

If a Django app runs with `DEBUG = True` in its `settings.py`, an unhandled error will expose a comprehensive traceback page.
*   **Value:** This page lists all local variables, environment settings, installed apps, and the `SECRET_KEY`.
*   **Method:** Force a 404 or a 500 error (e.g., by sending random non-UTF8 binary data or accessing a nonexistent URL).

## 2. Abusing the SECRET_KEY

The `SECRET_KEY` is absolute in Django. If you obtain it (via LFI, Path Traversal, repo leak, or Debug page):
*   **Session Forgery:** Django signs session cookies using the `SECRET_KEY`. By using Django's core signing libraries locally, you can modify the serialized dictionary inside the `sessionid` cookie to hijack admin sessions (`_auth_user_id`).
*   **Password Reset Hijacking:** The key is used to generate password reset tokens. You can potentially forge a reset token for the Superuser if you know their User ID configuration.

## 3. Default Admin Panel

Django comes with a highly recognizable `/admin/` portal.
*   **Vector:** Once a user account is compromised, test it against `/admin/`. Users with `is_staff=True` can access the portal and often upload files or execute commands through third-party admin plugins.

## 4. Misconfigured Static/Media Files

Django doesn't serve static files natively in production; it relies on Nginx/Apache or S3.
*   **Vector:** Look for misconfigurations in the `MEDIA_ROOT`. If a developer allows uploads without validating extensions, and the proxy serves the media folder recursively (e.g., Nginx mapping `/media/` directly to the disk without dropping execution privileges), uploaded Python or shell scripts could potentially be run, or arbitrary files downloaded.
