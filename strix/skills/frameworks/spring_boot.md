---
name: spring_boot
description: Specialized techniques for exploiting Java Spring Boot applications, focusing on Spring Actuator endpoints (heapdumps, env vars), SpEL injection, and deserialization.
---

# Java Spring Boot Exploitation & Pentesting

Spring Boot is the standard framework for enterprise Java applications. Misconfigurations in its monitoring features (Actuators) or data binding often lead directly to complete server compromise.

## 1. Spring Actuator Exposure

Spring Actuator provides built-in endpoints for monitoring the app. If unauthenticated, these are highly critical vectors.
*   **Discovery:** Common paths include `/actuator`, `/actuator/env`, `/actuator/heapdump`, `/actuator/routes`, `/env`, `/trace`, and `/dump`.
*   **Env Dump (`/actuator/env`):** Exploit this by searching for AWS keys, database connection strings, and JWT secrets. Often values are starred out (e.g., `***`), but can sometimes be retrieved via memory dumps or specific `/env` manipulations.
*   **Heap Dumps (`/actuator/heapdump`):** This downloads a full JVM memory snapshot (HPROF file).
    *   **Exploitation:** Use tools like `OQL` (Object Query Language), Eclipse MAT, or `heapdump_tool` to parse the snapshot. You can extract plaintext passwords, API keys, and session tokens residing in memory.

## 2. Remote Code Execution via Actuators

If the `/actuator/env` endpoint allows `POST` requests, you can achieve RCE:
*   **Spring Cloud Env Check:** You can modify the `eureka.client.serviceUrl.defaultZone` property using a POST request, point it to a malicious XStream payload on a server you control, and trigger `POST /actuator/refresh` to forcefully load and execute your payload (deserialization).
*   **Logback RCE:** Modify the `logging.config` via POST to fetch a malicious XML file, then trigger `/actuator/reload` or `/_node/restart`.

## 3. Spring Expression Language (SpEL) Injection

SpEL allows dynamic expression parsing. If user input reaches a SpEL evaluator (`ExpressionParser.parseExpression()`), RCE is possible.
*   **Vector:** Test parameters with `${9*9}` or `T(java.lang.Runtime).getRuntime().exec("id")`.
*   **Context:** Often found in custom validation messages, dynamic queries, or CVEs like Spring4Shell (CVE-2022-22965).

## 4. Path Traversal & Whitelabel Error Pages

*   Spring's default "Whitelabel Error Page" can trigger SpEL injection if it reflects user input that hasn't been properly escaped (legacy CVEs).
*   Test for directory traversal using `;` matrix variables (e.g., `/img/..;/..;/etc/passwd`), as older Spring routers handled `;` distinctly from standard proxies like Nginx, allowing complete bypass of WAF routing rules.
