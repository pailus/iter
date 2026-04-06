---
name: express
description: Specialized techniques for exploiting Express.js applications, covering Prototype Pollution, Server-Side Template Injection (SSTI), and Node.js-specific behaviors.
---

# Express.js (Node.js) Exploitation & Pentesting

Express is the de-facto standard framework for Node.js. Given Node.js's asynchronous, Javascript-driven runtime, exploitation relies heavily on JSON manipulation, Prototype Pollution, and Template Engines.

## 1. Prototype Pollution

Because Javascript allows deep object merging (common in Express via `lodash` or `express.json()`), you can "pollute" the base `Object.prototype`.
*   **Vector:** Send JSON bodies that include `__proto__` or `constructor.prototype` payloads.
    ```json
    {"__proto__": {"admin": true}}
    ```
*   **Impact:** If the application blindly merges this input into a configuration object, you can alter global application logic (e.g., bypassing authentication checks, turning on debug flags, or polluting exec/spawn commands for RCE).

## 2. Server-Side Template Injection (SSTI)

Express applications often use template engines like `Pug`, `EJS`, `Handlebars`, or `Nunjucks`.
*   **Vector:** If user input is passed directly to `res.render()` without sanitization.
*   **Exploitation:** Test characters like `<%= 7*7 %>` (EJS) or `{{7*7}}` (Handlebars). If it evaluates to `49`, SSTI exists. Node.js SSTI typically allows absolute RCE via `child_process.exec`.
    *Example EJS Payload:* `<%- global.process.mainModule.require('child_process').execSync('id') %>`

## 3. Unsafe Deserialization & Eval()

Many legacy Express apps use the generic `node-serialize` library.
*   **Vector:** If a cookie looks like `{ "rce": "_$$ND_FUNC$$_function (){...}()" }`, it executes immediately upon deserialization using Node's IIFE pattern.
*   Additionally, beware of any input passed into `eval()`, `setTimeout()`, or `setInterval()`, as they execute Javascript commands natively.

## 4. Directory Traversal with `res.sendFile()`

If an Express controller uses `res.sendFile(req.query.file)` indiscriminately:
*   **Bypass:** Express automatically decodes URL encoding `%2e%2e%2f` to `../`. If developers try to sanitize using simple replaces after decoding, they often fail.
*   **Target files:** Extract `.env`, `package.json` (to find vulnerable dependency versions), and `config.js`.
