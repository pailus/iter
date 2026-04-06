---
name: aspnet
description: Specialized techniques for exploiting ASP.NET and .NET Core applications, including ViewState deserialization, XXE, Web.config exposures, and Swagger enumeration.
---

# Microsoft ASP.NET & .NET Core Exploitation

Microsoft's .NET ecosystem is heavily utilized by governments and large corporations. Exploitation paths depend significantly on whether it is classical ASP.NET (.NET Framework) or modern ASP.NET Core.

## 1. Classical ASP.NET (.NET Framework)

### ViewState Deserialization
ASP.NET uses a hidden form field called `__VIEWSTATE` to maintain the state of the UI across POST requests.
*   **Vulnerability:** If the `MAC` (Message Authentication Code) validation is disabled (`EnableViewStateMac="false"`), or if the `MachineKey` is leaked (via LFI in `web.config`), you can use tools like `YSoSerial.Net` to generate a malicious serialized payload.
*   **Exploitation:** Submit the payload in the `__VIEWSTATE` parameter to achieve Remote Code Execution.

### Path Traversal & File Extensions
*   Test for Windows-specific file extensions: `.aspx`, `.ashx`, `.asmx`, `.svc`.
*   If testing LFI, always check typical config files mapping to the app root: `/web.config` or `C:\inetpub\wwwroot\web.config`.

## 2. Modern ASP.NET Core

Unlike classic ASP.NET, .NET Core apps run across platforms (Kestrel on Linux/Windows).

### Swagger / OpenAPI Exposure
Many .NET Core APIs use `Swashbuckle` to auto-generate API documentation.
*   **Vector:** Check paths like `/swagger/v1/swagger.json`, `/swagger/index.html`, `/api/docs`. 
*   **Value:** These expose the exact structure of all API endpoints and expected parameters, acting as a massive map for further attacks (BOLA/IDOR).

### Configuration Leaks (`appsettings.json`)
In .NET Core, settings are not in `web.config` but in `appsettings.json` (and `appsettings.Development.json`).
*   **Exploitation:** If a path traversal exists, aim for `/appsettings.json` to extract database connection strings and JWT signing keys.

## 3. General .NET Attack Vectors

*   **XML External Entity (XXE):** Older .NET APIs (.asmx/WCF) rely heavily on SOAP and XML. Often, they use outdated XML parsers. Send an XML payload declaring a `SYSTEM` entity (`<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">`) to test for file reads.
*   **Verbose Exceptions:** Force application errors to trigger the 'Yellow Screen of Death' (YSOD) or .NET Core Exception Handler, which will print stack traces. This reveals absolute directory paths (e.g., `D:\Apps\Production\src\...`), which aids LFI and file upload executions.
