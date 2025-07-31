# Adobe Experience Manager (AEM) Bug Bounty Hunting Cheat Sheet  
### Focus: Black-box Testing on Web Applications

---

## How to Use:  
Each numbered point represents a high-impact attack surface or issue to hunt. For each:  
- **Discovery:** How to find or confirm the target area/feature/misconfig.  
- **Identification:** How to verify vulnerability presence (responses, behaviors).  
- **Exploitation:** Typical attack techniques including CVEs, common payloads, or logic abuse patterns.

---

### 1. Default/Exposed AEM Login Console  
- **Discovery:** Browse default AEM ports (typically 4502, 4503) and look for `/libs/granite/core/content/login.html` or `/libs/cq/core/content/login.html`.  
- **Identification:** Access login page response; check for default admin credentials or weak creds via bruteforce (careful with rate limits).  
- **Exploitation:** Use default creds or credential spraying for unauthorized admin access.

### 2. Unauthenticated AEM JMX and CRX Explorer Access  
- **Discovery:** Enumerate endpoints like `/system/console/jmx`, `/crx/de/index.jsp` or `/crx/explorer/index.jsp`.  
- **Identification:** Check if console or CRX Explorer is accessible without authentication or via weak creds.  
- **Exploitation:** Exfiltrate repo contents, modify nodes, upload payloads, or escalate privileges.

### 3. AEM Debug & Error Pages Disclosure  
- **Discovery:** Trigger errors by injecting malformed parameters in URLs or POST requests (e.g., illegal XPath or JCR queries).  
- **Identification:** Look for verbose stack traces, Java exceptions, or debug info revealing internal structure or user session info.  
- **Exploitation:** Use leaked info for crafting targeted attacks or identify internal endpoint paths.

### 4. Path Traversal / File Disclosure via Sling Requests  
- **Discovery:** Fuzz parameters in Sling resource paths, e.g., search for `.json`, `.cfg`, `.properties` endpoints using URL parameters or extension filters.  
- **Identification:** Look for file contents, configs, or readable sensitive files exposed via traversal or misconfigured Sling servlets.  
- **Exploitation:** Exfiltrate sensitive files such as `sling.properties`, credentials, or authentication tokens.

### 5. CVE-2020-8840 / CVE-2020-3452 / Related RCE via AEM/Sling Misconfig  
- **Discovery:** Probe for vulnerable endpoints by accessing `/libs/granite/data/content/{file}` or unchecked file upload endpoints.  
- **Identification:** Check if arbitrary server-side request forgery (SSRF), deserialization or file upload leads to command execution.  
- **Exploitation:** Chain SSRF or deserialization to achieve remote code execution using crafted inputs (XML, JSON, or HTTP headers).

### 6. Insecure FILE UPLOAD & JCR INJECTION  
- **Discovery:** Search for upload forms or endpoints accepting files (e.g., DAM upload, custom components allowing file inputs).  
- **Identification:** Fuzz with shells, webshells, or malicious serialized payloads. Attempt JCR injection via node properties or metadata.  
- **Exploitation:** Upload webshells or manipulate JCR nodes for privilege escalation/persistent access.

### 7. XSST / Reflected XSS in Author / Publish Environments  
- **Discovery:** Fuzz input points, query params, form fields, custom components (e.g., search, comments).  
- **Identification:** Detect reflected or stored XSS via HTML/JS injection payloads.  
- **Exploitation:** Use XSS for session hijacking, privilege escalation, or as chain in multi-step attacks.

### 8. Insecure CRX Package Manager (/crx/packmgr) Access  
- **Discovery:** Navigate to `/crx/packmgr/index.jsp` or `/crx/packmgr/service.jsp`.  
- **Identification:** Test if package manager is unauthenticated or weakly protected.  
- **Exploitation:** Download/upload packages for code injection or info disclosure.

### 9. Directory Listing & Exposed .content.xml Files  
- **Discovery:** Check common AEM content directories for `.content.xml` exposure (`/content/dam/`, `/etc/designs/`).  
- **Identification:** Visible XML files leaking internal node structure or configurations.  
- **Exploitation:** Use info to map app components, extract sensitive config data.

### 10. Default Credentials and Weak Authentication Brute Forcing  
- **Discovery:** Collect public wordlists and test common default creds users: `'admin', 'test', 'cq', 'aemadmin'`.  
- **Identification:** Login response indicators, HTTP status codes  
- **Exploitation:** Gain unauthorized admin or author access.

### 11. CVE-2019-7836 — Path Traversal and Remote Code Execution  
- **Discovery:** Test `/bin...` path traversal style payloads or unfiltered resource paths in Sling servlet endpoints.  
- **Identification:** Look for disclosure of `jackrabbit` repository files or RCE via XML entity injection.  
- **Exploitation:** Use crafted XML payloads or traversal sequences for command execution.

### 12. CQ5 / AEM Package Manager Upload Vulnerabilities  
- **Discovery:** Upload endpoints for `.zip` packages via CRX or custom package max-age endpoints.  
- **Identification:** Check if upload can bypass security controls or validations.  
- **Exploitation:** Upload malicious package that can execute code or implant backdoors.

### 13. SSRF and HTTP Request Smuggling via Adobe Granite UI Components  
- **Discovery:** Target Granite components parsing URLs or proxying requests (e.g., replication agents).  
- **Identification:** Detect SSRF payloads triggering internal scans or metadata store leaks.  
- **Exploitation:** SSRF into internal network services, cloud metadata, or other sensitive internal resources.

### 14. Improper CORS Policy / CSRF in AEM Interfaces  
- **Discovery:** Inspect CORS headers on author and publish instances.  
- **Identification:** Look for overly permissive origins (`*`) or missing CSRF tokens in critical POST endpoints.  
- **Exploitation:** Cross-site attacks abusing the elevated privileges of logged-in users or admins.

### 15. CRLF / HTTP Response Splitting in Custom AEM Components  
- **Discovery:** Test input reflection in HTTP headers (e.g., `Location`, `Set-Cookie`).  
- **Identification:** Insert `%0d%0a` or `\r\n` payloads to create extra headers or response manipulation.  
- **Exploitation:** Perform cache poisoning, session fixation, or header injection attacks.

---

## Additional Tools & Tips for Black Box AEM Hunting:  
- Use Burp Suite with AEM extensions (such as AEM Scanner plugin) to automate vulnerability pattern checks.  
- Leverage git repositories and GitHub dorks for leaked AEM configs, credentials, and tokens.  
- Confirm instance type (author vs publish) via response headers or content patterns, as vulnerabilities can vary.  
- Map content repositories and replication agents for attack surface via directory enumeration and fuzzing.  
- Monitor Adobe Security Bulletins for the latest AEM CVEs and corresponding Nuclei templates (example: [Nuclei AEM Templates](https://github.com/projectdiscovery/nuclei-templates) - search for “AEM”).

---

## Example Nuclei Templates for AEM:  
- Check GitHub [ProjectDiscovery Nuclei Templates](https://github.com/projectdiscovery/nuclei-templates) repository for `aem` or `adobe` keywords to find community-developed templates for known CVEs and misconfigurations.

---

## BountyBoy: Elite Bug Bounty Program — trusted by 8000+ learners.
📄 Syllabus: https://lnkd.in/d6vTg3k9
🎯 Enroll Now: https://lnkd.in/d7p5spcS
