# Advanced Swagger (OpenAPI) Bug Bounty Hunting Cheat Sheet  
### Focus: Black-box Web App Testing with Exploitable CVEs & Techniques

---

## How to Use:  
This guide provides actionable info about key Swagger/OpenAPI vulnerabilities, common misconfigurations, and practical exploitation tips to maximize findings in black-box bug bounty programs.

---

### 1. CVE-2020-26217 — Swagger UI Arbitrary File Read (Local File Disclosure)  
- **Affected Versions:** Swagger UI versions prior to v3.24.2 (and similar OpenAPI UI implementations)  
- **Discovery:**  
  - Locate Swagger UI instances typically at endpoints like `/swagger-ui.html`, `/swagger/`, `/api-docs/`.  
  - Check for accessible `swagger.json` or `openapi.json` or YAML specs.  
- **Exploitation:**  
  - Abuse parameter traversal flaws or crafted requests to read local files on the server (e.g., `/swagger-ui/index.html?url=file:///etc/passwd`).  
  - Use SSRF vectors in API definitions to retrieve local resource contents or internal endpoints.  
- **PoC / Tools:**  
  - Actively fuzz URL or query parameters supporting file inputs.  
  - Example payload:  
    ```
    http://target/swagger-ui.html?url=file:///etc/passwd
    ```  
- **Impact:**  
  - Sensitive file disclosure, including passwd, config files, or credentials.

---

### 2. CVE-2019-10758 — Remote Code Execution in Swagger Editor or Swagger UI  
- **Affected Versions:** Older Swagger Editor/Swagger UI versions with XXE or deserialization bugs in parsing API specs  
- **Discovery:**  
  - Identify Swagger Editor or UI instances allowing file or spec uploads.  
  - Probe upload or input points with malicious YAML or JSON payloads.  
- **Exploitation:**  
  - Inject XML External Entity (XXE) in specs to leak files or internal data.  
  - Leverage vulnerable deserialization to execute arbitrary code depending on backend parsers (this is more rare but possible).  
- **PoC Payload (XXE example):**  
<?xml version="1.0" encoding="UTF-8"?> <!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>

- **Impact:**  
- Local file disclosure, server data leak, possible RCE.

---

### 3. Insecure Swagger API Spec Exposure & Dangerous Endpoint Disclosure  
- **Discovery:**  
- Search for accessible API specs (`swagger.json`, `swagger.yaml`, `openapi.json`) via common paths (`/api-docs/`, `/v2/api-docs/`, `/swagger/`).  
- Identify if specs reference sensitive internal or admin endpoints.  
- **Exploitation:**  
- Leverage exposed endpoints to attack undocumented or poorly-secured APIs.  
- Craft requests based on spec details to bypass auth or inject malicious payloads.  
- **Tips:**  
- Use automated tools like [Swagger UI](https://swagger.io/tools/swagger-ui/) or Postman to explore specs and test endpoints easily.  
- Combine with fuzzers for injection testing (SQLi, XSS, command injection).

---

### 4. Broken Authentication / Authorization on Swagger-Documented APIs  
- **Discovery:**  
- Identify endpoints and auth mechanisms (API keys, JWT, OAuth) via specs.  
- Test access control by tampering with tokens, session values, or missing auth enforcement.  
- **Exploitation:**  
- Bypass auth or elevate privileges by exploiting missing or improper access controls.  
- Utilize tokens or keys found in Swagger specs or GitHub dorks combined with request crafting.  
- **Example:**  
- A public endpoint with critical admin functionality exposed only via Swagger docs without proper auth.

---

### 5. CVE-2021-40539 — Server-Side Request Forgery (SSRF) via Swagger or OpenAPI Tools  
- **Affected Versions:** Vulnerabilities in Swagger/OpenAPI parser libs  
- **Discovery:**  
- Input URLs in Swagger tools pointing to internal resources or metadata endpoints.  
- Look for proxy or request forwarding APIs referenced in specs.  
- **Exploitation:**  
- Trigger SSRF to access internal services, cloud metadata APIs (AWS EC2, GCP), or internal networks.  
- **PoC:**  
- Use Swagger requests with specially crafted URLs targeting `http://169.254.169.254/` (AWS metadata).  
- **Impact:**  
- Cloud credential exposure, internal network attack pivoting.

---

### 6. Exploiting Outdated Swagger UI / Editor Versions  
- **Discovery:**  
- Fingerprint version header or page footers.  
- Search GitHub for old Swagger repos/configs in project targets.  
- **Exploitation:**  
- Use known exploits tied to specific versions for RCE, LFI, or XSS—some are public on security advisories and Exploit DB.

---

### 7. Sensitive Information Disclosure via Swagger Config & UI  
- **Discovery:**  
- Look for debug information, API keys, environment variables inside exposed `swagger.json` or UI data.  
- Check for `authorization` header examples or embedded tokens in specs.  
- **Exploitation:**  
- Use leaked secrets for API access or lateral movement.  
- Use environment or backend details for further exploitation (default creds, internal hostnames).

---

## Recommended Tooling for Exploitation and Recon  
- **Nuclei Templates:**  
- Check [ProjectDiscovery nuclei-templates](https://github.com/projectdiscovery/nuclei-templates) for swagger or openapi related templates.  
- **Swagger UI / Postman:** Easily explore Swagger specs and automate testing.  
- **Burp Suite:** For custom request tampering, fuzzing, and scanning API endpoints reflected in the specs.  
- **ffuf & sqlmap:** Fuzz and test injection points guided by API specs.  
- **GitHub Dorking:** Search for leaked Swagger/OpenAPI specs in code repos containing secrets or config info.

---

## BountyBoy: Elite Bug Bounty Program — trusted by 8000+ learners.
📄 Syllabus: https://lnkd.in/d6vTg3k9 🎯 Enroll Now: https://lnkd.in/d7p5spcS
