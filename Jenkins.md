# Advanced Jenkins Bug Bounty Hunting Cheat Sheet  
### Focus: Black-box Testing on Jenkins Web Applications & APIs _(Exploitable CVEs + Practical Attack Vectors, 2024–2025)_

---

## How to Use:  
This cheat sheet highlights critical, exploitable Jenkins vulnerabilities and discovery/exploitation tactics for black-box web app and CI/CD pipeline bug bounty hunting.

---

### 1. CVE-2024-23897 — Pre-auth Arbitrary File Read (Critical)
- **Discovery:**  
  - Probe Jenkins endpoints (default: `/`, `/login`), version check via headers or about page.  
  - Target `/securityRealm/user/admin/descriptorByName/org.jenkinsci.plugins.workflow.cps.CpsFlowDefinition/checkScriptCompile` endpoint.
- **Exploitation:**  
  - POST JSON like `{"value":"@GrabConfig(systemClassLoader=true) @Grab('file:/etc/passwd') import groovy.grape.Grape"}`
  - Retrieve file contents (e.g., `/etc/passwd`, credentials) from server without authentication.
- **Impact:** Full credential theft, sensitive info dump, possible privilege escalation.
- **PoC/Nuclei:**  
  - [Nuclei Template](https://github.com/projectdiscovery/nuclei-templates/blob/main/cves/2024/CVE-2024-23897.yaml)

---

### 2. CVE-2023-35141 — RCE via Command Parameters (Groovy Script Injection)
- **Discovery:**  
  - Find endpoints for script execution: `/script`, `/scriptText` on Jenkins master.
- **Exploitation:**  
  - Authenticated user injects Groovy code to execute arbitrary commands on the host.
- **Impact:** Full remote command execution (RCE), underlying server compromise.

---

### 3. CVE-2023-32993 — Stored XSS via Build Name/Description
- **Discovery:**  
  - Fuzz build info fields, job descriptions, or parameter values.
- **Exploitation:**  
  - Inject JavaScript payload (e.g., `<img src=x onerror=alert(1)>`) in build descriptors to attack admin/viewer users.
- **Impact:** Session/multifactor token theft, privilege escalation.

---

### 4. CVE-2022-20617 — Authentication Bypass via Crafted Header
- **Discovery:**  
  - Target `/securityRealm/` endpoints; manipulate the HTTP `X-Forwarded-User` and related headers.
- **Exploitation:**  
  - Send requests with custom header values to bypass authentication, gain admin access to Jenkins UI.
- **Impact:** Complete unauthorized access.

---

### 5. CVE-2019-1003000/1/2 — RCE via Pipeline Groovy Sandbox Bypass
- **Discovery:**  
  - Identify pipeline projects allowing user-contributed Groovy scripts.
- **Exploitation:**  
  - Submit specially crafted payload that escapes Groovy sandbox and executes commands on server.
- **Impact:** Arbitrary code execution, environment pivot, or CI agent takeover.
- **PoC/Nuclei:**  
  - [Metasploit Module & Examples](https://www.rapid7.com/db/modules/exploit/multi/http/jenkins_metaprogramming/)

---

### 6. Unsafe Deserialization (Multiple CVEs, Core & Plugins)
- **Discovery:**  
  - Probe endpoints that handle user-supplied serialized Java objects: `/cli`, `/createItem`, plugin-specific endpoints.
- **Exploitation:**  
  - Use gadget chains or known vulnerable plugins to deliver malicious serialized payloads for RCE.
- **Impact:** Full system compromise.

---

### 7. Default, Weak, or No Credentials
- **Discovery:**  
  - Test `/login` for "admin/admin", "jenkins/jenkins", or empty passwords.  
  - Brute-force attack allowed if rate-limiting not enforced.
- **Exploitation:**  
  - Immediate admin access and pivot to CLI/API tokens, job credentials.

---

### 8. Sensitive Information Disclosure (Secrets/Config)
- **Discovery:**  
  - Access `/script`, `/credentials/store/system/domain/_/`, `/user/admin/configure`.
- **Exploitation:**  
  - List build logs, credentials.xml, secrets in workspace or system folder.
- **Impact:** Steal environment secrets, source code, or API tokens.

---

### 9. SSRF, Proxy Abuse & Callback Endpoints
- **Discovery:**  
  - Test build parameters, plugin configuration (e.g., webhook, SCM, or artifact links) for SSRF.
- **Exploitation:**  
  - Point webhook or remote repository URL fields to internal services (e.g., `http://169.254.169.254/` for AWS/cloud meta-data).
- **Impact:** Data exfiltration, internal network mapping, privilege escalation.

---

### 10. Exploiting Dangerous Plugins
- **Discovery:**  
  - Enumerate plugins via `/pluginManager/`, `/script`, or fingerprint version via `/view/All/`.
- **Exploitation:**  
  - Use known-chained plugin vulnerabilities (Blue Ocean, Credentials, Git, Script Security) for RCE, SSRF, privilege escalation, or info disclosure.
- **Impact:** Chained cross-plugin attacks possible.

---

## Tooling for Jenkins Bug Hunting  
- **Nuclei Templates:**  
  - [ProjectDiscovery Jenkins CVE templates](https://github.com/projectdiscovery/nuclei-templates)  
- **Burp Suite:** Custom request crafting, API/SSRF/XSS fuzzing.
- **Metasploit/JenkinSploit:** For serialization & RCE bugs.
- **Shodan/Censys:** Scan for exposed Jenkins endpoints and enumerate version/plugins.
- **ffuf/dirsearch:** Brute-force hidden paths for jobs/configs/scripts.

---

## BountyBoy: Elite Bug Bounty Program — trusted by 8000+ learners.
📄 Syllabus: https://lnkd.in/d6vTg3k9 🎯 Enroll Now: https://lnkd.in/d7p5spcS
