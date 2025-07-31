# Advanced Jira Bug Bounty Hunting Cheat Sheet  
### Focus: Black-box Testing on Atlassian Jira Web Apps & APIs *(Exploitable CVEs + Offensive Techniques, 2024–2025)*

---

## How to Use:  
This cheat sheet highlights high-impact Jira vulnerabilities, CVEs, and real-world flaws for black-box bug bounty, red teaming, and offensive security web app testing.

---

### 1. CVE-2024-1597 — Authenticated RCE via Outdated Jira Service Management  
- **Discovery:**  
  - Detect Service Management endpoints (`/servicedesk/customer/*`) and fingerprint version in login headers or help/about info.  
- **Exploitation:**  
  - After user login, exploit crafted form data or attached files to achieve server-side command execution (chained template or file upload exploit).  
- **Impact:** Remote OS command execution; full system compromise or data export.

---

### 2. CVE-2023-22527 — Pre-auth RCE via OGNL Injection (Critical)  
- **Discovery:**  
  - Probe any endpoint (commonly `/secure/ContactAdministrators!default.jspa`) on Jira Data Center/Server 8.1–8.20.x unpatched instances.  
  - Check patch levels; many orgs remain unpatched into 2024.  
- **Exploitation:**  
  - Send OGNL-injected HTTP payload such as:  
    ```
    userName=%{(#_memberAccess['allowStaticMethodAccess']=true,#cmd='id',#isWin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win')),#cmds=(#isWin?{'cmd.exe','/c',#cmd}:{'/bin/sh','-c',#cmd}),#p=new java.lang.ProcessBuilder(#cmds),#p.redirectErrorStream(true),#process=#p.start(),#ros=(@org.apache.commons.io.IOUtils@toString(#process.getInputStream())))}  
    ```
  - Read RCE response or out-of-band indicator.  
- **PoC & Template:**  
  - [Nuclei Template](https://github.com/projectdiscovery/nuclei-templates/blob/main/cves/2023/CVE-2023-22527.yaml)  
- **Impact:** Unauthenticated full RCE, high payout bug!

---

### 3. CVE-2022-0540 — Auth Bypass and OGNL Injection (Jira Data Center/Server)  
- **Discovery:**  
  - Target `/plugins/servlet/*` endpoints for injection attempts.  
- **Exploitation:**  
  - Exploit auth bypass in 3rd-party or certain built-in plugins for code injection without credentials.  
- **Impact:** Arbitrary code execution, session exfiltration, persistent compromise.

---

### 4. CVE-2021-26086 — Information Disclosure via `/WEB-INF/web.xml`  
- **Discovery:**  
  - Access:  
    ```
    /s/WEB-INF/web.xml
    ```
    or variant paths.  
- **Exploitation:**  
  - Leak sensitive config including app keys, classpaths, DB connection details.
- **Impact:** Intelligence for further exploit chain (auth bypass, database takeover, RCE).

---

### 5. CVE-2020-14179 — Pre-auth Sensitive Info Disclosure via `/secure/QueryComponent!Default.jspa`  
- **Discovery:**  
  - Access affected endpoint directly (GET request).  
- **Exploitation:**  
  - Enumerate internal projects, issue keys, or privileged config data as guest user.  
- **Impact:** Recon for chained attacks, info on privileged workflow states.

---

### 6. Default Credentials, Weak Auth, and Public “Signup”  
- **Discovery:**  
  - Probe `/login.jsp` plus `/signup` and `/rest/auth/1/session`—test for default or weak password policies.  
- **Exploitation:**  
  - Credential stuffing, brute-force, or exploit enabled public registration for privilege escalation.  
- **Impact:** Unauthorized access, lateral movement, persistent project membership.

---

### 7. SSRF via Webhooks & Integrations  
- **Discovery:**  
  - Identify configurable webhook, application link, or outgoing integration endpoints (`/plugins/servlet/webhooks`, `/plugins/servlet/applinks`).  
- **Exploitation:**  
  - Create webhook to internal or cloud metadata endpoint (`http://169.254.169.254/`) or sensitive company infra.  
- **Impact:** Info disclosure, cloud/metadata theft, internal service scan.

---

### 8. XSS (Stored, Reflected, DOM) in Issue Descriptions, Custom Field Values, Comments  
- **Discovery:**  
  - Fuzz inputs on issue creation, edits, comments, attachment, settings fields.  
- **Exploitation:**  
  - Inject JS payloads (`<script>`, `"><img src=x onerror=alert(1)>`) and trigger as another user (stored), or through crafted email-based notifications (reflected/DOM).  
- **Impact:** Session hijacking, credential phishing, privilege escalation.

---

### 9. Directory Traversal in File Attachments (Multiple CVEs)  
- **Discovery:**  
  - Fuzz file upload endpoints or parameterized download/preview URLs for `../` sequences.  
- **Exploitation:**  
  - Access restricted files on server (config files, logs, secrets, license keys).  
  - Chain with file upload to plant webshells (rare but seen in misconfig).  
- **Impact:** Arbitrary file read/write on Jira server.

---

### 10. SSRF/CSRF/Priv Esc via “Gadgets”, Macros, or Weak Integrations  
- **Discovery:**  
  - Examine allowed gadget URLs, iframe sources, or integrations enabled (Jira Gadget Directory).  
- **Exploitation:**  
  - Use SSRF payloads, or exploit weak gadget config to escalate or steal user data via CSRF chain (force admin to trigger webhook, etc.).  
- **Impact:** Internal pivot, persistent SSRF, user data theft.

---

### 11. Insecure API & Excessive Data Exposure  
- **Discovery:**  
  - Intercept traffic at `/rest/api/2/*`, `/rest/auth/1/session`, `/rest/agile/1.0/*`.  
  - Test for access as guest or low-privileged user.  
- **Exploitation:**  
  - Enumerate user data, project metadata, sprints/issues, or manipulate without proper scope checks.  
- **Impact:** Data leak, privilege escalation, project manipulation.

---

### 12. CVE-2020-36289 — Path Traversal in Attachment Download  
- **Discovery:**  
  - Fuzz `fileName=` and `pathName=` parameters with traversal payloads.  
- **Exploitation:**  
  - Download arbitrary application files; potential LFI or config dump.

---

### 13. Exploitable Misconfigurations  
- **Discovery:**  
  - Scan for open CORS, misconfigured reverse proxies, or admin panels exposed to internet.  
  - Check `/plugins/servlet/`, `/rest/`, `/secure/`, and default admin endpoints.  
- **Exploitation:**  
  - Abuse misconfigs for bypassing auth, session fixation, or open redirect.
- **Impact:** Lateral movement, account takeover, data siphoning.

---

## Recommended Tools & Resources  
- **Nuclei Templates:**  
  - [Jira CVE templates (ProjectDiscovery)](https://github.com/projectdiscovery/nuclei-templates)  
  - Custom templates for `/WEB-INF/web.xml`, SSRF/Webhook, OGNL, path traversal.
- **Burp Suite:** For endpoint mapping, parameter fuzzing, SSRF, XSS, and command injection.
- **ffuf/dirsearch:** For endpoint and resource brute-forcing.
- **Metasploit Modules:** For some older RCE bugs and brute-force attacks.
- **Shodan:** Locate internet-exposed Jira instances and fingerprint patch level.

---

## BountyBoy: Elite Bug Bounty Program — trusted by 8000+ learners.
📄 Syllabus: https://lnkd.in/d6vTg3k9 🎯 Enroll Now: https://lnkd.in/d7p5spcS
