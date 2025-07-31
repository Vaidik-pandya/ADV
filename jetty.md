# Advanced Jetty Bug Bounty Hunting Cheat Sheet  
### Focus: Black-box Web App Testing with Exploitable CVEs & Techniques

---

## How to Use:  
This guide highlights critical Jetty web server and servlet vulnerabilities with real CVEs, discovery, detection, and exploitation paths, designed for practical black-box bug bounty scenarios.

---

### 1. CVE-2021-28164 — Request Smuggling via CRLF Injection  
- **Affected Versions:** Jetty 9.4.0.v20161208 to 9.4.38.v20210224  
- **Discovery:**  
  - Identify Jetty via headers (`Server: Jetty(...)`), error pages, or favicon hashes  
  - Test by sending POST requests with both Content-Length and Transfer-Encoding headers  
- **Exploitation:**  
  - Smuggle requests by crafting ambiguous HTTP requests splitting boundaries  
  - Leverage Burp Repeater/Intruder or custom scripts to check for prefix/suffix confusion  
- **PoC Example:**  
  Send raw requests with conflicting headers to trigger back-end desync and potentially perform web cache poisoning, credential theft, or bypass authentication  
- **More Info:**  
  - [Nuclei Template – CVE-2021-28164](https://github.com/projectdiscovery/nuclei-templates/blob/main/cves/CVE-2021-28164.yaml)

---

### 2. CVE-2020-27223 — Information Disclosure via Improper Handling in HTTP/2  
- **Affected Versions:** Jetty 9.4.6 to 9.4.35, 10.0.0  
- **Discovery:**  
  - Confirm HTTP/2 support by sending HTTP/2 requests (h2c upgrade probes)  
  - Observe response headers/frames for secret leakage  
- **Exploitation:**  
  - Manipulate HTTP/2 stream frames to trigger internal error messages or unintended data exposure  
  - Use custom HTTP/2 clients or scanners  
- **Impact:**  
  - Disclosure of internal data, sensitive error info, or session tokens

---

### 3. CVE-2017-7656 — Remote Code Execution via JSP File Upload  
- **Affected Versions:** Jetty 9.2.x, 9.3.x, 9.4.x before 9.4.6  
- **Discovery:**  
  - Hunt for public file uploaders or misconfigured webapps with file upload features  
  - Test by uploading `.jsp` or double extension (`.jsp;.jpg`) payloads  
- **Exploitation:**  
  - Upload malicious JSP web shell to accessible directory  
  - Trigger shell by browsing to uploaded file’s path and execute OS commands  
- **More Info & Exploit:**  
  - [Example PoC Write-up – Exploit-DB](https://www.exploit-db.com/exploits/43188)  
- **Impact:**  
  - Achieve remote command execution or server takeover

---

### 4. CVE-2021-34429 — Denial of Service via Large HTTP/2 Requests  
- **Affected Versions:** Jetty 9.4.37 to 9.4.42, 10.0.1 to 10.0.5  
- **Discovery:**  
  - Detect Jetty version and HTTP/2 support  
  - Fuzz server with super-sized HTTP/2 requests  
- **Exploitation:**  
  - Send huge request bodies via HTTP/2 to exhaust server resources and cause outages  
- **Impact:**  
  - Service disruption or black-box DoS vector during bug bounty competitions

---

### 5. CVE-2022-2047 — Path Traversal & Arbitrary File Read  
- **Affected Versions:** Various custom Jetty installations lacking proper input validation  
- **Discovery:**  
  - Fuzz URL endpoint parameters for directory traversal payloads like `../../etc/passwd`  
- **Exploitation:**  
  - Read sensitive files from the underlying OS (`WEB-INF/web.xml`, `/etc/passwd`, config files)  
- **PoC:**  

GET /static/../../../../etc/passwd HTTP/1.1
Host: target.com

- **Impact:**  
- Read secret server files, leak environment configs

---

### 6. CVE-2017-9735 — Directory Listing & File Disclosure via Misconfigured Handlers  
- **Discovery:**  
- Browse public endpoints and static URI patterns `/static/`, `/files/`, directory paths  
- Check for directory listing responses or open download links  
- **Exploitation:**  
- Crawl or manually enumerate exposed file archives and configuration files  
- **Impact:**  
- Download source, identify secrets/configs, or collect user data

---

### 7. Cookie and Session Misconfiguration  
- **Discovery:**  
- Analyze cookies set by Jetty (`JSESSIONID`) for missing `HttpOnly`, `Secure`, or randomization issues  
- **Exploitation:**  
- Session fixation/hijacking via predictable cookies or accessing as HTTP instead of HTTPS  
- **Impact:**  
- User session takeover or privilege escalation

---

## Recommended Tooling for Exploitation and Recon  
- **Nuclei Templates:**  
- Public: [https://github.com/projectdiscovery/nuclei-templates](https://github.com/projectdiscovery/nuclei-templates) (search for `jetty`, or specific CVEs)  
- CVE-2021-28164: [Nuclei Template](https://github.com/projectdiscovery/nuclei-templates/blob/main/cves/CVE-2021-28164.yaml)
- **Burp Suite / Repeater / Turbo Intruder:** For custom request crafting, fuzzing, smuggling
- **ffuf/dirsearch:** For content and directory bruteforce
- **SSL Labs, Censys, Shodan:** To fingerprint Jetty versions and open endpoints

---

## BountyBoy: Elite Bug Bounty Program — trusted by 8000+ learners.
📄 Syllabus: https://lnkd.in/d6vTg3k9 🎯 Enroll Now: https://lnkd.in/d7p5spcS
