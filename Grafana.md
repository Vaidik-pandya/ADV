# Advanced Grafana Bug Bounty Hunting Cheat Sheet  
### Focus: Black-box Web App Testing with Exploitable CVEs & Techniques

---

## How to Use:  
This guide highlights critical Grafana vulnerabilities with relevant CVEs, black-box discovery steps, and actionable exploitation paths for bug bounty hunters.

---

### 1. CVE-2021-43798 — Directory Traversal & Arbitrary File Read  
- **Affected Versions:** Grafana 8.0.0-beta1 to 8.3.0  
- **Discovery:**  
  - Fingerprint Grafana via login page, `/login`, favicon, or headers (`Server: Grafana`, `/public/build/`).  
  - Browse to `/public/plugins/` and fuzz for traversal, e.g.:  
    ```
    /public/plugins/alertlist/../../../../../../../../../../etc/passwd
    ```
- **Exploitation:**  
  - Replace `alertlist` with various plugin names and attempt file reads using directory traversal.
  - Dump sensitive files: `/etc/passwd`, `/etc/grafana/grafana.ini`, or database configs.
- **More Info & Nuclei Template:**  
  - [CVE-2021-43798 Nuclei Template](https://github.com/projectdiscovery/nuclei-templates/blob/main/cves/CVE-2021-43798.yaml)

---

### 2. CVE-2023-3128 — Auth Bypass in LDAP/Active Directory Integration  
- **Affected Versions:** Grafana 6.7.0 to 9.5.1 (when using LDAP/AD with specific configs)  
- **Discovery:**  
  - Identify if LDAP/AD is enabled (often via company branding, email hints, login flows).  
  - Try authenticating with crafted credentials targeting bypass techniques.
- **Exploitation:**  
  - Manipulate login forms, try credential spraying using variations on email/case, or inject wildcards to trigger bypass logic.
- **Impact:**  
  - Access dashboards, sensitive data, or perform privilege escalation.

---

### 3. CVE-2021-39226 — Unauthenticated Snapshot Disclosure  
- **Affected Versions:** Before Grafana 8.1.6  
- **Discovery:**  
  - Probe `/api/snapshots` or `/dashboard/snapshot/*` endpoints.  
  - Use Shodan/Censys for publicly exposed instances.
- **Exploitation:**  
  - Retrieve or brute force dashboard snapshot links containing sensitive metrics, credentials, or secrets.
- **Impact:**  
  - Unauthenticated data leaks, system exposure, and lateral movement.

---

### 4. CVE-2021-27962 — XSS via HTTP API Response  
- **Affected Versions:** Grafana 7.x, some earlier versions  
- **Discovery:**  
  - Fuzz API endpoints (`/api/`, `/dashboard/scripts`) with reflected payloads.
- **Exploitation:**  
  - Inject JavaScript in fields that appear in API or dashboard responses to pop admin/session cookies.
- **Payload Example:**
- 
<img src=x onerror=alert(1)> ```

- **Impact:** - XSS used for session hijacking, user phishing, or privilege escalation.

  ### 5. CVE-2021-28146 — Incorrect Access Control via Team Sync API  
- **Affected Versions:** Grafana Enterprise 7.4.0 to 7.4.4  
- **Discovery:**  
  - Identify Grafana Enterprise instances using external authentication (LDAP, SSO).  
  - Confirm usage of teams with special permissions configured on the instance.  
  - Enumerate accessible HTTP API endpoints related to teams (e.g., `/api/teams/external-groups`).  
- **Exploitation:**  
  - Any authenticated user can add external groups to existing teams via the HTTP team sync API.  
  - This allows escalation of permissions by granting team membership with access to dashboards and data sources the attacker shouldn’t have.  
  - Additionally, unauthenticated users with knowledge of a team ID can list associated external groups.  
  - No known workaround other than upgrading the Grafana Enterprise version.  
- **Impact:**  
  - Unauthorized privilege escalation and data access within the Grafana deployment.  
- **Mitigation:**  
  - Upgrade to Grafana Enterprise version 7.4.5 or later.  
- **Reference:**  
  - [Grafana Security Advisory](https://grafana.com/blog/2021/03/18/grafana-6.7.6-7.3.10-and-7.4.5-released-with-important-security-fixes-for-grafana-enterprise/)  
  - [NVD CVE-2021-28146](https://nvd.nist.gov/vuln/detail/CVE-2021-28146)  

---

### 6. Default Credentials and Misconfigurations  
- **Discovery:**  
  - Check for `/login` page and attempt common default credentials such as `admin/admin` or `admin/grafana`.  
  - Enumerate public dashboards and plugins under `/d/` and `/public/plugins/`.  
- **Exploitation:**  
  - Gain admin or viewer access if weak defaults exist.  
  - Access open dashboards to collect sensitive monitoring data or configuration.  
- **Impact:**  
  - Initial access vectors for further exploitation or data exfiltration.

---

## Recommended Tooling for Exploitation and Recon  
- **Nuclei Templates:**  
  - Official and community templates covering Grafana CVEs here:  
    https://github.com/projectdiscovery/nuclei-templates (search for `grafana`)  
  - Example: CVE-2021-43798 template for directory traversal  
- **Burp Suite:** For API fuzzing, session tampering, and XSS payload delivery.  
- **ffuf/dirsearch:** For discovery of hidden directories, files, and public plugins.  
- **Shodan/Censys:** Finding exposed Grafana instances with public IPs.  

---

## BountyBoy: Elite Bug Bounty Program — trusted by 8000+ learners.
📄 Syllabus: https://lnkd.in/d6vTg3k9 🎯 Enroll Now: https://lnkd.in/d7p5spcS
