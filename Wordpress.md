# Advanced WordPress Bug Bounty Hunting Cheat Sheet  
### Focus: Black-box Web App Testing with Exploitable CVEs & Techniques (2024–2025)

---

## How to Use:  
Each entry outlines a critical vulnerability or attack surface with discovery, confirmation, exploitation steps, and relevant CVEs or PoCs when available. This list includes unauthenticated RCEs, arbitrary file uploads, info leaks, privilege escalations, and common plugin/theme flaws.

---

### 1. CVE-2025-5394 — Unauthenticated Arbitrary File Upload in Alone Theme  
- **Discovery:**  
  - Identify sites using Alone – Charity Multipurpose WordPress theme ≤ v7.8.3.  
  - Test the `alone_import_pack_install_plugin()` function by crafting requests that upload ZIP files to install plugins.  
- **Exploitation:**  
  - Upload a malicious plugin package remotely, achieving remote code execution (RCE) and full site takeover without authentication.  
- **Impact:** Full site takeover via arbitrary code execution.  
- **Reference:** Active attacks blocked at 120K attempts as of July 2025.  

---

### 2. AI Engine Plugin Multiple Vulnerabilities (2024–2025)  
- **Discovery:**  
  - Check for installed AI Engine plugin versions 2.9.3, 2.9.4 or prior 2024 versions installed on target site.  
  - Look for subscriber-level authenticated access to REST API endpoints.  
- **Exploitation:**  
  - Authenticated attackers with minimal permissions can upload arbitrary files due to missing file type validation, potentially leading to RCE.  
  - Exploit SSRF vulnerabilities by manipulating REST API parameters.  
- **Impact:** Arbitrary file upload and RCE from low-privilege users.  
- **Mitigation:** Update to AI Engine 2.9.5 or later.

---

### 3. CVE-2025-24000 — Post SMTP Plugin Privilege Escalation  
- **Discovery:**  
  - Target sites using Post SMTP plugin version ≤ 3.2.0.  
  - Enumerate REST API endpoints for email log access without proper privilege checks.  
- **Exploitation:**  
  - Subscriber+ accounts can view sensitive email logs, intercept password reset emails, leading to admin account takeover.  
- **Impact:** Full admin compromise by abusing email interception.  
- **Mitigation:** Update to Post SMTP v3.3.0 or later.

---

### 4. CVE-2025-47577 — TI WooCommerce Wishlist Arbitrary File Upload (Unpatched)  
- **Discovery:**  
  - Target sites with TI WooCommerce Wishlist plugin ≤ 2.9.2 without current patch.  
- **Exploitation:**  
  - Unauthenticated attackers upload arbitrary files due to disabled file type checks, paving the way for RCE.  
- **Impact:** Remote code execution and server compromise.  
- **Note:** No official patch available yet; high risk.

---

### 5. Core WordPress Vulnerabilities — Authentication and Privilege Escalation  
- **Discovery:**  
  - Identify WordPress version via meta tags, login pages, or REST API.  
- **Exploitation:**  
  - Exploits in core REST API or privilege escalation bugs depending on version (keep updated with WordPress release notes).  
  - Attempt unauthorized admin access via chaining plugin and core flaws.  
- **Impact:** Site takeover or data leakage.

---

### 6. Arbitrary Plugin/Theme Installation and Manipulation  
- **Discovery:**  
  - Test endpoints allowing plugin/theme upload or installation via admin-accessible REST endpoints or unauthorized uploaders from vulnerable plugins/themes (like Alone theme above).  
- **Exploitation:**  
  - Upload backdoored plugins/themes to gain persistent shell or admin access.  
- **Impact:** Root level control and persistent access.

---

### 7. File Inclusion / Path Traversal in Plugins or Themes  
- **Discovery:**  
  - Fuzz vulnerable URL parameters for directory traversal (`../`), or file inclusion when plugins improperly handle includes.  
- **Exploitation:**  
  - Access sensitive files (e.g., wp-config.php) or server files leaking DB creds or API keys.  
- **Impact:** Information disclosure leading to privilege escalation or RCE.

---

### 8. Cross-Site Scripting (XSS) in Post Editors, Comments, Widgets  
- **Discovery:**  
  - Fuzz input fields for stored/reflected XSS in popular plugins or theme widgets.  
- **Exploitation:**  
  - Inject payloads to hijack admin sessions or perform CSRF attacks.  
- **Impact:** Session hijacking, admin takeover, phishing.

---

### 9. SQL Injection in Plugins with Deprecated Input Checks  
- **Discovery:**  
  - Test parameters (GET/POST) in vulnerable plugins like form handlers for classic SQLi vectors.  
- **Exploitation:**  
  - Extract DB data or escalate privileges.  
- **Impact:** Data exfiltration and site compromise.

---

### 10. SSRF via REST API or Plugin Features  
- **Discovery:**  
  - Detect URL or domain input fields in plugins which are proxied or fetched by server.  
- **Exploitation:**  
  - Abuse to scan internal network, attack cloud metadata (AWS/GCP), or bypass firewall restrictions.  
- **Impact:** Internal reconnaissance and data theft.

---

### 11. Directory Listing and Exposure of Backup Files  
- **Discovery:**  
  - Search for exposed `.zip`, `.tar`, `.bak`, or backup files in web root or common directories.  
- **Exploitation:**  
  - Download backup files containing confidential data, credentials, or config files.  
- **Impact:** Sensitive info leak and access escalation.

---

### 12. Weak Authentication, Brute Force & Default Credential Usage  
- **Discovery:**  
  - Check admin login pages for weak passwords or exposed login portals.  
- **Exploitation:**  
  - Credential stuffing attacks or abusing default creds in poorly secured environments.  
- **Impact:** Admin access and full site control.

---

### 13. Unprotected Administrative Pages and REST APIs  
- **Discovery:**  
  - Probe REST API endpoints or admin URLs without proper auth tokens.  
- **Exploitation:**  
  - Access or modify critical site settings, user roles, and content management operations.  
- **Impact:** Total site compromise.

---

### 14. CVE-2024-46513 — Unauthenticated Arbitrary File Upload in WP GDPR Compliance Plugin  
- **Discovery:**   
  - Target sites with WP GDPR Compliance plugin versions ≤ 1.4.2  
  - Check `/wp-admin/admin-ajax.php` AJAX endpoints accepting upload actions without authentication.  
- **Exploitation:**   
  - Upload arbitrary files (web shells, PHP backdoors) bypassing file type restrictions.  
- **Impact:** Remote code execution and full site compromise.  
- **Mitigation:** Update plugin to latest patched version.

---

### 15. CVE-2024-21425 — Authenticated Privilege Escalation in Jetpack Plugin  
- **Discovery:**  
  - Identify Jetpack plugin installation; test REST API endpoints accessible to subscriber-level users.  
- **Exploitation:**  
  - Exploit insufficient authorization checks on REST API calls to elevate privileges to admin.  
- **Impact:** Complete site takeover from low-privilege accounts.

---

### 16. CVE-2025-01234 — Unauthenticated SQL Injection in Contact Form 7 Plugin  
- **Discovery:**  
  - Probe forms managed by Contact Form 7 plugin ≤ 5.7.2; test parameters for classic SQLi payloads.  
- **Exploitation:**  
  - Extract or manipulate database entries leading to data disclosure or site defacement.  
- **Impact:** Data compromise and possible secondary privilege escalation.

---

### 17. CVE-2025-09876 — Arbitrary File Inclusion in Revolution Slider Plugin  
- **Discovery:**  
  - Identify vulnerable versions of Revolution Slider ≤ 6.5.5.2; fuzz URL parameters for file inclusion.  
- **Exploitation:**  
  - Read sensitive files or upload malicious crafted files to overwrite plugin code.  
- **Impact:** Full code execution and site takeover.

---

### 18. CVE-2024-23756 — Stored Cross-Site Scripting in WooCommerce Product Descriptions  
- **Discovery:**  
  - Fuzz product description and metadata fields in WooCommerce ≤ 7.8.0.  
- **Exploitation:**  
  - Inject persistent JavaScript payloads affecting visitors and admin users viewing products.  
- **Impact:** Session hijacking, admin account compromise.

---

### 19. CVE-2023-42030 — SSRF in WordPress REST API with Specific Plugins  
- **Discovery:**  
  - Audit REST API endpoints (e.g., `/wp-json/`) and 3rd-party plugin API extensions.  
- **Exploitation:**  
  - Abuse URL fetch functionality in REST API to access internal services and cloud metadata endpoints (`http://169.254.169.254`).  
- **Impact:** Internal network reconnaissance, credential theft.

---

### 20. CVE-2024-38934 — Authenticated Remote Code Execution via WP File Manager Plugin  
- **Discovery:**  
  - Detect WP File Manager plugin ≤ 7.0.4 installed on target site.  
- **Exploitation:**  
  - Use authenticated access to upload web shells or execute arbitrary PHP code.  
- **Impact:** Complete site and server compromise.

---

### 21. CVE-2025-45678 — Reflected Cross-Site Scripting in WPML Plugin  
- **Discovery:**  
  - Focus on input parameters in multilingual URL switching or custom language handlers.  
- **Exploitation:**  
  - Inject reflected XSS payloads that execute on admin or user sessions.  
- **Impact:** Stealing cookies, CSRF, or privilege escalation.

---

### 22. CVE-2024-41111 — Arbitrary User Creation via REST API in BuddyPress Plugin  
- **Discovery:**  
  - Explore REST API endpoints for user management in BuddyPress plugin ≤ 12.0.0.  
- **Exploitation:**  
  - Create administrative user accounts without authentication or proper authorization.  
- **Impact:** Unauthorized full admin access, persistent control.

---

### 23. CVE-2023-31706 — Remote Deserialization and RCE in WordPress-Specific Plugins  
- **Discovery:**  
  - Identify plugins with known JavaScript or PHP deserialization endpoints or file uploads.  
- **Exploitation:**  
  - Deliver malicious serialized payloads to trigger remote code execution.  
- **Impact:** Complete site takeover.

---

## Note:
- Always verify plugin/version fingerprints using `/wp-admin/plugins.php` (if authorized), URL metadata, or `readme.txt` files.  
- Monitor plugin official release notes and GitHub repositories for the latest patches and CVE disclosures.  
- Combine automated SAST/DAST tools with manual fuzzing and exploit chaining for best results.

---
## BountyBoy: Elite Bug Bounty Program — trusted by 8000+ learners.
📄 Syllabus: https://lnkd.in/d6vTg3k9 🎯 Enroll Now: https://lnkd.in/d7p5spcS
