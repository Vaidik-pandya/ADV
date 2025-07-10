# 40 High-Impact Apache Attack Surfaces for Bug Bounty Hunters

---

## Format:
Each point includes:
- Discovery — How to find the issue.
- Identification — How to confirm it.
- Exploitation — How to abuse it.

---

## First 20 Attack Surfaces

### 1. Apache Path Traversal
- Discovery: Fuzz URLs like `/../../etc/passwd`
- Identification: Look for indicators like `/root` or `/bin/bash`
- Exploitation: Read sensitive files from the server

### 2. CVE-2021-41773 - RCE on Apache 2.4.49+
- Discovery: Check Apache version via headers or error pages
- Identification: Send `/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd`
- Exploitation: If CGI is enabled, full RCE possible

### 3. Exposed Git / SVN / .htaccess Files
- Discovery: Fuzz `.git/config`, `.svn/entries`, `.htaccess`
- Identification: Check response for sensitive data
- Exploitation: Leak source code, internal paths, credentials

### 4. Open Directory Listing
- Discovery: Manually browse `/uploads/`, `/logs/`, etc.
- Identification: Apache returns file listings
- Exploitation: Download files like backups or configs

### 5. mod_cgi / mod_php RCE
- Discovery: Identify `.cgi`, `.php`, `.pl` endpoints
- Identification: Upload or locate scripts accepting input
- Exploitation: Execute system commands remotely

### 6. mod_proxy SSRF
- Discovery: Identify reverse proxy headers or behavior
- Identification: Fuzz with internal IPs via Host/X-Forwarded-For
- Exploitation: Access internal services like AWS metadata

### 7. .htaccess Bypass
- Discovery: Look for `.htaccess` protection
- Identification: Try encoded paths like `%2e`, `%2f` to bypass
- Exploitation: Access restricted files or routes

### 8. TRACE Method Enabled
- Discovery: Send `OPTIONS /` to see allowed methods
- Identification: Look for `TRACE` in response
- Exploitation: XST attack to steal cookies or headers

### 9. mod_status Disclosure
- Discovery: Visit `/server-status`
- Identification: If page loads, check request logs
- Exploitation: Leak real-time traffic, internal IPs, and more

### 10. Weak SSL/TLS Configuration
- Discovery: Scan with `testssl.sh` or SSL Labs
- Identification: Look for SSLv2/SSLv3, RC4, missing HSTS
- Exploitation: Downgrade or MITM attacks

### 11. CVE-2019-0211 - Local Privilege Escalation
- Discovery: Apache version ≤ 2.4.38 with mod_prefork
- Identification: Check server architecture
- Exploitation: Local user can escalate to root

### 12. Insecure File Upload
- Discovery: Locate upload forms
- Identification: Upload `.php`, `.jsp`, `.cgi`, etc.
- Exploitation: Upload web shell and execute it

### 13. CVE-2022-23943 - mod_sed Command Injection
- Discovery: Look for mod_sed in use
- Identification: Craft malicious Content-Type headers
- Exploitation: Command injection through HTTP headers

### 14. CVE-2022-22721 - Buffer Overflow
- Discovery: Identify Apache < 2.4.52
- Identification: Confirm version from headers
- Exploitation: Remote DoS or potential RCE

### 15. .htpasswd Disclosure
- Discovery: Fuzz for `/admin/.htpasswd`
- Identification: Response contains hashed credentials
- Exploitation: Crack offline and reuse

### 16. mod_session Cache Poisoning
- Discovery: Check for mod_session with cache enabled
- Identification: Tamper with session cookies
- Exploitation: Serve poisoned sessions to other users

### 17. HTTP Request Smuggling
- Discovery: Apache behind reverse proxy
- Identification: Use TE.CL and CL.TE attack methods
- Exploitation: Bypass access controls, cache poisoning

### 18. Verbose Server Headers
- Discovery: Check response headers and error pages
- Identification: Look for exact Apache version
- Exploitation: Match with CVEs for targeted attacks

### 19. CVE-2017-15715 - mod_mime Bypass
- Discovery: Upload with double extensions
- Identification: Try `.php%00.jpg`, `.php.jpg`
- Exploitation: Bypass filters to upload a shell

### 20. Insecure CORS Configuration
- Discovery: Check response headers
- Identification: Look for `Access-Control-Allow-Origin: *`
- Exploitation: Hijack session using cross-origin requests

---

## Additional 20 Attack Surfaces

### 21. HTTP/2 DoS (CVE-2023-25690)
- Discovery: Check if HTTP/2 is enabled
- Identification: Send malformed SETTINGS frames
- Exploitation: Crash the server via DoS

### 22. mod_rewrite Open Redirect
- Discovery: Analyze `.htaccess` or virtual host rules
- Identification: Input reflects in Location header
- Exploitation: Redirect victims to attacker-controlled URLs

### 23. Slowloris Attack (Timeout Misconfiguration)
- Discovery: Review Apache timeout settings
- Identification: Send slow HTTP requests
- Exploitation: Starve worker threads, cause DoS

### 24. CVE-2022-31813 - mod_suexec RCE
- Discovery: Confirm mod_suexec is enabled
- Identification: Check binary permissions and input handling
- Exploitation: Execute arbitrary commands

### 25. Log Injection
- Discovery: Inject payloads into headers like User-Agent
- Identification: Review logs for reflected input
- Exploitation: XSS in log viewer panels or log poisoning

### 26. Exposed WebDAV
- Discovery: Try WebDAV verbs like `PROPFIND`
- Identification: WebDAV is enabled and accessible
- Exploitation: Arbitrary file upload and download

### 27. mod_autoindex Misconfig
- Discovery: Check directory listing with previews
- Identification: mod_autoindex is rendering file listings
- Exploitation: Download or view metadata of internal files

### 28. File Inclusion Vulnerabilities
- Discovery: Look for `?file=`, `?page=`
- Identification: Test with `../../etc/passwd`
- Exploitation: Local File Inclusion, possibly leading to RCE

### 29. CVE-2016-0736 - mod_auth_digest DoS
- Discovery: Apache uses mod_auth_digest
- Identification: Send malformed digest requests
- Exploitation: Trigger server crash

### 30. Exposed Server Info
- Discovery: Access `/server-info`
- Identification: No authentication required
- Exploitation: Leak full Apache configuration

### 31. Weak Basic Auth over HTTP
- Discovery: Check `WWW-Authenticate: Basic` header
- Identification: Used over plain HTTP
- Exploitation: Intercept credentials over network

### 32. Exposed Admin Panels
- Discovery: Fuzz for `/manager`, `/admin`, `/console`
- Identification: Default credentials work
- Exploitation: Admin access or full server control

### 33. RFI via Server-Side Includes
- Discovery: Look for `.shtml` files or SSI usage
- Identification: Try `<!--#include virtual="..." -->`
- Exploitation: Remote file inclusion via injected input

### 34. Broken Access Controls in VirtualHost
- Discovery: Review site configs or guess subdomains
- Identification: Access internal routes without auth
- Exploitation: Access staging, test, or admin areas

### 35. Default Credentials on Admin Tools
- Discovery: Use common usernames/passwords
- Identification: Works on exposed admin panels
- Exploitation: Full control of the environment

### 36. mod_php Temp File Race
- Discovery: Check how temp files are handled during upload
- Identification: Symlink race with temp filename
- Exploitation: Overwrite system files during upload

### 37. Dangerous Environment Variables
- Discovery: Look for `SetEnv` in `.htaccess`
- Identification: Injection possible via crafted headers or input
- Exploitation: Command execution via env variable abuse

### 38. Caching Sensitive Content
- Discovery: Review `Cache-Control` headers
- Identification: Private or auth content marked as public
- Exploitation: Session data stored and reused

### 39. Java Deserialization via Apache Modules
- Discovery: Look for serialized input in body or headers
- Identification: Identify Java-backed services
- Exploitation: Send malicious serialized object for RCE

### 40. CVE-2023-27522 - Apache Ingress Controller SSRF
- Discovery: Apache used as ingress in Kubernetes
- Identification: SSRF via manipulated `Host` headers
- Exploitation: Access internal metadata endpoints

---

Tools for Testing:
- nmap, httpx, ffuf, curl, dirsearch
- testssl.sh, nikto, whatweb
- Burp Suite, SSRF tools, log poisoning payloads
- Custom bash scripts for mass recon

---
\





# Top 12 Version-Based P1 Issues in Apache HTTP Server

Each issue includes:
- Affected Version(s)
- Summary
- Impact
- Basic Exploitation Method

---

### 1. CVE-2021-41773
- **Affected**: Apache HTTPD 2.4.49
- **Summary**: Path traversal and file disclosure
- **Impact**: RCE (if CGI is enabled)
- **Exploit**: 

Combine with CGI upload for full RCE.

---

### 2. CVE-2021-42013
- **Affected**: Apache HTTPD 2.4.50
- **Summary**: Incomplete patch of CVE-2021-41773
- **Impact**: RCE
- **Exploit**: Path traversal + script execution using:



---

### 3. CVE-2019-0211
- **Affected**: Apache HTTPD 2.4.17 to 2.4.38 (on Unix)
- **Summary**: Local Privilege Escalation
- **Impact**: Unprivileged user → root
- **Exploit**: Place malicious script and wait for master process to restart or reload.

---

### 4. CVE-2022-23943
- **Affected**: Apache HTTPD 2.4.52
- **Summary**: Command injection in mod_sed via crafted headers
- **Impact**: RCE
- **Exploit**: Inject sed expressions in headers like:



---

### 5. CVE-2022-22721
- **Affected**: Apache HTTPD < 2.4.52
- **Summary**: Buffer Overflow in mod_lua
- **Impact**: Potential RCE / DoS
- **Exploit**: Crafted Lua script in request

---

### 6. CVE-2023-25690
- **Affected**: Apache HTTPD 2.4.55 and earlier (with mod_proxy)
- **Summary**: HTTP/2 DoS vulnerability
- **Impact**: Denial of Service (can lead to crash loop)
- **Exploit**: Flood server with malicious HTTP/2 frames

---

### 7. CVE-2022-22720
- **Affected**: Apache HTTPD < 2.4.52
- **Summary**: Use-after-free in `r:parsebody`
- **Impact**: Potential RCE
- **Exploit**: Complex chaining via crafted request and Lua module

---

### 8. CVE-2021-26691
- **Affected**: Apache HTTPD (2.4.46 and lower)
- **Summary**: Session fixation / cache poisoning in mod_session
- **Impact**: Session hijacking
- **Exploit**: Inject poisoned cookies and wait for cache reuse

---

### 9. CVE-2017-15715
- **Affected**: Apache HTTPD 2.4.0 to 2.4.29
- **Summary**: mod_mime whitelist bypass
- **Impact**: File upload → RCE
- **Exploit**: Upload `.php%00.jpg` to bypass restrictions

---

### 10. CVE-2016-0736
- **Affected**: Apache HTTPD 2.2.x and 2.4.x with mod_auth_digest
- **Summary**: NULL pointer dereference
- **Impact**: DoS
- **Exploit**: Send malformed digest auth request

---

### 11. CVE-2014-0231
- **Affected**: Apache HTTPD 2.4.6 and earlier
- **Summary**: mod_cgid denial of service
- **Impact**: Resource exhaustion
- **Exploit**: Flood `CGI` scripts with slow requests

---

### 12. CVE-2010-1623
- **Affected**: Apache HTTPD 2.2.14 and earlier
- **Summary**: mod_proxy_ajp info disclosure or code execution
- **Impact**: RCE via internal AJP abuse
- **Exploit**: SSRF or RCE via backend manipulation

---

# Recommendation:
Always check the exact Apache version via headers or `/server-status`. Use this list to cross-check possible vulnerabilities based on version and module usage. Focus on chaining these with misconfigurations (e.g., exposed CGI, open directory listing, weak file upload filters) to achieve full compromise.


