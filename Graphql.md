# Advanced GraphQL Bug Bounty Hunting Cheat Sheet  
### Focus: Black-box Web App Testing with Exploitable CVEs, Techniques & Payloads

---

## How to Use:  
This cheat sheet highlights critical attack vectors for GraphQL endpoints, known CVEs, misconfigurations, and exploitation methods tailored for bug bounty hunters testing without source access.

---

### 1. **Discovery of GraphQL Endpoints**  
- **Techniques:**  
  - Common paths: `/graphql`, `/api/graphql`, `/v1/graphql` or any API gateway.  
  - Look for HTTP POST requests with `application/json` content-type containing `"query":` key.  
  - Use Burp Suite or proxy tools to identify unusual JSON API calls.  
  - Automatically scan with tools like `Graphqler`, `GraphQLmap`, or grep with `grep -Ri "graphql"` on URLs/logs.

---

### 2. **Introspection Enabled – Schema Enumeration**  
- **Discovery:**  
  - Send introspection query:
    ```
    {
      __schema {
        types {
          name
          fields {
            name
          }
        }
      }
    }
    ```
  - If enabled, retrieves full schema including types, fields, queries, mutations, and subscriptions.  
- **Impact:** Enables crafting precise queries and mutations to exploit business logic.  
- **Exploitation:**  
  - Use full schema knowledge for fuzzing, authorization bypass, and injection attack surface mapping.  
- **Mitigation Check:** Determines if introspection query is disabled or protected (common security best practice).

---

### 3. **Authorization and Access Control Bypass**  
- **Discovery:**  
  - Test if queries and mutations can access or modify data without proper auth tokens.  
  - Attempt privilege escalation by querying admin functions as a normal user.  
  - Use specially crafted queries or header manipulation.  
- **Exploitation:**  
  - Access sensitive data, perform unauthorized mutations, or escalate privileges.  
- **Example:** Some GraphQL servers do not enforce field-level auth, exposing data leakage vectors.

---

### 4. **Blind or Error-based Injection Vulnerabilities**  
- **Discovery:**  
  - Inject GraphQL query arguments with special characters (`'`, `"`, `{}`, `()`, `$`) to test injection response.  
  - Check error messages, response timing differences, or abnormal outputs for indications of injection points.  
- **Exploitation Examples:**  
  - **SQL Injection:** In resolvers interacting with databases.  
  - **NoSQL Injection:** MongoDB-like query injections in filters.  
  - **Command Injection:** Unsafe evaluation in custom resolvers or directives.  
- **Tools:** GraphQLmap, Burp Intruder, manual fuzzing payloads.

---

### 5. **Batching & Query Complexity Abuse (Denial of Service)**  
- **Discovery:**  
  - Test if application accepts batched queries (multiple queries/mutations in a single request).  
  - Analyze if complexity or depth limiting is enforced.  
- **Exploitation:**  
  - Send deeply nested or batched queries consuming excessive resources (CPU, memory).  
  - Resulting in Denial of Service or delayed responses.  
- **Tips:** Generate complex queries automatically with tools or scripts.

---

### 6. **CVE-2021-3121 — GraphQL Playground SSRF & RCE in Apollo Server**  
- **Affected Versions:** Apollo Server Playground before v2.25.0  
- **Discovery:**  
  - Identify use of Apollo Server with enabled Playground IDE.  
- **Exploitation:**  
  - Exploit SSRF through schema introspection in the playground.  
  - Combine SSRF with other flaws to reach internal services or achieve RCE.  
- **Reference:**  
  - [GitHub Advisory and PoC](https://github.com/apollographql/apollo-server/security/advisories/GHSA-r6h7-gv6p-3w4g)  
- **Mitigation:** Upgrade Apollo Server and disable playground on production.

---

### 7. **GraphQL Injection Leading to Authentication Bypass (CVE-2019-10742)**  
- **Affected Implementations:** Vulnerable custom resolvers in certain CMS and platforms.  
- **Discovery:**  
  - Try inputting query parameters with injection payloads targeting badly sanitized inputs.  
- **Exploitation:**  
  - Exploit input sanitization flaws to bypass authentication or escalate privileges.  
- **Example Payload:**
- 
query {
user(username: "admin" OR "1"="1") {
id
email
}
}


---

### 8. **Introspection Data Leakage and Variant Attacks**  
- **Discovery:**  
- Even if introspection is disabled, APIs may leak types or fields via error messages or response timing.  
- **Exploitation:**  
- Use partial introspection info combined with fuzzing for information disclosure or injection points.

---

### 9. **File Upload Vulnerabilities in GraphQL**  
- **Discovery:**  
- Detect multipart file upload support via GraphQL mutations or spec-compliant `graphql-multipart-request-spec`.  
- **Exploitation:**  
- Abuse inadequate checks to upload malicious files or webshells.  
- Combine with path traversal or insecure storage to achieve remote code execution.

---

### 10. **Improper Validation in Custom Scalars and Directives**  
- **Discovery:**  
- Identify custom defined scalars (`Date`, `Email`, `JSON`) and directives in schema.  
- **Exploitation:**  
- Exploit lax input validation to inject payloads or cause unexpected behavior in back-end code.

---

### 11. **Insecure Deserialization in Resolvers**  
- **Discovery:**  
- Find resolvers accepting serialized inputs (JSON, XML) without proper validation.  
- **Exploitation:**  
- Supply crafted serialized payloads triggering deserialization flaws leading to RCE.

---

### 12. **Lack of Rate Limiting & Logging**  
- **Discovery:**  
- Assess if rapid repeated query attempts or bruteforcing is possible without throttling.  
- **Exploitation:**  
- Automate data exfiltration or injection via bulk querying.

---

## Recommended Tools & Resources  
- **GraphQLmap:** Automated GraphQL injection & exploitation tool.  
- **Burp Suite:** For intercepting, crafting, and fuzzing GraphQL payloads.  
- **Apollo Engine & GraphQL-Cop:** For introspection and schema fuzzing.  
- **Nuclei Templates:** Search community repos for GraphQL-related CVE scans.  
- **GitHub Dorks:** To find leaked GraphQL endpoints or configs.  
- **Payload Examples:** Ready-made payloads for injection testing at [PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/GraphQL).

---

## BountyBoy: Elite Bug Bounty Program — trusted by 8000+ learners.
📄 Syllabus: https://lnkd.in/d6vTg3k9 🎯 Enroll Now: https://lnkd.in/d7p5spcS
