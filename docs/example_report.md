# SAST Security Report — WebGoat
Date: 2025-04-30
Target: https://github.com/WebGoat/WebGoat
Analyzer: late-sast 1.0.0 (code graph SAST + live verification)

## Executive Summary
WebGoat is a **deliberately insecure** Spring Boot web application designed for educational purposes. The audit identified **36+ intentional vulnerability lessons** across SQL Injection, XSS, XXE, Path Traversal, SSRF, JWT forgery, Deserialization, CSRF, and insecure file uploads. Key architectural finding: the application uses vulnerable versions of several libraries including xstream (1.4.5) with known CVEs. The app serves its web interface on port 8080 with a `/WebGoat` context path and exposes 106 entry points across multiple lesson modules.

## Critical Findings

### SQL Injection — String Concatenation in Query Building
**Location:** `SqlInjectionLesson6a.java` (and multiple other SQL injection lessons)
**CVSS:** ~9.8 (where exploitable)
The `injectableQuery()` method concatenates user input directly into SQL strings:
```java
query = "SELECT * FROM user_data WHERE last_name = '" + accountName + "'";
```
This enables classic UNION-based and blind SQL injection attacks. Affected lessons: `/SqlInjection/attack5`, `/SqlInjection/attack6a`, `/SqlInjection/attack9`, `/SqlInjectionAdvanced/attack6a`, `/SqlInjectionAdvanced/attack6b`, `/SqlInjectionMitigations/attack12a`, and others.

### Insecure Deserialization
**Location:** `VulnerableTaskHolder.java` (`/org/dummy/insecure/framework/VulnerableTaskHolder.java`)
**CVSS:** ~9.8
```java
private void readObject(ObjectInputStream stream) throws Exception {
    stream.defaultReadObject();
    if (taskAction.startsWith("sleep") || taskAction.startsWith("ping")) {
        Runtime.getRuntime().exec(taskAction);
    }
}
```
A `Serializable` class with a custom `readObject` method that executes shell commands (`sleep`, `ping`) during deserialization. Attackers can craft serialized payloads to achieve Remote Code Execution (RCE).

### JWT Secret Key Forgery
**Location:** `JWTSecretKeyEndpoint.java` (`/JWT/secret`)
**CVSS:** ~9.0
```java
public static final String[] SECRETS = {"victory", "business", "available", "shipping", "washington"};
public static final String JWT_SECRET = TextCodec.BASE64.encode(SECRETS[new Random().nextInt(SECRETS.length)]);
```
The JWT signing key is chosen from a small dictionary of 5 values and base64-encoded. An attacker can brute-force all 5 possibilities (~768 bytes of entropy) and forge valid JWT tokens. The `/JWT/secret` endpoint validates against specific claims (`username`, `Role`).

## High Findings

### Reflected Cross-Site Scripting (XSS)
**Location:** `CrossSiteScriptingLesson5a.java` (`/CrossSiteScripting/attack5a`)
**CVSS:** 7.5
The lesson renders user input in the response without encoding:
```java
cart.append("<p>We have charged credit card:" + field1 + "<br />");
```
Multiple XSS lessons exist (`/CrossSiteScripting/attack1`, `/CrossSiteScripting/phone-home-xss`, `/CrossSiteScriptingStored/stored-xss`) testing reflected, DOM-based, and stored XSS scenarios.

### XXE — XML External Entity Injection
**Location:** `CommentsCache.java` (`/xxe/parseXml`)
**CVSS:** 7.5
```java
var jc = JAXBContext.newInstance(Comment.class);
var xif = XMLInputFactory.newInstance();
var xsr = xif.createXMLStreamReader(new StringReader(xml));
var unmarshaller = jc.createUnmarshaller();
```
The XML parser is created without security features enabled by default. External DTD entities are resolved when `securityEnabled` is true, but the initial `XMLInputFactory` lacks `ACCESS_EXTERNAL_DTD` restriction unless explicitly set.

### Path Traversal / Zip Slip
**Location:** `ProfileUpload.java`, `ProfileZipSlip.java` (`/PathTraversal/profile-upload`)
**CVSS:** 7.0+
File upload handler accepts user-supplied filenames and paths without validation. The `ProfileZipSlip` variant specifically demonstrates ZIP slip vulnerability where `../` sequences in archive entries can overwrite files outside the target directory.

### Server-Side Request Forgery (SSRF)
**Location:** `SSRFTask1.java`, `SSRFTask2.java` (`/SSRF/task1`, `/SSRF/task2`)
**CVSS:** 7.0
The application makes HTTP requests to user-supplied URLs (e.g., `/SSRF/task2` uses `furBall()` method to fetch external resources). Internal endpoints are reachable via `http://127.0.0.1:8080` or `http://localhost:8080`.

### JWT Algorithm Confusion / None Attack
**Location:** `JWTDecodeEndpoint.java`, `JWTToken.java`
**CVSS:** 7.0
The JWT lesson demonstrates algorithm confusion where the `alg` field can be set to `none` or swapped between HS256/RS256, allowing signature verification bypass.

## Medium Findings

### Insecure HTTP Session (HijackSession)
**Location:** `HijackSessionAssignment.java` (`/HijackSession/login`)
**CVSS:** 6.5
Session management lesson demonstrates cookie-based session hijacking via HTTP header manipulation.

### CSRF-Protected and Unprotected Endpoints
**Location:** `CSRF.java` lesson with `/CSRF/protected` and `/CSRF/protectedGet` endpoints
**CVSS:** 5.4
Some endpoints lack CSRF token validation. The `CSRF` lesson teaches both vulnerable and protected patterns.

### Open Redirect
**Location:** `OpenRedirectTask1.java`, `OpenRedirectTask2.java`
**CVSS:** 6.5
URL redirect endpoints allow external domain redirects via query parameter manipulation.

### Weak Random Key Generation
**Location:** `JWTSecretKeyEndpoint.java`
**CVSS:** 6.5
Uses `java.util.Random` (not `SecureRandom`) for JWT secret selection. With only 5 possible values, brute-force is trivial.

### Insecure File Upload
**Location:** `ProfileUpload.java`
**CVSS:** 6.0
Accepts uploaded files without MIME-type validation or extension filtering. File path constructed directly from user input.

## Low Findings

### Verbose Error Messages
**Location:** `VerboseErrorTask.java` (`/securitymisconfiguration`)
**CVSS:** 3.1
The application exposes stack traces and SQL error messages that can leak internal state.

### Debug Endpoint Exposure
**CVSS:** 3.0
Several assignment endpoints return raw SQL queries in the response output (e.g., `YOUR_QUERY_WAS` prefix in error messages).

### Missing HSTS / Secure Cookie Flags
**CVSS:** 3.0
The application defaults to non-SSL (`webgoat.sslenabled=false`). Cookies are not flagged with `Secure` or `SameSite` attributes in some endpoints.

## Dependency Vulnerabilities

The following vulnerabilities were identified in the application's Maven dependencies:

### XStream 1.4.5 (pom.xml line 108, version property `xstream.version`)
| CVE | CVSS | Severity | Description | Link |
|-----|------|----------|-------------|------|
| CVE-2022-41966 | 8.2 | HIGH | Stack overflow DoS via recursive hash calculation in collection/map processing | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2022-41966) |
| CVE-2022-40152 | 6.5 | MEDIUM | Woodstox DTD-based stack overflow DoS | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2022-40152) |
| CVE-2022-40151 | 6.5 | MEDIUM | XML parser stack overflow DoS | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2022-40151) |
| CVE-2021-43859 | 7.5 | HIGH | 100% CPU DoS via XML element recursion | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2021-43859) |

### JAXB API 2.3.1 (pom.xml line 78, `${jaxb.version}`)
- Known issues with XML processing when used alongside xstream for deserialization

### JJWT 0.9.1 (pom.xml line 79, `${jjwt.version}`)
- Older version used for JWT building/parsing
- Vulnerable to algorithm confusion when `alg` is not strictly validated

### Jose4j 0.9.3 (pom.xml line 80, `${jose4j.version}`)
- Used for JWT/JWK operations
- Older version may have known key generation issues

## Informational

- **Architecture:** Spring Boot 3.5.6 on Java 25 (JDK 25), Apache Tomcat 10.1.46
- **Build:** Maven-based, `pom.xml` with multi-profile configuration (`local-server`, `start-server`, `owasp`)
- **Context Path:** `/WebGoat`
- **Database:** HSQLDB (in-memory) via Flyway migrations
- **Frontend:** Bootstrap 5.3.5, jQuery 3.7.1
- **Test Framework:** Selenium WebDriver, Playwright, Failsafe integration tests
- **WebWolf Sidecar:** Separate service on port 9090 for email/file hosting during lessons
- **Total Indexed Nodes:** 4,451 | **Edges:** 9,722

## Scan Coverage
Languages: Java (primary), JavaScript/TypeScript (frontend lessons), XML
Entry points: 106 routes discovered
Functions analysed: 4,451 nodes across 9,722 graph edges
Findings: 3 critical, 4 high, 5 medium, 3 low
Vulnerable dependencies: 4 CVEs identified in XStream 1.4.5
Unverifiable: Live exploit testing limited by container state at time of scan

## Remediation Priority

1. **PRIORITY 1 — Upgrade XStream to ≥1.4.20** (3 CVEs, effort: 10 min)
   Update `pom.xml`: `<xstream.version>1.4.20</xstream.version>`

2. **PRIORITY 2 — Fix SQL Injection in SqlInjectionLesson6a** (effort: 15 min)
   Replace string concatenation with parameterized queries:
   ```java
   try (PreparedStatement ps = connection.prepareStatement(
           "SELECT * FROM user_data WHERE last_name = ?")) {
       ps.setString(1, accountName);
       ResultSet rs = ps.executeQuery();
   }
   ```

3. **PRIORITY 3 — Harden JWTSecretKeyEndpoint** (effort: 20 min)
   - Replace `java.util.Random` with `SecureRandom`
   - Increase secret space or use a proper key derivation function

4. **PRIORITY 4 — Add XSS escaping** (effort: 15 min)
   Apply `StringEscapeUtils.escapeHtml4()` or use Thymeleaf's auto-escaping in `CrossSiteScriptingLesson5a`

5. **PRIORITY 5 — Restrict XXE parser configuration** (effort: 10 min)
   Set `ACCESS_EXTERNAL_DTD` and `ACCESS_EXTERNAL_SCHEMA` to `""` by default in `XMLInputFactory`

6. **PRIORITY 6 — Validate file upload paths** (effort: 20 min)
   Add `Path.startsWith(baseDir)` check in `ProfileUpload.uploadFileHandler()`

7. **PRIORITY 7 — Add CSRF tokens** to all state-changing endpoints (effort: 30 min)

8. **PRIORITY 8 — Enable HTTPS** in production (effort: 20 min)
   Set `webgoat.sslenabled=true` and configure TLS certificate

---
*Report generated by late-sast v1.0.0 | 2025-04-30*
*WebGoat is intentionally vulnerable — findings represent expected behavior per design.*
