---
name: sast-tls
description: >-
  Detect disabled TLS certificate and hostname verification in outbound HTTPS clients using a
  three-phase approach: recon (find all TLS verification sinks where verification is explicitly
  disabled), batched verify (determine in parallel whether each sink is reachable in a production
  code path and not guarded by an environment/test-only flag, 3 sinks each), and merge
  (consolidate batch results into final reports). Covers Python requests/httpx/urllib, Go
  tls.Config, Node.js https/fetch, Java JSSE/OkHttp, .NET HttpClient, Ruby Net::HTTP, and PHP
  cURL. Requires sast/architecture.md (run sast-analysis first). Outputs findings to
  sast/tls-results.md and sast/tls-results.json. Use when asked to find TLS verification
  bypass, MITM exposure, or CWE-295 issues.
version: 0.1.0
---

# TLS Verification Disabled Detection

You are performing a focused security assessment to find cases where TLS certificate or hostname verification has been explicitly disabled for outbound network connections. This skill uses a three-phase approach with subagents: **recon** (find every location where TLS verification is turned off), **batched verify** (determine production reachability in parallel batches of 3), and **merge** (consolidate batch reports into `sast/tls-results.md` and `sast/tls-results.json`).

**Prerequisites**: `sast/architecture.md` must exist. Run the analysis skill first if it doesn't.

---

## What is Disabled TLS Verification

TLS (Transport Layer Security) provides two distinct security properties when establishing an outbound HTTPS connection:

1. **Certificate verification**: The server's certificate is signed by a trusted Certificate Authority (CA), is not expired, and matches the expected domain. Disabling this allows any certificate — including one presented by an attacker — to be accepted.
2. **Hostname verification**: The hostname in the server's certificate matches the hostname the client is connecting to. Disabling this allows a certificate issued for `attacker.com` to be accepted when connecting to `api.example.com`.

Disabling either property exposes all data transmitted over the connection to a **machine-in-the-middle (MITM) attack**: a network attacker can intercept and modify traffic, steal credentials, tokens, session cookies, PII, and financial data, or inject malicious payloads into API responses.

The core pattern: *a TLS client option that controls certificate or hostname validation is explicitly set to a value that bypasses verification.*

### What TLS Verification Bypass IS

- Passing `verify=False` to Python `requests.get()`, `requests.post()`, `httpx.get()`, or any `requests.Session()` / `httpx.Client()` call
- Creating an `ssl.SSLContext` with `ssl.CERT_NONE` or `check_hostname=False` and using it for outbound connections
- Calling `ssl._create_unverified_context()` and passing the result to any socket-level or `urllib` call
- Setting `InsecureSkipVerify: true` in a Go `tls.Config{}` struct used by `http.Transport` or a gRPC dial option
- Passing `rejectUnauthorized: false` in the `https.request` options object or to `https.Agent` in Node.js
- Setting the `NODE_TLS_REJECT_UNAUTHORIZED` environment variable to `"0"` anywhere in application startup or process configuration code
- Implementing `ALLOW_ALL_HOSTNAME_VERIFIER` or registering it via `HttpsURLConnection.setDefaultHostnameVerifier(...)` in Java
- Implementing a no-op `X509TrustManager` that overrides `checkClientTrusted`/`checkServerTrusted`/`getAcceptedIssuers` without actually validating anything (trust-all TrustManager)
- Passing a lambda `(sender, cert, chain, errors) => true` to `ServicePointManager.ServerCertificateValidationCallback` or `HttpClientHandler.ServerCertificateCustomValidationCallback` in .NET
- Setting `OpenSSL::SSL::VERIFY_NONE` in Ruby's `Net::HTTP`, Faraday, or HTTParty client configuration
- Passing `CURLOPT_SSL_VERIFYPEER => false` or `CURLOPT_SSL_VERIFYHOST => 0` to `curl_setopt` in PHP
- OkHttp or Retrofit in Android/Java with a custom `SSLSocketFactory` built from a trust-all `TrustManager`

### What TLS Verification Bypass is NOT

Do not flag these patterns:

- **Custom CA bundle with full validation**: `requests.get(url, verify='/etc/ssl/certs/company-ca.crt')` — this enables verification with a custom CA, not disables it
- **Certificate pinning**: A custom `TrustManager` that checks a specific known certificate hash instead of calling out to CA chains — this is a stronger form of verification, not weaker
- **Test-only scope with provable isolation**: `if Rails.env.test?` / `if os.getenv('PYTEST_CURRENT_TEST')` blocks or test fixture files (`test_*.py`, `*_test.go`, `*.spec.ts`) where the flag cannot reach production code paths
- **Internal trusted CA in a controlled environment**: A `tls.Config` that loads an internal self-signed CA bundle and sets `RootCAs` accordingly — this is not bypassing verification, it is providing a trust anchor
- **`CURLOPT_SSL_VERIFYHOST => 2`**: The value `2` is the secure default (check hostname); only `0` or `1` disables it — do not flag `2`
- **Mock HTTP servers in integration tests**: `httpretty`, `responses`, `nock`, `msw`, or similar libraries that intercept at the socket level for testing — no real TLS is involved
- **Client certificates (`cert=` in requests)**: Providing a client certificate for mutual TLS authentication is unrelated to server certificate verification

### Patterns That Prevent TLS Verification Bypass

When you see these patterns, the connection is likely **not vulnerable**:

**1. Explicit CA bundle path (Python)**
```python
# SECURE: verification is on, using a custom CA bundle
requests.get(url, verify='/etc/ssl/certs/ca-certificates.crt')
requests.get(url, verify='/app/certs/internal-ca.pem')
session.verify = '/etc/ssl/ca-bundle.crt'

# SECURE: default behavior — verify=True is the default
response = requests.get(url)
```

**2. Go TLS with proper root CA pool**
```go
// SECURE: custom CA pool, verification still enforced
caCert, _ := os.ReadFile("/etc/ssl/certs/ca-certificates.crt")
caCertPool := x509.NewCertPool()
caCertPool.AppendCertsFromPEM(caCert)
tlsConfig := &tls.Config{RootCAs: caCertPool}
transport := &http.Transport{TLSClientConfig: tlsConfig}
```

**3. Node.js with CA bundle**
```javascript
// SECURE: custom CA, hostname verification still active
const options = {
  ca: fs.readFileSync('/etc/ssl/certs/ca-certificates.crt'),
  // rejectUnauthorized defaults to true
};
https.request(options, callback);
```

**4. Java with explicit TrustManager loading a keystore**
```java
// SECURE: loads actual CA certificates rather than trusting all
KeyStore trustStore = KeyStore.getInstance("JKS");
trustStore.load(new FileInputStream("/app/truststore.jks"), password);
TrustManagerFactory tmf = TrustManagerFactory.getInstance("PKIX");
tmf.init(trustStore);
SSLContext ctx = SSLContext.getInstance("TLS");
ctx.init(null, tmf.getTrustManagers(), null);
```

**5. Environment-gated flag (provably non-production)**
```python
# SECURE (if TEST env var is never set in production):
import os
verify = not os.getenv('TEST_MODE', '').lower() == 'true'
requests.get(url, verify=verify)
# — BUT ONLY if you can confirm TEST_MODE is never true in prod
```

**6. .NET with proper certificate validation**
```csharp
// SECURE: validates the certificate, only accepts expected subject
handler.ServerCertificateCustomValidationCallback = (msg, cert, chain, errors) => {
    return errors == SslPolicyErrors.None && 
           cert.Subject.Contains("CN=api.example.com");
};
```

---

## Vulnerable vs. Secure Examples

### Python — requests

```python
# VULNERABLE: certificate and hostname verification completely disabled
import requests

def fetch_user_data(user_id: str) -> dict:
    url = f"https://api.internal.example.com/users/{user_id}"
    response = requests.get(url, verify=False)  # MITM possible
    return response.json()

# VULNERABLE: session-level disable affects all requests
session = requests.Session()
session.verify = False  # all requests through this session are unprotected

# VULNERABLE: explicit unverified context
import ssl
import urllib.request

ctx = ssl._create_unverified_context()
response = urllib.request.urlopen("https://api.example.com/data", context=ctx)

# VULNERABLE: CERT_NONE on a manually constructed SSLContext
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.verify_mode = ssl.CERT_NONE
ctx.check_hostname = False

# SECURE: default (verify=True) — no argument needed
response = requests.get(url)

# SECURE: custom internal CA bundle
response = requests.get(url, verify='/etc/ssl/certs/company-ca.pem')

# SECURE: verify set to the CA bundle path in a session
session = requests.Session()
session.verify = '/app/config/internal-ca.crt'
```

### Python — httpx

```python
# VULNERABLE: httpx verify=False
import httpx

async def get_payment_status(payment_id: str) -> dict:
    async with httpx.AsyncClient(verify=False) as client:  # MITM possible
        resp = await client.get(f"https://payments.example.com/status/{payment_id}")
        return resp.json()

# VULNERABLE: synchronous httpx client
client = httpx.Client(verify=False)

# SECURE: httpx with custom CA
client = httpx.AsyncClient(verify='/etc/ssl/certs/ca-bundle.crt')

# SECURE: default (verify=True is the httpx default)
async with httpx.AsyncClient() as client:
    resp = await client.get(url)
```

### Go — net/http

```go
// VULNERABLE: InsecureSkipVerify disables both cert and hostname verification
import (
    "crypto/tls"
    "net/http"
)

func fetchSecret(apiURL string) ([]byte, error) {
    tr := &http.Transport{
        TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // MITM possible
    }
    client := &http.Client{Transport: tr}
    resp, err := client.Get(apiURL)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()
    return io.ReadAll(resp.Body)
}

// VULNERABLE: gRPC dial with insecure TLS
import "google.golang.org/grpc/credentials"
creds := credentials.NewTLS(&tls.Config{InsecureSkipVerify: true})
conn, _ := grpc.Dial(address, grpc.WithTransportCredentials(creds))

// SECURE: standard http.Client uses system CA pool by default
client := &http.Client{}
resp, err := client.Get(apiURL)

// SECURE: custom CA pool, verification enforced
caCert, err := os.ReadFile("/etc/ssl/certs/ca-certificates.crt")
caCertPool := x509.NewCertPool()
caCertPool.AppendCertsFromPEM(caCert)
tr := &http.Transport{
    TLSClientConfig: &tls.Config{RootCAs: caCertPool},
}
client := &http.Client{Transport: tr}
```

### Node.js — https / node-fetch / axios

```javascript
// VULNERABLE: rejectUnauthorized: false in https.request options
const https = require('https');

function callSecureAPI(path) {
  const options = {
    hostname: 'api.example.com',
    port: 443,
    path,
    method: 'GET',
    rejectUnauthorized: false,  // MITM possible
  };
  return new Promise((resolve, reject) => {
    const req = https.request(options, (res) => { /* ... */ });
    req.end();
  });
}

// VULNERABLE: https.Agent with rejectUnauthorized: false passed to node-fetch or axios
const agent = new https.Agent({ rejectUnauthorized: false });
const response = await fetch('https://api.example.com/data', { agent });
await axios.get('https://api.example.com/data', { httpsAgent: agent });

// VULNERABLE: process-level flag — affects all HTTPS in the process
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

// VULNERABLE: .env file or startup script with this line
// NODE_TLS_REJECT_UNAUTHORIZED=0

// SECURE: default behavior — rejectUnauthorized is true by default
const req = https.request({ hostname: 'api.example.com', path: '/data' }, callback);

// SECURE: custom CA (still verifies, with additional trust anchor)
const options = {
  hostname: 'internal.corp.example.com',
  ca: fs.readFileSync('/app/certs/internal-ca.pem'),
};
```

### Java — HttpsURLConnection / OkHttp

```java
// VULNERABLE: ALLOW_ALL_HOSTNAME_VERIFIER (deprecated but still seen)
import javax.net.ssl.HttpsURLConnection;
import org.apache.http.conn.ssl.AllowAllHostnameVerifier;

HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
conn.setHostnameVerifier(new AllowAllHostnameVerifier());  // hostname check disabled

// VULNERABLE: always-true lambda hostname verifier
conn.setHostnameVerifier((hostname, session) -> true);  // hostname check disabled

// VULNERABLE: global default override
HttpsURLConnection.setDefaultHostnameVerifier((hostname, session) -> true);

// VULNERABLE: trust-all TrustManager (accepts any certificate)
TrustManager[] trustAllCerts = new TrustManager[]{
    new X509TrustManager() {
        public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
        public void checkClientTrusted(X509Certificate[] certs, String authType) {}  // no-op
        public void checkServerTrusted(X509Certificate[] certs, String authType) {}  // no-op
    }
};
SSLContext sc = SSLContext.getInstance("TLS");
sc.init(null, trustAllCerts, new SecureRandom());
HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());

// VULNERABLE: OkHttp with trust-all
OkHttpClient client = new OkHttpClient.Builder()
    .hostnameVerifier((hostname, session) -> true)  // hostname check disabled
    .sslSocketFactory(insecureSocketFactory, trustAllManager)
    .build();

// SECURE: OkHttp default — uses system CA store with proper verification
OkHttpClient client = new OkHttpClient();

// SECURE: explicit truststore with proper CA chain
KeyStore trustStore = KeyStore.getInstance("JKS");
trustStore.load(new FileInputStream("/app/truststore.jks"), "password".toCharArray());
TrustManagerFactory tmf = TrustManagerFactory.getInstance(
    TrustManagerFactory.getDefaultAlgorithm());
tmf.init(trustStore);
SSLContext ctx = SSLContext.getInstance("TLS");
ctx.init(null, tmf.getTrustManagers(), null);
```

### PHP — cURL

```php
// VULNERABLE: disabling peer verification (certificate not checked)
function fetchUserProfile(string $userId): array {
    $ch = curl_init("https://api.example.com/users/{$userId}");
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);  // MITM possible
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    $response = curl_exec($ch);
    curl_close($ch);
    return json_decode($response, true);
}

// VULNERABLE: disabling hostname verification (value 0 or 1)
curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 1);  // 1 also disables strict check

// VULNERABLE: both disabled in a reusable Guzzle client
$client = new \GuzzleHttp\Client([
    'verify' => false,  // MITM possible
]);

// SECURE: default cURL behavior (peer verification is enabled by default)
$ch = curl_init("https://api.example.com/users/{$userId}");
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

// SECURE: custom CA bundle
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);  // 2 = strict hostname check
curl_setopt($ch, CURLOPT_CAINFO, '/etc/ssl/certs/ca-certificates.crt');

// SECURE: Guzzle with custom CA
$client = new \GuzzleHttp\Client([
    'verify' => '/etc/ssl/certs/ca-certificates.crt',
]);
```

### .NET — HttpClient

```csharp
// VULNERABLE: always-true callback on ServicePointManager (global)
using System.Net;
using System.Net.Security;

// This affects ALL HttpClient instances in the AppDomain
ServicePointManager.ServerCertificateValidationCallback =
    (sender, cert, chain, errors) => true;  // MITM possible

// VULNERABLE: per-handler callback returning true
var handler = new HttpClientHandler
{
    ServerCertificateCustomValidationCallback = (message, cert, chain, errors) => true,
};
var client = new HttpClient(handler);

// VULNERABLE: DangerousAcceptAnyServerCertificateValidator (explicit bypass)
var handler = new HttpClientHandler();
handler.ServerCertificateCustomValidationCallback =
    HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;

// SECURE: default HttpClient uses OS certificate store with full validation
var client = new HttpClient();

// SECURE: custom CA with proper validation logic
var handler = new HttpClientHandler();
handler.ServerCertificateCustomValidationCallback = (message, cert, chain, errors) =>
{
    if (errors == SslPolicyErrors.None) return true;
    // Allow only a specific known self-signed cert by thumbprint
    return cert?.GetCertHashString() == "EXPECTED_THUMBPRINT_HEX";
};
```

### Ruby — Net::HTTP / Faraday

```ruby
# VULNERABLE: VERIFY_NONE disables certificate verification
require 'net/http'
require 'openssl'

def fetch_data(uri_string)
  uri = URI(uri_string)
  http = Net::HTTP.new(uri.host, uri.port)
  http.use_ssl = true
  http.verify_mode = OpenSSL::SSL::VERIFY_NONE  # MITM possible
  http.get(uri.path)
end

# VULNERABLE: Faraday adapter with verify: false
conn = Faraday.new(url: 'https://api.example.com') do |f|
  f.adapter :net_http do |http|
    http.verify_mode = OpenSSL::SSL::VERIFY_NONE
  end
end

# VULNERABLE: HTTParty with global SSL override
class ApiClient
  include HTTParty
  default_options.update(verify: false)
end

# SECURE: default Net::HTTP with SSL — verify_mode defaults to VERIFY_PEER
http = Net::HTTP.new(uri.host, uri.port)
http.use_ssl = true
# verify_mode is VERIFY_PEER by default

# SECURE: custom CA bundle
http.ca_file = '/etc/ssl/certs/ca-certificates.crt'
http.verify_mode = OpenSSL::SSL::VERIFY_PEER
```

---

## Execution

This skill runs in three phases using subagents. Pass the contents of `sast/architecture.md` to all subagents as context.

### Phase 1: Recon — Find TLS Verification Bypass Sites

Launch a subagent with the following instructions:

> **Goal**: Find every location in the codebase where TLS certificate or hostname verification has been explicitly disabled. Write results to `sast/tls-recon.md`.
>
> **Context**: You will be given the project's architecture summary. Use it to understand what HTTP client libraries are used, what language/framework stack is present, and what outbound connections the application makes.
>
> **What to search for — TLS verification bypass patterns**:
>
> For each language, look for these specific patterns. Flag ANY occurrence of the bypass flag — you are not yet determining if it is production-reachable; that is Phase 2's job.
>
> **Python**:
> - `verify=False` anywhere in a `requests.get/post/put/patch/delete/head/options/request()` call or `requests.Session()` assignment
> - `session.verify = False` or `self.verify = False` on a requests Session object
> - `ssl.CERT_NONE` assigned to `ctx.verify_mode` or passed as `context=` to urllib
> - `ssl.create_default_context()` followed by `ctx.check_hostname = False` or `ctx.verify_mode = ssl.CERT_NONE`
> - `ssl._create_unverified_context()` — any usage
> - `httpx.Client(verify=False)` or `httpx.AsyncClient(verify=False)` or `verify=False` in any httpx request call
>
> **Go**:
> - `InsecureSkipVerify: true` anywhere in a `tls.Config{}` struct literal
> - Variable assignments `tlsCfg.InsecureSkipVerify = true`
> - `grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{InsecureSkipVerify: true}))`
>
> **Node.js / JavaScript / TypeScript**:
> - `rejectUnauthorized: false` in any `https.request`, `https.get`, `https.Agent`, `tls.connect` options object
> - `NODE_TLS_REJECT_UNAUTHORIZED` set to `'0'` or `"0"` — in `process.env`, `.env` files, startup scripts, `docker-compose.yml`, Kubernetes manifests
> - `agent: new https.Agent({ rejectUnauthorized: false })` passed to fetch, axios, got, or node-fetch
> - `httpsAgent: new https.Agent({ rejectUnauthorized: false })` in axios config
>
> **Java**:
> - `ALLOW_ALL_HOSTNAME_VERIFIER` — any reference (Apache HttpClient)
> - `(hostname, session) -> true` or `(h, s) -> true` passed to `setHostnameVerifier` or `setDefaultHostnameVerifier`
> - `X509TrustManager` implementation with empty/no-op `checkServerTrusted` body
> - `TrustManager` implementations where `getAcceptedIssuers()` returns `new X509Certificate[0]` or `null` AND check methods are no-ops
> - `SSLContext.init(null, trustAllCerts, ...)` where `trustAllCerts` is a no-op TrustManager array
> - OkHttp: `.hostnameVerifier((hostname, session) -> true)` or `.sslSocketFactory(factory, trustAllManager)` with a no-op TrustManager
>
> **PHP**:
> - `CURLOPT_SSL_VERIFYPEER` set to `false`, `0`, or `FALSE`
> - `CURLOPT_SSL_VERIFYHOST` set to `0` or `1` (both are insecure; `2` is secure)
> - Guzzle: `'verify' => false` in client options
> - Symfony HttpClient: `'verify_peer' => false` or `'verify_host' => false`
>
> **.NET / C#**:
> - `ServerCertificateValidationCallback` or `ServerCertificateCustomValidationCallback` assigned a lambda/delegate that always returns `true`
> - `HttpClientHandler.DangerousAcceptAnyServerCertificateValidator` — any usage
> - `ServicePointManager.ServerCertificateValidationCallback` set to a always-true delegate
>
> **Ruby**:
> - `OpenSSL::SSL::VERIFY_NONE` assigned to `verify_mode`
> - `verify: false` in Faraday builder
> - `default_options.update(verify: false)` in HTTParty class
> - `:ssl => { :verify => false }` in RestClient
>
> **Environment / Configuration files** (search `.env`, `.env.*`, `docker-compose.yml`, `kubernetes/*.yaml`, `helm/**/*.yaml`, CI workflow files):
> - `NODE_TLS_REJECT_UNAUTHORIZED=0`
> - `GIT_SSL_NO_VERIFY=true` (if the app uses git over HTTPS programmatically)
>
> **What to skip** (these are safe — do not flag):
> - `verify='/path/to/ca.crt'` — passing a CA bundle path, not disabling verification
> - `ssl.CERT_REQUIRED` or `ssl.CERT_OPTIONAL` — these are not disabling verification
> - `CURLOPT_SSL_VERIFYHOST => 2` — value `2` is the strict/secure setting
> - `rejectUnauthorized: true` — explicitly enabling (same as default)
> - CA bundle loading: `RootCAs`, `ca:`, `cafile:`, `trustStore` — providing a CA pool, not disabling
> - Test-only files with `.test.`, `.spec.`, `_test.go`, `test_*.py` suffix when flag is clearly test-scoped
>
> **Output format** — write to `sast/tls-recon.md`:
>
> ```markdown
> # TLS Recon: [Project Name]
>
> ## Summary
> Found [N] locations where TLS certificate or hostname verification is explicitly disabled.
>
> ## TLS Bypass Sites
>
> ### 1. [Descriptive name — e.g., "verify=False in payment API client"]
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Function / class / endpoint**: [function name, class, or route]
> - **Library / client**: [requests / httpx / https.request / OkHttp / HttpClient / cURL / etc.]
> - **Bypass type**: [cert verification / hostname verification / both]
> - **Bypass pattern**: [e.g., `verify=False` / `InsecureSkipVerify: true` / `VERIFY_NONE` / trust-all TrustManager]
> - **Code snippet**:
>   ```
>   [the line(s) disabling TLS verification]
>   ```
> - **Note**: [any context — e.g., "inside a try block", "session-level flag", "global process override"]
>
> [Repeat for each site]
> ```

### After Phase 1: Check for Candidates Before Proceeding

After Phase 1 completes, read `sast/tls-recon.md`. If the recon found **zero TLS bypass sites** (the summary reports "Found 0" or the "TLS Bypass Sites" section is empty or absent), **skip Phase 2 entirely**. Instead, write the following content to both output files and stop:

```markdown
# TLS Verification Analysis Results

No vulnerabilities found.
```

```json
{
  "findings": []
}
```

Write the markdown to `sast/tls-results.md` and the JSON to `sast/tls-results.json`.

Only proceed to Phase 2 if Phase 1 found at least one TLS bypass site.

### Phase 2: Verify — Production Reachability Analysis (Batched)

After Phase 1 completes, read `sast/tls-recon.md` and split the bypass sites into **batches of up to 3 sites each**. Launch **one subagent per batch in parallel**. Each subagent determines production reachability only for its assigned sites and writes results to its own batch file.

**Batching procedure** (you, the orchestrator, do this — not a subagent):

1. Read `sast/tls-recon.md` and count the numbered site sections under "TLS Bypass Sites" (### 1., ### 2., etc.).
2. Divide them into batches of up to 3. For example, 7 sites → 3 batches (1-3, 4-6, 7).
3. For each batch, extract the full text of those site sections from the recon file.
4. Launch all batch subagents **in parallel**, passing each one only its assigned sites.
5. Each subagent writes to `sast/tls-batch-N.md` where N is the 1-based batch number.
6. Identify the project's primary language/framework from `sast/architecture.md` and select only the matching vulnerable/secure examples from the "Vulnerable vs. Secure Examples" section above. Pass these selected examples to each subagent where indicated by `[TECH-STACK EXAMPLES]` below.

Give each batch subagent the following instructions (substitute the batch-specific values):

> **Goal**: For each assigned TLS bypass site, determine whether the bypass is reachable in a production code path and assess the actual risk. Write results to `sast/tls-batch-[N].md`.
>
> **Your assigned sites** (from the recon phase):
>
> [Paste the full text of the assigned site sections here, preserving the original numbering]
>
> **Context**: You will be given the project's architecture summary. Use it to understand the application's network topology, what external services are called, and how the HTTP client is constructed and used.
>
> **TLS reference — determine production reachability**:
>
> For each site, answer these questions in order:
>
> **Question 1: Is this in a test-only code path?**
>
> A site is test-only if ALL of the following are true:
> - The file is in a test directory (`tests/`, `test/`, `spec/`, `__tests__/`) or has a test naming convention (`_test.go`, `test_*.py`, `.spec.ts`, `.test.js`)
> - OR the bypass is inside a conditional block that is provably only executed during testing: `if os.getenv('PYTEST_CURRENT_TEST')`, `if Rails.env.test?`, `if process.env.NODE_ENV === 'test'`
> - AND there is no way for a production code path to import or call this code
>
> If all three are true → **Not Vulnerable** (test-only). Note in your report why it's test-only.
>
> **Question 2: Is the bypass scoped to a known internal trusted network only?**
>
> A site may be lower-risk if:
> - The URL or endpoint being called is a hardcoded internal hostname (e.g., `localhost`, `*.internal`, `10.x.x.x`) with no path to the public internet
> - AND the application's architecture description confirms it runs in a controlled network segment with no public routing
>
> If true → classify as **Likely Vulnerable** (reduced scope) rather than **Vulnerable**, and set `exploitability: conditional`.
>
> **Question 3: Is the bypass guarded by an environment variable that is demonstrably never set in production?**
>
> Check if the bypass is inside a conditional like:
> - `if os.getenv('DISABLE_TLS_VERIFY'):` or `if process.env.DISABLE_TLS_VERIFY === '1':`
> - Then search the codebase for production config files (`.env.production`, `config/production.yml`, Kubernetes production manifests, Terraform production variables) to determine if this variable is set there
>
> If the variable is demonstrably absent from all production configuration → `exploitability: conditional`, lower confidence
> If the variable is present in production config or its production value is ambiguous → treat as production-reachable
>
> **Question 4: What data is transmitted over this connection?**
>
> Read the code around the bypass site to understand what the HTTP call does:
> - Does it transmit credentials, API keys, session tokens, or authorization headers?
> - Does it transmit PII (names, emails, addresses, health data, financial data)?
> - Is this an internal health check or status endpoint with no sensitive payload?
>
> If sensitive data flows over the unverified connection → severity is **critical** (per spec, raise from default **high**)
> If only non-sensitive internal data → severity remains **high**
> If clearly no-op or health-only with no sensitive data → **medium**
>
> **FP-killers** (patterns that confirm the site is NOT a real vulnerability):
>
> 1. `verify='/path/to/ca.crt'` — if the file shows a CA bundle path being passed elsewhere in the same function/client, the `verify=False` may have been a temporary dev change that was reverted; check the actual executing call
> 2. The class/function is never instantiated or called from any non-test code path — dead code
> 3. The flag is set but then immediately overridden in a subclass or wrapper that always passes `verify=True`
> 4. `CURLOPT_SSL_VERIFYHOST` set to `0` but `CURLOPT_SSL_VERIFYPEER` is `true` — hostname is still at risk, but certificate is checked; this is still a real finding (classify as **Likely Vulnerable** specifically for hostname bypass)
>
> **exploitability / confidence rules**:
>
> - `exploitability: reachable` — bypass is in production code, no env guard, no test scope
> - `exploitability: conditional` — bypass is guarded by an env var whose production value is ambiguous, or limited to an internal network
> - `exploitability: unreachable` — bypass is demonstrably test-only (use this sparingly; confirm with file path + call graph evidence)
> - `confidence: high` — literal bypass pattern in a production file with a clear call path to a real network endpoint
> - `confidence: medium` — bypass is in a shared utility or base class, production use is likely but requires tracing callers; or env-guard whose production value is unknown
> - `confidence: low` — bypass found in a file that appears to be a dev/debug helper; production instantiation not confirmed
>
> **chain_id rules**:
>
> - If the site transmits credentials, tokens, or API keys over the unverified connection, AND those are hardcoded or stored in plaintext: set `chain_id: "mitm-credential"`
> - If the site is the only finding, or no chain applies: `chain_id: null`
>
> **Vulnerable vs. Secure examples for this project's tech stack**:
>
> [TECH-STACK EXAMPLES]
>
> **Classification**:
> - **Vulnerable**: Bypass is in production-reachable code, `exploitability: reachable`, `confidence: high` or `medium`
> - **Likely Vulnerable**: Bypass is production-reachable but limited scope (internal network only) or env-guarded with ambiguous production value; `exploitability: conditional`
> - **Not Vulnerable**: Bypass is demonstrably test-only or dead code; `exploitability: unreachable`
> - **Needs Manual Review**: Cannot determine if the code path is production-reachable (opaque dependency injection, complex factory pattern, dynamic module loading)
>
> **Output format** — write to `sast/tls-batch-[N].md`:
>
> ```markdown
> # TLS Batch [N] Results
>
> ## Findings
>
> ### [VULNERABLE] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Function / class / endpoint**: [name]
> - **Bypass pattern**: [`verify=False` / `InsecureSkipVerify: true` / etc.]
> - **Issue**: [e.g., "Production requests to payments API transmitted with certificate verification disabled"]
> - **Data at risk**: [What sensitive data flows over this connection — credentials, tokens, PII, etc.]
> - **Severity**: high | critical (raise to critical if credentials/tokens/PII flow over the unverified connection)
> - **exploitability**: reachable | conditional
> - **confidence**: high | medium | low
> - **chain_id**: "mitm-credential" | null
> - **Impact**: [What an attacker in MITM position can do — intercept auth tokens, inject malicious responses, steal PII]
> - **Remediation**: [Remove the `verify=False` flag. If a custom CA is required, pass a CA bundle path: `verify='/etc/ssl/certs/company-ca.crt'`. Never disable verification to work around expired or self-signed certificates in production.]
> - **Dynamic Test**:
>   ```
>   # Set up a MITM proxy (e.g., mitmproxy) on the network path and observe whether
>   # the client connects and sends data without certificate errors.
>   # With mitmproxy running on port 8080:
>   # HTTP_PROXY=http://localhost:8080 HTTPS_PROXY=http://localhost:8080 <app command>
>   # A vulnerable client will connect; a secure client will raise a certificate error.
>   ```
>
> ### [LIKELY VULNERABLE] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Function / class / endpoint**: [name]
> - **Bypass pattern**: [pattern]
> - **Issue**: [e.g., "Bypass limited to internal network but env guard value unknown in production"]
> - **Severity**: high
> - **exploitability**: conditional
> - **confidence**: medium
> - **chain_id**: null
> - **Concern**: [Why it remains a risk — what would need to be true for it to be exploitable]
> - **Remediation**: [Remove the bypass; if an internal CA is needed, distribute the CA bundle]
>
> ### [NOT VULNERABLE] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Function / class / endpoint**: [name]
> - **Reason**: [e.g., "File is in tests/ directory and function is never called from production code" or "bypass is inside `if Rails.env.test?` block"]
>
> ### [NEEDS MANUAL REVIEW] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Function / class / endpoint**: [name]
> - **Uncertainty**: [Why production reachability could not be determined]
> - **Suggestion**: [What a human reviewer should check — e.g., "Trace all callers of `build_http_client()` to confirm whether the `insecure=True` parameter is ever passed from production config"]
> ```

### Phase 3: Merge — Consolidate Batch Results

After **all** Phase 2 batch subagents complete, read every `sast/tls-batch-*.md` file and merge them into both `sast/tls-results.md` (human-readable) and `sast/tls-results.json` (machine-readable). You (the orchestrator) do this directly — no subagent needed.

**Merge procedure**:

1. Read all `sast/tls-batch-1.md`, `sast/tls-batch-2.md`, ... files.
2. Collect all findings from each batch file and combine them into one list, preserving classification and all detail fields.
3. Count totals across all batches for the executive summary.
4. Assign a sequential numeric ID to each finding for the JSON output: `tls-1`, `tls-2`, etc. (ordered: Vulnerable first, then Likely Vulnerable, then Needs Manual Review, then Not Vulnerable).
5. Write the merged markdown report to `sast/tls-results.md`:

```markdown
# TLS Verification Analysis Results: [Project Name]

## Executive Summary
- Sites analyzed: [total bypass sites from recon]
- Vulnerable: [N]
- Likely Vulnerable: [N]
- Not Vulnerable: [N]
- Needs Manual Review: [N]

## Findings

[All findings from all batches, grouped by classification:
 VULNERABLE first, then LIKELY VULNERABLE, then NEEDS MANUAL REVIEW, then NOT VULNERABLE.
 Preserve every field from the batch results exactly as written.]
```

6. Write the machine-readable JSON to `sast/tls-results.json` using the canonical schema. For each Vulnerable, Likely Vulnerable, and Needs Manual Review finding, emit one JSON object. Not Vulnerable findings are omitted from the JSON output (they represent true negatives, not findings):

```json
{
  "findings": [
    {
      "id": "tls-1",
      "skill": "sast-tls",
      "severity": "high",
      "title": "TLS certificate verification disabled in payment API client",
      "description": "The payment service HTTP client passes verify=False to requests.get(), disabling certificate and hostname verification for all outbound calls to https://payments.example.com. An attacker in a MITM position can present any certificate and intercept or modify payment data.",
      "location": { "file": "app/clients/payment_client.py", "line": 42, "column": 37 },
      "remediation": "Remove verify=False. If a custom CA is required for the payments endpoint, pass a CA bundle path: verify='/etc/ssl/certs/company-ca.crt'. Never disable verification to work around expired or self-signed certificates in production.",
      "exploitability": "reachable",
      "confidence": "high",
      "chain_id": "mitm-credential"
    }
  ]
}
```

Field mapping from batch results to JSON:
- `id`: `tls-<N>` sequential
- `skill`: always `"sast-tls"`
- `severity`: from the batch finding's **Severity** field (`"critical"` if credentials/PII flow over the unverified connection, otherwise `"high"` for Vulnerable, `"high"` for Likely Vulnerable, `"medium"` for Needs Manual Review)
- `title`: short one-line description synthesized from the finding name
- `description`: combine **Issue** + **Data at risk** + **Impact** fields from the batch result
- `location.file`: from **File** field, path only (no line range syntax — use the start line for `line`)
- `location.line`: the line number of the bypass flag itself
- `location.column`: column if visible from the code snippet; `null` if not determined
- `remediation`: from the **Remediation** field
- `exploitability`: from the **exploitability** field in the batch result
- `confidence`: from the **confidence** field in the batch result
- `chain_id`: from the **chain_id** field in the batch result (`null` if not set)

If no real findings exist (all sites were Not Vulnerable), write `"findings": []` to the JSON file.

7. After writing both output files, **delete all intermediate batch files** (`sast/tls-batch-*.md`) and the recon file (`sast/tls-recon.md`).

---

## Severity Reference (CWE-295)

| Condition | Default Severity |
|---|---|
| Bypass is production-reachable; no sensitive data confirmed in payload | **high** |
| Bypass is production-reachable; credentials, tokens, or PII flow over the connection | **critical** |
| Bypass is limited to an internal segment with no internet path; or env-guarded with ambiguous production value | **high** (Likely Vulnerable) |
| Bypass is internal segment; payload confirmed non-sensitive | **medium** |
| Bypass is test-only | **info** (Not Vulnerable — omit from JSON) |

CWE reference: **CWE-295** (Improper Certificate Validation), also related to **CWE-297** (Improper Validation of Certificate with Host Mismatch) for hostname-only bypasses.

OWASP mapping: **A02:2021 — Cryptographic Failures**, **A04:2021 — Insecure Design**.

---

## Remediation Reference

Include the relevant remediation in every finding's `remediation` field:

**Python (requests)**
```python
# Before (vulnerable):
requests.get(url, verify=False)

# After (secure):
requests.get(url)  # verify=True is the default
# Or, with internal CA:
requests.get(url, verify='/etc/ssl/certs/company-ca.crt')
```

**Python (httpx)**
```python
# Before:
httpx.AsyncClient(verify=False)

# After:
httpx.AsyncClient()  # default is secure
# Or with internal CA:
httpx.AsyncClient(verify='/etc/ssl/certs/company-ca.crt')
```

**Go**
```go
// Before:
&tls.Config{InsecureSkipVerify: true}

// After:
&tls.Config{}  // uses system CA pool by default
// Or with internal CA:
caCert, _ := os.ReadFile("/etc/ssl/certs/ca-certificates.crt")
pool := x509.NewCertPool()
pool.AppendCertsFromPEM(caCert)
&tls.Config{RootCAs: pool}
```

**Node.js**
```javascript
// Before:
new https.Agent({ rejectUnauthorized: false })

// After:
new https.Agent()  // rejectUnauthorized defaults to true
// Or with CA:
new https.Agent({ ca: fs.readFileSync('/etc/ssl/certs/ca-certificates.crt') })
```

**Java**
```java
// Before (trust-all TrustManager):
// Replace the entire SSLContext with the default:
SSLContext ctx = SSLContext.getDefault();
// Or use OkHttp defaults:
OkHttpClient client = new OkHttpClient();
```

**PHP**
```php
// Before:
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);

// After:
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);
// Or Guzzle:
$client = new \GuzzleHttp\Client(['verify' => '/etc/ssl/certs/ca-certificates.crt']);
```

**.NET**
```csharp
// Before:
handler.ServerCertificateCustomValidationCallback = (msg, cert, chain, err) => true;

// After:
// Remove the callback entirely — default validation uses OS cert store
// Or validate explicitly:
handler.ServerCertificateCustomValidationCallback = (msg, cert, chain, err) =>
    err == SslPolicyErrors.None;
```

**Ruby**
```ruby
# Before:
http.verify_mode = OpenSSL::SSL::VERIFY_NONE

# After:
http.verify_mode = OpenSSL::SSL::VERIFY_PEER  # or omit — VERIFY_PEER is default with use_ssl=true
```

**General guidance**:
- Never disable TLS verification to work around an expired or self-signed certificate — fix the certificate instead
- If an internal PKI is required, distribute the CA bundle to all application containers via secrets management (Vault, Kubernetes secrets, AWS Secrets Manager) and pass the bundle path to the client
- For high-value connections (payment processors, identity providers), consider adding certificate pinning on top of standard verification
- Scan environment variables and configuration files in addition to source code — a single `NODE_TLS_REJECT_UNAUTHORIZED=0` in a `.env` file can silently bypass TLS for an entire Node.js process

---

## Chains with Other Skills

TLS verification bypass compounds with other findings. When a TLS bypass site is co-located with one of the following patterns, set `chain_id: "mitm-credential"`:

- **sast-hardcodedsecrets**: Hardcoded credentials are transmitted over an unverified TLS connection → attacker intercepts both the credential and the session at once
- **sast-missingauth**: An unauthenticated endpoint that also transmits data over unverified TLS doubles the exposure surface
- **sast-ssrf**: If the SSRF target is reached via an HTTP client with `verify=False`, the SSRF can be used to exfiltrate data through the MITM-susceptible channel

Chain composition example:
```
sast-hardcodedsecrets finding: API_KEY hardcoded in config.py
sast-tls finding: requests.get(url, verify=False) in the same file
→ chain_id: "mitm-credential" on both findings
→ combined narrative: hardcoded API key transmitted over MITM-susceptible TLS connection
```

---

## Test Fixture (True Positive / True Negative Reference)

The following minimal examples define what the skill MUST flag (TP) and MUST NOT flag (TN):

**TP — Must flag, exploitability: reachable, severity: high**
```python
# app/services/notification_service.py
import requests

def send_notification(user_id: str, message: str) -> bool:
    resp = requests.post(
        "https://notifications.internal.example.com/send",
        json={"user_id": user_id, "message": message},
        verify=False,  # ← TP: production code, verify=False, no env guard
    )
    return resp.status_code == 200
```

**TP — Must flag, exploitability: reachable, severity: critical (credentials transmitted)**
```python
# app/clients/stripe_client.py
import requests

STRIPE_API_KEY = "sk_live_abc123..."

def charge_card(amount: int, token: str) -> dict:
    resp = requests.post(
        "https://api.stripe.com/v1/charges",
        headers={"Authorization": f"Bearer {STRIPE_API_KEY}"},
        data={"amount": amount, "source": token},
        verify=False,  # ← TP: production code, credentials in headers, severity critical
    )
    return resp.json()
```

**TN — Must NOT flag (test-only scope)**
```python
# tests/test_api_client.py
import requests
import pytest

@pytest.fixture
def insecure_client():
    session = requests.Session()
    session.verify = False  # ← TN: test file, test fixture only
    return session
```

**TN — Must NOT flag (custom CA bundle, verification enabled)**
```python
# app/clients/internal_api.py
import requests

def get_internal_data(path: str) -> dict:
    resp = requests.get(
        f"https://internal.example.com{path}",
        verify="/etc/ssl/certs/company-ca.crt",  # ← TN: CA bundle path, not False
    )
    return resp.json()
```

**TN — Must NOT flag (Go with proper CA pool)**
```go
// internal/client/secure_client.go
func NewSecureClient(caPath string) *http.Client {
    caCert, _ := os.ReadFile(caPath)
    pool := x509.NewCertPool()
    pool.AppendCertsFromPEM(caCert)
    return &http.Client{
        Transport: &http.Transport{
            TLSClientConfig: &tls.Config{RootCAs: pool},  // ← TN: custom CA, not skip
        },
    }
}
```

Assert: only the TPs are flagged in results; TNs must appear as NOT VULNERABLE or be absent from the JSON findings array.

---

## Important Reminders

- Read `sast/architecture.md` and pass its content to all subagents as context.
- Phase 2 must run AFTER Phase 1 completes — it depends on the recon output.
- Phase 3 must run AFTER all Phase 2 batches complete — it depends on all batch outputs.
- Batch size is **3 sites per subagent**. If there are 1-3 sites total, use a single subagent. If there are 10, use 4 subagents (3+3+3+1).
- Launch all batch subagents **in parallel** — do not run them sequentially.
- Each batch subagent receives only its assigned sites' text from the recon file, not the entire recon file.
- **Phase 1 is purely structural**: flag any TLS verification bypass pattern, regardless of whether it is production-reachable. Do not assess reachability in Phase 1 — that is Phase 2's job.
- **Phase 2 is purely reachability analysis**: for each assigned site, determine whether it is in production code, test-only code, or guarded by an env flag. Set `exploitability` and `confidence` based on the evidence found.
- The most important FP source for this skill is **test-only bypasses**: many projects disable TLS in test fixtures to avoid certificate management. Always verify that a test-only bypass cannot be imported or called from production code before classifying it as Not Vulnerable.
- The second most common FP source is **custom CA bundles mistaken for bypasses**: `verify='/path/to/ca.crt'` is NOT a bypass. Only `verify=False` and similar disable flags are.
- `NODE_TLS_REJECT_UNAUTHORIZED=0` in any `.env`, Docker Compose, or CI file is a **process-level bypass** affecting all HTTPS in the process — this is often the most dangerous form because it is invisible in the application source code. Always scan configuration files.
- Raise severity to **critical** when the bypassed connection carries credentials, tokens, or PII. The default is **high**.
- The `chain_id: "mitm-credential"` field should be set on any finding where the unverified connection co-occurs with credential transmission (hardcoded or injected) — this signals to the report generator that the finding chains with `sast-hardcodedsecrets`.
- Clean up intermediate files: delete `sast/tls-recon.md` and all `sast/tls-batch-*.md` files after the final reports are written. The only outputs that should remain are `sast/tls-results.md` and `sast/tls-results.json`.
- If a skip flag appears in both source code AND an environment variable (e.g., `verify=os.getenv('TLS_VERIFY', 'false') == 'true'` inverted), check the production `.env` and CI config — the effective bypass may be the env var, not the source line.
- For `.NET`, distinguish between `ServicePointManager` (global, affects all HttpClient) and per-handler callbacks — global bypasses are higher severity because they affect the entire process.
