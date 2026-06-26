---
name: sast-ssrfimds
description: >-
  Detect Server-Side Request Forgery targeting cloud instance metadata endpoints
  (IMDSv1) using a three-phase approach: recon (find user-controlled URL fetch
  sinks, IMDSv1 usage, and cloud execution context indicators), batched verify
  (taint analysis tracing user input to the fetch sink while confirming cloud
  reachability, in parallel subagents of 3 candidates each), and merge
  (consolidate results into sast/ssrfimds-results.md and
  sast/ssrfimds-results.json). Covers Python, Node.js, Java, Go, PHP, Ruby,
  and .NET stacks. Requires sast/architecture.md (run sast-analysis first).
  Severity defaults to critical because successful exploitation leaks cloud
  credentials and enables full account takeover.
version: 0.1.0
---

# Cloud Metadata SSRF (IMDSv1) Detection

You are performing a focused security assessment to find Server-Side Request Forgery vulnerabilities where a user-controlled URL can reach the cloud instance metadata endpoint. This skill uses a three-phase approach with subagents: **recon** (find user-controlled URL fetch sinks, IMDSv1 usage patterns, and cloud execution context indicators), **batched verify** (taint + reachability analysis in parallel batches of 3), and **merge** (consolidate batch reports into one file plus a canonical JSON output).

**Prerequisites**: `sast/architecture.md` must exist. Run the analysis skill first if it doesn't.

---

## What is Cloud Metadata SSRF (IMDSv1)

Cloud Instance Metadata Service (IMDS) endpoints are link-local HTTP servers available to every running cloud instance, container, or serverless function:

| Provider | IPv4 endpoint | IPv6 / alt |
|---|---|---|
| AWS EC2, Lambda, ECS | `169.254.169.254` | `fd00:ec2::254` (ECS also `169.254.170.2`) |
| GCP Compute, Cloud Run | `metadata.google.internal` | `169.254.169.254` |
| Azure VM, AKS | `169.254.169.254` | — |
| Oracle Cloud | `169.254.169.254` | — |
| DigitalOcean Droplets | `169.254.169.254` | — |

IMDSv1 (the original AWS design) responds to any unauthenticated GET. An attacker who can make the application issue an HTTP GET to `http://169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>` receives temporary AWS credentials in the response — no authentication, no token, no interaction required beyond the GET. This is the mechanism that leaked Capital One's 2019 breach (100M+ records; $190M in fines).

The core pattern: *user-supplied URL → outbound HTTP GET → metadata endpoint responds with cloud credentials → credentials exfiltrated.*

### What this skill IS

- A user-supplied URL (query param, body field, header) flowing directly into an outbound HTTP call with no SSRF filter
- An outbound HTTP call that can reach `169.254.169.254`, `fd00:ec2::254`, `metadata.google.internal`, or `169.254.170.2` from the application's network position
- IMDSv1 usage: GET-based metadata requests without a prior PUT-token preflight (AWS IMDSv2 pattern) or without the `Metadata-Flavor: Google` header from a server-side caller (GCP)
- Missing URL allowlist: no deny-list blocking RFC-1918 (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) or link-local (`169.254.0.0/16`) addresses
- Partial IMDSv2 enforcement: hop limit set to 1 but `HttpTokens` not set to `required`, allowing direct instance access

### What this skill is NOT

Do not flag these as Cloud Metadata SSRF:

- **Generic SSRF to internal services**: Requests to internal databases, internal APIs, or RFC-1918 addresses that are not the IMDS endpoint — use `sast-ssrf` for those
- **CORS misconfiguration**: Reflected origins allowing cross-domain reads — use `sast-cors`
- **Open redirect**: User-controlled redirect targets that only affect browser navigation — use `sast-openredirect`
- **IMDSv2 fully enforced**: When `HttpTokens: required` is set AND the code performs the PUT-token preflight before every GET — not vulnerable
- **Egress firewall documented**: When infrastructure documentation or IaC (Terraform, CloudFormation) confirms that `169.254.0.0/16` is blocked at the network level — flag as low/info with the evidence
- **Non-cloud execution environment**: On-premises servers with no cloud metadata endpoint reachable — only flag when cloud deployment can be inferred

### Patterns That Prevent Cloud Metadata SSRF

**1. URL allowlist / SSRF guard library**
```python
# Python — ssrffilter
from ssrffilter import SSRFFilter
ssrf_filter = SSRFFilter()
ssrf_filter.get(user_url)  # raises if URL resolves to private/link-local IP

# Python — manual allowlist
import ipaddress, socket
ALLOWED_HOSTS = {'api.example.com', 'cdn.example.com'}
parsed = urllib.parse.urlparse(user_url)
if parsed.hostname not in ALLOWED_HOSTS:
    raise ValueError("URL not in allowlist")

# Python — block link-local + RFC-1918
def is_safe_url(url: str) -> bool:
    parsed = urllib.parse.urlparse(url)
    try:
        ip = ipaddress.ip_address(socket.gethostbyname(parsed.hostname))
    except Exception:
        return False
    return not (ip.is_private or ip.is_link_local or ip.is_loopback)
```

**2. IMDSv2 enforced (AWS)**
```bash
# Terraform: require token on every EC2 instance
resource "aws_instance" "app" {
  metadata_options {
    http_tokens                 = "required"   # IMDSv2
    http_put_response_hop_limit = 1
    http_endpoint               = "enabled"
  }
}

# AWS CLI: enforce on existing instance
aws ec2 modify-instance-metadata-options \
  --instance-id i-1234567890abcdef0 \
  --http-tokens required \
  --http-endpoint enabled
```

**3. IMDSv2 code pattern (pre-flight PUT)**
```python
# Python — correct IMDSv2 fetch
import requests

def get_imds_token(ttl_seconds: int = 21600) -> str:
    resp = requests.put(
        "http://169.254.169.254/latest/api/token",
        headers={"X-aws-ec2-metadata-token-ttl-seconds": str(ttl_seconds)},
        timeout=1,
    )
    resp.raise_for_status()
    return resp.text

def get_instance_metadata(path: str) -> str:
    token = get_imds_token()
    resp = requests.get(
        f"http://169.254.169.254/latest/meta-data/{path}",
        headers={"X-aws-ec2-metadata-token": token},
        timeout=1,
    )
    resp.raise_for_status()
    return resp.text
```

**4. GCP Metadata-Flavor enforcement**
```python
# SAFE — server-side only, Metadata-Flavor header present
# (but this call itself is internal infra, not user-controlled)
resp = requests.get(
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
    headers={"Metadata-Flavor": "Google"},
)
# The SSRF risk is when user_url → requests.get(user_url) and user sets
# url=http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
```

**5. Network-level block (IaC)**
```hcl
# AWS Security Group — deny egress to 169.254.0.0/16 from application
resource "aws_security_group_rule" "deny_imds" {
  type        = "egress"
  from_port   = 80
  to_port     = 80
  protocol    = "tcp"
  cidr_blocks = ["169.254.0.0/16"]
  security_group_id = aws_security_group.app.id
  # combined with allow-list default deny ensures IMDS is blocked
}
```

---

## Vulnerable vs. Secure Examples

### Python — Flask / requests (most common pattern)

```python
# VULNERABLE: direct user URL fetch, no validation, cloud context present (Lambda/EC2)
import requests
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/fetch')
def fetch_url():
    url = request.args.get('url')           # taint source: HTTP query param
    resp = requests.get(url, timeout=10)    # sink: unvalidated outbound GET
    return jsonify({"content": resp.text})

# Attack:
# GET /fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/my-role
# Response: {"content": "{\"AccessKeyId\":\"ASIA...\",\"SecretAccessKey\":\"...\"}"}

# SECURE: validate against allowlist before fetching
import ipaddress, socket, urllib.parse

ALLOWED_SCHEMES = {"https"}
ALLOWED_HOSTS = {"api.partner.com", "cdn.example.com"}

def validate_url(url: str) -> None:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ALLOWED_SCHEMES:
        raise ValueError(f"Scheme not allowed: {parsed.scheme}")
    if parsed.hostname not in ALLOWED_HOSTS:
        raise ValueError(f"Host not in allowlist: {parsed.hostname}")

@app.route('/fetch')
def fetch_url_safe():
    url = request.args.get('url')
    validate_url(url)                        # raises on link-local, RFC-1918, unlisted host
    resp = requests.get(url, timeout=10)
    return jsonify({"content": resp.text})
```

### Python — httpx (async, FastAPI)

```python
# VULNERABLE: httpx.get with user-controlled URL in async endpoint
import httpx
from fastapi import FastAPI, Request

app = FastAPI()

@app.get("/proxy")
async def proxy(request: Request):
    target_url = request.query_params.get("target")   # taint source
    async with httpx.AsyncClient() as client:
        resp = await client.get(target_url)            # sink
    return resp.json()

# SECURE: use ssrffilter or manual IP block
from ssrffilter import SSRFFilter
_ssrf = SSRFFilter()

@app.get("/proxy")
async def proxy_safe(request: Request):
    target_url = request.query_params.get("target")
    _ssrf.get(target_url)   # raises ssrffilter.SSRFException on private/link-local
    async with httpx.AsyncClient() as client:
        resp = await client.get(target_url)
    return resp.json()
```

### Python — urllib / urllib3

```python
# VULNERABLE: urllib.request with user URL, deployed in ECS (ECS_CONTAINER_METADATA_URI set)
import urllib.request
from flask import Flask, request

app = Flask(__name__)

@app.route('/check')
def check_url():
    url = request.form.get('url')                   # taint source: POST body
    with urllib.request.urlopen(url) as resp:       # sink
        return resp.read().decode()

# Attack: POST /check url=http://169.254.170.2/v2/credentials/ecs-task-role-id
```

### Node.js — Express / node-fetch / axios

```javascript
// VULNERABLE: axios with req.body.url, no SSRF protection
const express = require('express');
const axios = require('axios');
const app = express();
app.use(express.json());

app.post('/webhook-test', async (req, res) => {
  const { url } = req.body;                     // taint source: POST body
  const response = await axios.get(url);        // sink
  res.json({ status: response.status, data: response.data });
});

// SECURE: validate URL scheme and block private/link-local ranges
const { URL } = require('url');
const dns = require('dns').promises;
const ipaddr = require('ipaddr.js');

async function assertSafeUrl(rawUrl) {
  const parsed = new URL(rawUrl);
  if (!['http:', 'https:'].includes(parsed.protocol)) {
    throw new Error('Scheme not allowed');
  }
  const addresses = await dns.resolve4(parsed.hostname).catch(() => []);
  for (const addr of addresses) {
    const ip = ipaddr.parse(addr);
    if (ip.range() !== 'unicast') {              // blocks link-local, private, loopback
      throw new Error(`Host resolves to non-unicast IP: ${addr}`);
    }
  }
}

app.post('/webhook-test', async (req, res) => {
  const { url } = req.body;
  await assertSafeUrl(url);                      // throws before fetch
  const response = await axios.get(url);
  res.json({ status: response.status, data: response.data });
});
```

```javascript
// VULNERABLE: native fetch (Node 18+) with req.query.url
app.get('/preview', async (req, res) => {
  const url = req.query.url;                    // taint source: query param
  const resp = await fetch(url);                // sink
  const text = await resp.text();
  res.send(text);
});
```

### Java — Spring Boot / RestTemplate

```java
// VULNERABLE: RestTemplate.getForObject with user-supplied URL
@RestController
public class ProxyController {

    private final RestTemplate restTemplate = new RestTemplate();

    @GetMapping("/fetch")
    public ResponseEntity<String> fetchUrl(@RequestParam("url") String url) {
        // taint source: @RequestParam — direct HTTP query parameter
        // sink: RestTemplate.getForObject — outbound GET with no URL validation
        String body = restTemplate.getForObject(url, String.class);
        return ResponseEntity.ok(body);
    }
}

// SECURE: allowlist + block private ranges before request
import java.net.*;

@Service
public class SafeHttpService {

    private static final Set<String> ALLOWED_HOSTS = Set.of("api.partner.com", "cdn.example.com");

    public String safeGet(String rawUrl) throws Exception {
        URI uri = new URI(rawUrl);
        String host = uri.getHost();

        if (!ALLOWED_HOSTS.contains(host)) {
            throw new SecurityException("Host not in allowlist: " + host);
        }
        InetAddress addr = InetAddress.getByName(host);
        if (addr.isLinkLocalAddress() || addr.isSiteLocalAddress() || addr.isLoopbackAddress()) {
            throw new SecurityException("Resolved to private/link-local address");
        }

        RestTemplate restTemplate = new RestTemplate();
        return restTemplate.getForObject(rawUrl, String.class);
    }
}
```

```java
// VULNERABLE: WebClient (reactive) with user URL, deployed on GKE (GOOGLE_CLOUD_PROJECT set)
@GetMapping("/proxy")
public Mono<String> proxy(@RequestParam String url) {
    // taint: @RequestParam  sink: WebClient.get().uri(url)
    return WebClient.create().get().uri(url).retrieve().bodyToMono(String.class);
}
```

### Go — net/http

```go
// VULNERABLE: http.Get with user-supplied URL, running on EC2 (AWS_DEFAULT_REGION set)
func fetchHandler(w http.ResponseWriter, r *http.Request) {
    url := r.URL.Query().Get("url")       // taint source: query param
    resp, err := http.Get(url)            // sink
    if err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }
    defer resp.Body.Close()
    io.Copy(w, resp.Body)
}

// SECURE: resolve hostname and check IP ranges before fetch
func isSafeURL(rawURL string) error {
    parsed, err := url.Parse(rawURL)
    if err != nil {
        return err
    }
    addrs, err := net.LookupHost(parsed.Hostname())
    if err != nil {
        return err
    }
    for _, addr := range addrs {
        ip := net.ParseIP(addr)
        if ip == nil {
            return fmt.Errorf("could not parse IP: %s", addr)
        }
        if ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLoopback() {
            return fmt.Errorf("URL resolves to restricted address: %s", addr)
        }
    }
    return nil
}

func fetchHandlerSafe(w http.ResponseWriter, r *http.Request) {
    rawURL := r.URL.Query().Get("url")
    if err := isSafeURL(rawURL); err != nil {
        http.Error(w, "URL not allowed", http.StatusForbidden)
        return
    }
    resp, err := http.Get(rawURL)
    // ...
}
```

### PHP — curl

```php
<?php
// VULNERABLE: curl_exec with CURLOPT_URL set to user input, running on AWS Lambda via Bref
function fetchURL(string $userUrl): string {
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $userUrl);         // sink: user-controlled URL
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    $result = curl_exec($ch);
    curl_close($ch);
    return $result;
}

$url = $_GET['url'];                                 // taint source: GET param
echo fetchURL($url);

// SECURE: validate scheme and block private/link-local
function isSafeUrl(string $url): bool {
    $parsed = parse_url($url);
    if (!in_array($parsed['scheme'] ?? '', ['http', 'https'])) {
        return false;
    }
    $ip = gethostbyname($parsed['host']);
    $long = ip2long($ip);
    // Block 169.254.0.0/16 (link-local), 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
    $blocked = [
        ['start' => ip2long('169.254.0.0'), 'end' => ip2long('169.254.255.255')],
        ['start' => ip2long('10.0.0.0'),    'end' => ip2long('10.255.255.255')],
        ['start' => ip2long('172.16.0.0'),  'end' => ip2long('172.31.255.255')],
        ['start' => ip2long('192.168.0.0'), 'end' => ip2long('192.168.255.255')],
    ];
    foreach ($blocked as $range) {
        if ($long >= $range['start'] && $long <= $range['end']) {
            return false;
        }
    }
    return true;
}
```

### Ruby on Rails

```ruby
# VULNERABLE: Net::HTTP with user URL, running on Heroku (GOOGLE_CLOUD_PROJECT or AWS creds set)
class FetchController < ApplicationController
  def show
    url = params[:url]                         # taint source: route/query param
    uri = URI.parse(url)
    response = Net::HTTP.get_response(uri)     # sink
    render plain: response.body
  end
end

# SECURE: use ssrf_filter gem
# gem 'ssrf_filter'
require 'ssrf_filter'

class FetchController < ApplicationController
  def show
    url = params[:url]
    result = SsrfFilter.get(url)               # raises SsrfFilter::PrivateIPAddress on IMDS range
    render plain: result.body
  end
end
```

### C# — HttpClient / .NET

```csharp
// VULNERABLE: HttpClient.GetAsync with user-supplied URL, deployed on Azure AKS
[ApiController, Route("api/[controller]")]
public class ProxyController : ControllerBase
{
    private readonly HttpClient _http;
    public ProxyController(IHttpClientFactory factory) => _http = factory.CreateClient();

    [HttpGet]
    public async Task<IActionResult> Get([FromQuery] string url)
    {
        // taint source: [FromQuery] url — HTTP query parameter
        // sink: HttpClient.GetAsync — outbound GET with no URL validation
        var resp = await _http.GetAsync(url);
        var content = await resp.Content.ReadAsStringAsync();
        return Ok(content);
    }
}

// SECURE: validate URL before request
private static readonly HashSet<string> AllowedHosts =
    new() { "api.partner.com", "cdn.example.com" };

private static void AssertSafeUrl(string rawUrl)
{
    var uri = new Uri(rawUrl);
    if (!AllowedHosts.Contains(uri.Host))
        throw new InvalidOperationException($"Host not in allowlist: {uri.Host}");
    var addresses = Dns.GetHostAddresses(uri.Host);
    foreach (var addr in addresses)
    {
        if (addr.IsIPv6LinkLocal || IsPrivateIPv4(addr))
            throw new InvalidOperationException("Host resolves to restricted address");
    }
}
```

---

## Execution

This skill runs in three phases using subagents. Pass the contents of `sast/architecture.md` to all subagents as context.

### Phase 1: Recon — Find Candidates

Launch a subagent with the following instructions:

> **Goal**: Find every location in the codebase where three signals overlap (or can plausibly overlap at runtime): (1) a user-controlled URL reaches an outbound HTTP fetch call, (2) IMDSv1-style metadata access is present or the metadata endpoint is reachable, and (3) cloud execution context is indicated. Write all candidates to `sast/ssrfimds-recon.md`. You are **not yet tracing taint** — that is Phase 2's job. Flag any location where the pattern exists regardless of whether user input can demonstrably reach it.
>
> **Context**: You will be given the project's architecture summary. Use it to understand the tech stack, outbound HTTP libraries, deployment environment, and cloud provider.
>
> ---
>
> **Signal A — User-controlled URL fetch sinks**
>
> Search for outbound HTTP calls where the URL argument contains a variable (not a string literal). Flag ANY variable — Phase 2 will determine if it is user-controlled.
>
> Python:
> - `requests.get(`, `requests.post(`, `requests.request(` — flag when the first argument is a variable
> - `httpx.get(`, `httpx.post(`, `httpx.request(`, `client.get(`, `client.post(` — flag when URL arg is a variable
> - `urllib.request.urlopen(`, `urllib.request.Request(` — flag when argument is a variable
> - `urllib3.PoolManager().request(`, `http.client.HTTPConnection(` — flag when host/URL is a variable
> - `aiohttp.ClientSession().get(`, `.post(`, `.request(` — flag when URL is a variable
>
> Node.js / TypeScript:
> - `fetch(` — flag when first arg is a variable
> - `axios.get(`, `axios.post(`, `axios.request(`, `axios(` — flag when URL arg is a variable
> - `http.get(`, `https.get(`, `http.request(`, `https.request(` — flag when URL/options.host is variable
> - `got(`, `got.get(`, `got.post(` — flag when URL is a variable
> - `needle(`, `superagent.get(` — flag when URL is a variable
> - `node-fetch`: `fetch(url)` where `url` is a variable
>
> Java:
> - `restTemplate.getForObject(url,`, `restTemplate.exchange(url,` — flag when first arg is a variable
> - `WebClient.create().get().uri(url)` — flag when URI is a variable
> - `new URL(userUrl).openConnection()`, `HttpURLConnection` — flag when URL is variable
> - `HttpClient.newHttpClient().send(HttpRequest.newBuilder().uri(URI.create(url))` — flag when url is variable
> - `OkHttpClient().newCall(Request.Builder().url(url)` — flag when url is variable
>
> Go:
> - `http.Get(url)`, `http.Post(url,` — flag when url is a variable
> - `http.NewRequest("GET", url,` — flag when url is a variable
> - `client.Do(req)` where `req` was built with a variable URL
>
> PHP:
> - `curl_setopt($ch, CURLOPT_URL, $var)` — flag when third arg is a variable
> - `file_get_contents($url)` — flag when arg is a variable
> - Guzzle: `$client->get($url)`, `$client->request('GET', $url)` — flag when URL is variable
>
> Ruby:
> - `Net::HTTP.get(URI($url))`, `Net::HTTP.get_response(URI.parse($url))` — flag when URL is variable
> - `URI.open($url)`, `open($url)` — flag when URL is variable
> - `RestClient.get($url)`, `Faraday.get($url)` — flag when URL is variable
> - `HTTParty.get($url)` — flag when URL is variable
>
> C#:
> - `HttpClient.GetAsync(url)`, `.PostAsync(url,`, `.SendAsync(request)` — flag when URL is a variable
> - `WebRequest.Create(url)` — flag when url is variable
> - RestSharp: `new RestRequest(url)` — flag when url is variable
>
> ---
>
> **Signal B — IMDSv1 usage and metadata endpoint references**
>
> Search for hardcoded metadata endpoint strings — these indicate the application itself calls IMDS directly (and may be using IMDSv1 without the PUT-token preflight):
>
> - `169.254.169.254` — any occurrence in source code or config
> - `fd00:ec2::254` — AWS IPv6 metadata
> - `metadata.google.internal` — GCP metadata
> - `169.254.170.2` — ECS container credentials endpoint
> - `instance-data` — Azure IMDS legacy alias
> - `/latest/meta-data/` — AWS IMDS path fragment
> - `/latest/api/token` — if present this is IMDSv2; note it but flag absence of token PUT before GET as IMDSv1
> - `X-aws-ec2-metadata-token` — IMDSv2 token header; if absent in metadata calls, flag as IMDSv1
> - `Metadata-Flavor: Google` — GCP requirement; absence from server-side metadata calls is a finding
>
> ---
>
> **Signal C — Cloud execution context indicators**
>
> Search for environment variable accesses that indicate the code runs in a cloud environment:
>
> - `AWS_DEFAULT_REGION`, `AWS_REGION` — EC2/Lambda environment variable
> - `AWS_EXECUTION_ENV` — Lambda runtime indicator
> - `AWS_LAMBDA_FUNCTION_NAME` — Lambda indicator
> - `ECS_CONTAINER_METADATA_URI`, `ECS_CONTAINER_METADATA_URI_V4` — ECS task
> - `GOOGLE_CLOUD_PROJECT`, `GCLOUD_PROJECT`, `GCP_PROJECT` — GCP project
> - `METADATA_FLAVOR` — GCP custom
> - `IDENTITY_ENDPOINT`, `IDENTITY_HEADER` — Azure MSI/IMDS
> - `MSI_ENDPOINT`, `MSI_SECRET` — Azure managed identity legacy
> - `WEBSITE_INSTANCE_ID` — Azure App Service
> - IaC files (Terraform, CloudFormation, CDK, Pulumi, Kubernetes manifests) that deploy to AWS/GCP/Azure/OCI
> - Docker / Kubernetes manifests referencing cloud-specific image registries (`ecr.amazonaws.com`, `gcr.io`, `azurecr.io`)
> - `boto3`, `google-cloud-*`, `azure-identity` in `requirements.txt`, `package.json`, `pom.xml`, `go.mod`, `Gemfile` — cloud SDK dependencies imply cloud deployment
>
> ---
>
> **Signal D — SSRF guard / allowlist absent**
>
> Look for the absence of protection around fetch sinks found in Signal A:
>
> - No `ssrffilter`, `ssrf_filter`, `ipaddr`, `netaddr`, `is-ip-private`, `private-ip` import near the fetch call
> - No explicit check for `169.254`, `link_local`, `private`, `is_private` near the URL before the fetch
> - No URL allowlist (hardcoded set of permitted hosts checked before the fetch)
> - Note: IMDSv2 token preflight (`PUT /latest/api/token`) is a mitigation — if present AND `HttpTokens: required` is set in IaC, mark as protected
>
> ---
>
> **Output format** — write to `sast/ssrfimds-recon.md`:
>
> ```markdown
> # SSRF/IMDS Recon: [Project Name]
>
> ## Summary
> Found [N] candidates for Cloud Metadata SSRF (IMDSv1).
> Cloud context: [detected / not detected — list indicators found]
> IMDSv1 usage: [yes / no / partial IMDSv2]
>
> ## Candidates
>
> ### 1. [Descriptive name — e.g., "Unvalidated user URL in /fetch endpoint"]
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Function / endpoint**: [function name or HTTP route]
> - **Fetch method**: [requests.get / axios.get / http.Get / etc.]
> - **URL variable**: `var_name` — [brief note: assigned from request.args.get / req.body / etc. or unknown origin]
> - **SSRF guard present**: [yes / no / partial — describe what is present]
> - **IMDSv1 signal**: [direct hardcoded metadata URL / reachable via user URL / absent — describe]
> - **Cloud context signals**: [list env vars or dependencies found that indicate cloud deployment]
> - **Code snippet**:
>   ```
>   [the fetch call and the line(s) that assign the URL variable]
>   ```
>
> [Repeat for each candidate]
>
> ## IMDSv1 Direct Usage
>
> [List any locations where the code itself calls the metadata endpoint, with file/line and whether IMDSv2 token preflight is present]
>
> ## Cloud Context Evidence
>
> [List all cloud context signals found: env var references, cloud SDK imports, IaC files, image registry names]
> ```

### After Phase 1: Check for Candidates Before Proceeding

After Phase 1 completes, read `sast/ssrfimds-recon.md`. If the recon found **zero candidates** (the "Candidates" section is empty or the summary reports "Found 0"), **skip Phase 2 entirely**. Write the following files and stop:

`sast/ssrfimds-results.md`:
```markdown
# Cloud Metadata SSRF (IMDSv1) Analysis Results

No vulnerabilities found.
```

`sast/ssrfimds-results.json`:
```json
{ "findings": [] }
```

Only proceed to Phase 2 if Phase 1 found at least one candidate.

### Phase 2: Verify — Taint + Reachability Analysis (Batched)

After Phase 1 completes, read `sast/ssrfimds-recon.md` and split the candidates into **batches of up to 3 candidates each**. Launch **one subagent per batch in parallel**. Each subagent does taint analysis for its assigned candidates and writes results to its own batch file.

**Batching procedure** (you, the orchestrator, do this — not a subagent):

1. Read `sast/ssrfimds-recon.md` and count the numbered candidate sections under "Candidates" (### 1., ### 2., etc.).
2. Divide them into batches of up to 3. For example, 7 candidates → 3 batches (1-3, 4-6, 7).
3. For each batch, extract the full text of those candidate sections from the recon file.
4. Also extract the "IMDSv1 Direct Usage" and "Cloud Context Evidence" sections — pass these to all batch subagents as shared context.
5. Launch all batch subagents **in parallel**, passing each one only its assigned candidates plus the shared context sections.
6. Each subagent writes to `sast/ssrfimds-batch-N.md` where N is the 1-based batch number.
7. Identify the project's primary language/framework from `sast/architecture.md` and select **only the matching examples** from the "Vulnerable vs. Secure Examples" section above. Include these in each subagent's instructions where indicated by `[TECH-STACK EXAMPLES]`.

Give each batch subagent the following instructions (substitute batch-specific values):

> **Goal**: For each assigned candidate, determine (a) whether a user-supplied value can reach the outbound HTTP fetch URL argument, and (b) whether the cloud metadata endpoint (`169.254.169.254` et al.) is reachable from the application's execution environment. If both are true and no effective SSRF guard is present, this is a confirmed vulnerability. Write results to `sast/ssrfimds-batch-[N].md`.
>
> **Your assigned candidates** (from the recon phase):
>
> [Paste the full text of the assigned candidate sections here, preserving the original numbering]
>
> **Shared context from recon**:
>
> [Paste the "IMDSv1 Direct Usage" and "Cloud Context Evidence" sections here]
>
> **Context**: You will be given the project's architecture summary. Use it to understand request entry points, middleware, framework routing, and deployment environment.
>
> **Step 1: Taint analysis — trace the URL variable backward to its origin**
>
> For each candidate, trace the URL variable used in the fetch call back to its origin:
>
> 1. **Direct user input** — the URL variable is assigned directly from a request source:
>    - HTTP query params: `request.args.get('url')`, `req.query.url`, `params[:url]`, `$_GET['url']`, `c.Query("url")`, `@RequestParam String url`, `r.URL.Query().Get("url")`
>    - Request body / form: `request.json.get('url')`, `req.body.url`, `request.POST.get('url')`, `$_POST['url']`
>    - Path parameters: `request.view_args['url']`, `req.params.url`, `params[:url]`
>    - HTTP headers: `request.headers.get('X-Target-URL')`, `req.headers['url']`
>    - Cookies: `request.cookies.get('url')`, `req.cookies.url`
>
> 2. **Indirect / derived user input** — the URL is built from user input through intermediate assignments, function calls, or class attributes. Trace the full chain:
>    - Variable read from a database row that was originally stored from user input
>    - URL built by concatenating a user-supplied host/path with a hardcoded scheme
>    - URL passed through a helper function — check that function's callers
>    - Conditionally assigned from multiple sources — check all branches
>
> 3. **Server-side / hardcoded origin** — the URL comes from config, environment variables, a hardcoded constant, or server-side logic with no user input. Mark as NOT VULNERABLE for the taint prong.
>
> **Step 2: Reachability analysis — is the cloud metadata endpoint reachable?**
>
> Determine if the application's execution environment can reach `169.254.169.254` (or cloud-provider equivalents). Use the cloud context evidence from the recon phase:
>
> - **High confidence reachable**: AWS env vars (`AWS_DEFAULT_REGION`, `AWS_EXECUTION_ENV`, `AWS_LAMBDA_FUNCTION_NAME`, `ECS_CONTAINER_METADATA_URI`) present in the codebase; OR IaC (Terraform/CloudFormation) deploys EC2/Lambda/ECS; OR cloud SDK (`boto3`, `google-cloud-*`, `azure-identity`) is a dependency.
> - **Medium confidence reachable**: Docker/Kubernetes deployment files found but no explicit cloud provider identified; application reads IAM roles or cloud credentials at runtime; OR `METADATA_FLAVOR`, `GOOGLE_CLOUD_PROJECT`, `IDENTITY_ENDPOINT` env vars referenced.
> - **Low confidence / unknown**: No cloud signals found; on-premises deployment apparent; or metadata endpoint explicitly blocked in IaC egress rules.
> - **Not reachable**: IaC documents an egress security group or firewall rule that blocks `169.254.0.0/16` from the application subnet, AND the rule is actually applied to the instance/container running this code.
>
> **Step 3: SSRF guard check**
>
> Even if taint reaches the sink, check for mitigations between the taint source and the fetch call:
>
> - **Effective allowlist**: URL/hostname validated against a hardcoded set of permitted hosts (not just scheme validation alone)
> - **IP range block**: Code resolves the hostname to an IP and checks against RFC-1918 and link-local CIDRs (`169.254.0.0/16`) — must cover DNS rebinding (resolve at call time, not cached)
> - **SSRF guard library**: `ssrffilter` (Python), `ssrf_filter` (Ruby gem), `is-ip-private` / `private-ip` (npm), similar — verify it is actually called on the user URL before the fetch
> - **IMDSv2 enforcement**: If the code calls `http://169.254.169.254/latest/api/token` with a PUT before every metadata GET, this specific path is mitigated — but the generic user URL fetch sink is still vulnerable if user can supply arbitrary URLs
> - **Partial mitigation**: Scheme validation only (`http` vs `https`), regex on the URL string without IP resolution, or `HttpTokens` set but without `required` — classify as CONDITIONAL, not NOT VULNERABLE
>
> **FP killers — immediately downgrade or discard if**:
> - URL is validated against an allowlist that does not include `169.254.0.0/16` and is checked before the fetch
> - IaC confirms `HttpTokens: required` is set on all EC2 instances and the code performs the PUT-token preflight
> - Egress firewall rule in IaC/network documentation blocks `169.254.0.0/16` at the network level with evidence it is applied to this application's subnet
> - The fetch is always to a hardcoded URL (no variable) — the recon may have false-positived a variable that is actually a constant after tracing
> - Application is a CLI tool or test harness that is never deployed to a cloud environment (inferred from `sast/architecture.md`)
>
> **Severity and field assignment**:
>
> | Condition | severity | exploitability | confidence |
> |---|---|---|---|
> | Direct taint (`user_url → fetch`) + cloud context confirmed + no guard | `critical` | `reachable` | `high` |
> | Direct taint + cloud context inferred from dependencies (not env vars) | `critical` | `reachable` | `medium` |
> | Indirect taint (derived URL) + cloud context confirmed + no guard | `high` | `conditional` | `medium` |
> | Taint present + cloud context unknown + no guard | `high` | `conditional` | `medium` |
> | IMDSv2 partially enforced (hop-limit only, `HttpTokens` not `required`) | `high` | `conditional` | `medium` |
> | Taint present but allowlist covers most cases, one bypass path possible | `medium` | `conditional` | `low` |
> | Cloud creds endpoint reachable only via authenticated path | `medium` | `conditional` | `medium` |
> | Cannot determine taint origin | `high` | `unknown` | `low` |
>
> **chain_id assignment**:
> - `"ssrf-imds"` — user-controlled URL fetch sink that can reach the IMDS endpoint (chain with `sast-ssrf`)
> - `"imds-iac-confirm"` — cloud metadata SSRF where IaC confirms IMDSv2 is NOT enforced (`HttpTokens` absent or `optional`) — chain with `sast-iac`
> - `null` — if neither chain applies (isolated finding)
>
> **Vulnerable vs. Secure examples for this project's tech stack**:
>
> [TECH-STACK EXAMPLES]
>
> **Classification**:
> - **VULNERABLE**: User URL reaches fetch AND cloud metadata is reachable AND no effective guard
> - **LIKELY VULNERABLE**: Indirect taint OR cloud context not confirmed but inferred OR partial guard only
> - **NOT VULNERABLE**: Effective allowlist OR IMDSv2 fully enforced OR cloud metadata not reachable
> - **NEEDS MANUAL REVIEW**: Taint origin opaque, complex indirect flow, or guard library call site unclear
>
> **Output format** — write to `sast/ssrfimds-batch-[N].md`:
>
> ```markdown
> # SSRF/IMDS Batch [N] Results
>
> ## Findings
>
> ### [VULNERABLE] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint / function**: [HTTP route or function name]
> - **Taint trace**: [Step-by-step from request parameter to fetch call, e.g.: "request.args.get('url') (line 12) → url variable → requests.get(url) (line 15)"]
> - **Cloud context**: [Evidence that IMDS endpoint is reachable — env vars, IaC, SDK deps]
> - **SSRF guard**: [None / partial — describe what is absent]
> - **Issue**: [One-sentence summary]
> - **Impact**: [Attacker can fetch http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>, receiving temporary AWS credentials enabling full AWS account access]
> - **severity**: critical/high/medium/low
> - **exploitability**: reachable/conditional/unreachable/unknown
> - **confidence**: high/medium/low
> - **chain_id**: ssrf-imds / imds-iac-confirm / null
> - **Proof-of-concept request**:
>   ```
>   # Replace <HOST> and <PARAM> with actual values
>   curl -s "https://<HOST>/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"
>   # Expected: 200 response with IAM role name
>   curl -s "https://<HOST>/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/<ROLE>"
>   # Expected: JSON with AccessKeyId, SecretAccessKey, Token
>   ```
> - **Remediation**: [Specific fix for this file/line: use ssrffilter, add allowlist, or enforce IMDSv2]
>
> ### [LIKELY VULNERABLE] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint / function**: [route or function name]
> - **Taint trace**: [Best-effort trace; mark uncertain steps with "→ ? (unclear)"]
> - **Cloud context**: [Evidence or inference]
> - **Concern**: [Why it remains a risk despite uncertainty]
> - **severity**: high/medium
> - **exploitability**: conditional
> - **confidence**: medium/low
> - **chain_id**: ssrf-imds / null
> - **Remediation**: [Specific fix]
>
> ### [NOT VULNERABLE] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint / function**: [route or function name]
> - **Reason**: [e.g., "URL validated against ALLOWED_HOSTS allowlist that does not include 169.254.x.x before fetch" or "IMDSv2 enforced: PUT token preflight present and HttpTokens: required in Terraform"]
>
> ### [NEEDS MANUAL REVIEW] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint / function**: [route or function name]
> - **Uncertainty**: [Why taint origin or reachability could not be determined]
> - **Suggestion**: [What a human reviewer should check — e.g., "trace resolve_url() helper at lib/util.py:45 to determine if its caller passes user input"]
> ```

### Phase 3: Merge — Consolidate Batch Results

After **all** Phase 2 batch subagents complete, read every `sast/ssrfimds-batch-*.md` file and produce two output files. You (the orchestrator) do this directly — no subagent needed.

**Merge procedure**:

1. Read all `sast/ssrfimds-batch-1.md`, `sast/ssrfimds-batch-2.md`, ... files.
2. Collect all findings from each batch file. Combine them into one list, preserving all detail fields exactly.
3. Count totals across all batches for the executive summary.
4. Write the merged human-readable report to `sast/ssrfimds-results.md`:

```markdown
# Cloud Metadata SSRF (IMDSv1) Analysis Results: [Project Name]

## Executive Summary
- Candidates analyzed: [total across all batches]
- Vulnerable: [N]
- Likely Vulnerable: [N]
- Not Vulnerable: [N]
- Needs Manual Review: [N]
- Cloud context: [detected / not detected — summarize evidence]
- IMDSv1 usage: [yes / no / partial IMDSv2 — summarize]

## Risk

Successful exploitation of a VULNERABLE finding allows an attacker to:
1. Retrieve temporary cloud credentials (AccessKeyId, SecretAccessKey, SessionToken)
2. Use those credentials to call AWS/GCP/Azure APIs with the permissions of the instance role
3. Escalate to full cloud account takeover if the role has broad permissions (common in Lambda/ECS roles)
4. Exfiltrate environment variables, source code, database credentials, and customer data from cloud storage

## Findings

[All findings from all batches, grouped by classification:
 VULNERABLE first, then LIKELY VULNERABLE, then NEEDS MANUAL REVIEW, then NOT VULNERABLE.
 Preserve every field from the batch results exactly as written.]
```

5. Write the canonical machine-readable output to `sast/ssrfimds-results.json`. Use this exact schema:

```json
{
  "findings": [
    {
      "id": "ssrfimds-1",
      "skill": "sast-ssrfimds",
      "severity": "critical",
      "title": "User-controlled URL fetched without SSRF guard on AWS Lambda",
      "description": "The /fetch endpoint reads a URL from the 'url' query parameter (request.args.get('url')) and passes it directly to requests.get() with no URL validation. The application runs on AWS Lambda (AWS_EXECUTION_ENV detected), making the IMDS endpoint at 169.254.169.254 reachable. An attacker can supply http://169.254.169.254/latest/meta-data/iam/security-credentials/<role-name> to retrieve temporary AWS credentials.",
      "location": { "file": "app/views.py", "line": 15, "column": 11 },
      "remediation": "Validate the user-supplied URL against an allowlist of permitted hosts before calling requests.get(). Alternatively, use the ssrffilter library which automatically blocks requests to RFC-1918, link-local, and loopback addresses. Additionally, enforce IMDSv2 (HttpTokens: required) on all EC2 instances and ECS task definitions at the infrastructure level.",
      "exploitability": "reachable",
      "confidence": "high",
      "chain_id": "ssrf-imds"
    }
  ]
}
```

Emit one JSON object per confirmed VULNERABLE or LIKELY VULNERABLE finding. NOT VULNERABLE findings are omitted from the JSON. NEEDS MANUAL REVIEW findings with `confidence: medium` or higher may be included. Assign sequential IDs: `ssrfimds-1`, `ssrfimds-2`, etc.

If no VULNERABLE or LIKELY VULNERABLE findings exist, write `{ "findings": [] }`.

6. After writing both output files, **delete all intermediate files**: `sast/ssrfimds-recon.md` and all `sast/ssrfimds-batch-*.md`.

---

## chain_id Reference

| chain_id | Meaning | Chains with |
|---|---|---|
| `"ssrf-imds"` | User-controlled URL fetch sink that can reach the IMDS endpoint. This finding is the IMDS-specific instance of the broader SSRF class. | `sast-ssrf` — the generic SSRF skill provides the broader sink inventory; this skill narrows to IMDS reachability and cloud context |
| `"imds-iac-confirm"` | Cloud metadata SSRF where IaC analysis confirms IMDSv2 is NOT enforced (`HttpTokens` absent or `optional`) on the EC2 instance or ECS task definition, raising confidence from `medium` to `high` | `sast-iac` — look for `metadata_options { http_tokens = "optional" }` or missing `metadata_options` block in Terraform `aws_instance` or `aws_ecs_task_definition` resources |

---

## Important Reminders

- Read `sast/architecture.md` and pass its content to all subagents as context.
- Phase 2 must run AFTER Phase 1 completes — it depends on the recon output.
- Phase 3 must run AFTER all Phase 2 batches complete — it depends on all batch outputs.
- Batch size is **3 candidates per subagent**. Single batch for 1-3 candidates; 4 subagents for 10 candidates (3+3+3+1).
- Launch all batch subagents **in parallel** — do not run them sequentially.
- Each batch subagent receives only its assigned candidates' text from the recon file, plus the shared cloud context sections. Keep subagent context small and focused.
- **Phase 1 is purely structural**: flag any variable-URL fetch call alongside cloud context signals. Do not trace user input in Phase 1.
- **Phase 2 is taint + reachability**: trace the URL variable to its origin AND confirm cloud metadata is reachable. Only confirm VULNERABLE when both are true and no effective guard is present.
- The metadata endpoint at `169.254.169.254` is link-local and always reachable from within a cloud instance or container unless an egress firewall rule explicitly blocks it. Assume reachable unless IaC or network documentation contradicts this.
- IMDSv2 (`HttpTokens: required`) is only effective if BOTH the infrastructure enforces it (IaC setting) AND the application code performs the PUT-token preflight before every GET. A setting without code enforcement, or code without infrastructure enforcement, is a partial mitigation — classify as LIKELY VULNERABLE (`conditional`), not NOT VULNERABLE.
- DNS rebinding is a bypass: an attacker can register a domain that initially resolves to a public IP (passing an IP-based allowlist check) and then re-resolves to `169.254.169.254` after the check. Note this as a concern when custom IP-checking code is present without a library that handles rebinding.
- GCP metadata requires the `Metadata-Flavor: Google` header for the metadata endpoint to respond. However, this does NOT protect against SSRF — the attacker controls the request URL, not the server's headers. The header is a defense-in-depth on the GCP side but does not mitigate the SSRF sink.
- When in doubt, classify as "Needs Manual Review" rather than "Not Vulnerable". A false negative for a critical vulnerability is far worse than a false positive.
- Clean up intermediate files: delete `sast/ssrfimds-recon.md` and all `sast/ssrfimds-batch-*.md` after the final output files are written.
- Both `sast/ssrfimds-results.md` and `sast/ssrfimds-results.json` must always be written — even when no findings are found, write the JSON with `"findings": []` so the aggregator can verify the scan ran.
