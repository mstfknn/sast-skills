---
name: sast-oauth
description: >-
  Detect OAuth 2.0 and OIDC implementation flaws in a codebase using a
  three-phase approach: recon (find authorization flows, redirect_uri handling,
  state parameter usage, PKCE configuration, and grant type selection), batched
  verify (check each candidate for exploitable misconfigurations in parallel
  subagents, 3 candidates each), and merge (consolidate batch results). Covers
  unvalidated redirect_uri (open redirect / authorization-code interception),
  missing or unverified state parameter (CSRF on callback), missing PKCE for
  public clients, and implicit grant flow usage. Requires sast/architecture.md
  (run sast-analysis first). Outputs findings to sast/oauth-results.md. Use
  when asked to find OAuth, OIDC, or authorization flow security bugs.
version: 0.1.0
---

# OAuth 2.0 / OIDC Misconfiguration Detection

You are performing a focused security assessment to find OAuth 2.0 and OpenID Connect (OIDC) implementation flaws in a codebase. This skill uses a three-phase approach with subagents: **recon** (find authorization flows and their configuration), **batched verify** (check OAuth/OIDC protections in parallel batches of 3 candidates each), and **merge** (consolidate batch results into the final report).

**Prerequisites**: `sast/architecture.md` must exist. Run the analysis skill first if it doesn't.

---

## What is an OAuth / OIDC Misconfiguration

OAuth 2.0 is an authorization delegation protocol. OIDC is an authentication layer built on top of it. Both rely on several security controls — validated redirect URIs, the `state` parameter, PKCE, and the authorization-code grant — that developers frequently omit, misimplement, or disable in the interest of flexibility. When any of these controls is absent or bypassable, an attacker can intercept authorization codes (leading to full account takeover), forge authorization requests (forcing the victim to authorize the attacker's session), or extract access tokens directly from the browser's navigation history.

The vulnerability classes in scope are:

1. **Unvalidated `redirect_uri`** — the authorization server (or the client callback handler) accepts a `redirect_uri` from the request parameter rather than validating it against a pre-registered allowlist. An attacker crafts an authorization URL pointing `redirect_uri` to an attacker-controlled server; the authorization server delivers the authorization code (and sometimes the access token) there.

2. **Missing or unverified `state` parameter** — the `state` parameter is OAuth's built-in CSRF defense for the callback. If the client does not include `state` in the authorization request, or includes it but never compares the callback value to the session-stored value, an attacker can initiate a forged authorization flow and trick the victim's browser into completing it — a CSRF attack on the OAuth callback.

3. **Missing PKCE for public clients** — PKCE (Proof Key for Code Exchange, RFC 7636) defends against authorization-code interception attacks by binding the code to a secret (`code_verifier`) that only the legitimate client knows. Public clients (SPAs, mobile apps, CLIs) that omit PKCE and rely solely on the client secret (which they cannot protect) or on nothing at all are vulnerable to code interception.

4. **Implicit grant flow** — the implicit grant delivers access tokens directly in the URL fragment (`response_type=token`), bypassing the authorization code exchange. Tokens appear in browser history, server logs, `Referer` headers, and are accessible to any same-origin JavaScript. RFC 9700 (OAuth 2.0 Security Best Current Practice) deprecates the implicit grant entirely.

### What OAuth Misconfigs ARE

- `redirect_uri` built from a request parameter without an exact-match allowlist check before the redirect
- Callback handler that reads `code` from the query string and immediately exchanges it without comparing `req.query.state` to `req.session.oauthState`
- Public client (SPA, mobile, CLI) using authorization-code flow without generating `code_verifier` / `code_challenge`
- Provider configuration with `response_type: 'token'` or `grant_type: 'implicit'`
- OIDC callback that does not validate the `nonce` claim in the received ID token
- Authorization server accepting wildcard or suffix-matched `redirect_uri` patterns (`https://app.example.com/*`) that an attacker can defeat with a crafted path

### What OAuth Misconfigs are NOT

Do not flag these here:

- **Server-to-server client-credentials flows with no redirect** — there is no `redirect_uri`, no `state`, and no user agent involved. Out of scope for this skill.
- **Correctly implemented PKCE + state flows** — `code_verifier` generated with a CSPRNG, stored server-side or in session, sent as `code_challenge` with the authorization request, and verified on the token exchange.
- **Library-managed flows where the library enforces controls by default** — e.g., Passport.js with `state: true`, `django-allauth >= 0.47` (enforces PKCE + state automatically), Spring Security OAuth2 Client with default configuration.
- **Missing auth altogether** — that is `sast-missingauth`.
- **Classic CSRF on non-OAuth endpoints** — that is `sast-csrf`.
- **Open redirect on non-OAuth endpoints** — that is `sast-openredirect`. The OAuth-specific `redirect_uri` flaw is in scope here; chain with `sast-openredirect` when the same redirect logic is also exploitable in a general open-redirect context.

### Patterns That Prevent OAuth Misconfigurations

When you see these patterns applied correctly, the candidate is likely **not vulnerable**:

**1. Strict redirect_uri allowlist**

The client's registered `redirect_uri` at the authorization server is exact-match only. The client application itself also validates any dynamic `redirect_uri` against a hardcoded list before using it:

```javascript
// Node.js — explicit allowlist check before building the authorization URL
const ALLOWED_REDIRECTS = new Set([
  'https://app.example.com/auth/callback',
  'https://app.example.com/auth/mobile-callback',
]);

function buildAuthUrl(redirectUri) {
  if (!ALLOWED_REDIRECTS.has(redirectUri)) {
    throw new Error('redirect_uri not allowed');
  }
  return oauth2Client.generateAuthUrl({ redirect_uri: redirectUri, ... });
}
```

**2. State parameter: generate, store, verify**

The client generates a cryptographically random `state`, stores it in the session, includes it in the authorization request, and compares the callback value before exchanging the code:

```javascript
// Node.js — Passport.js with state: true (library handles generation + verification)
passport.use(new OAuth2Strategy({
  authorizationURL: 'https://provider.example.com/oauth/authorize',
  tokenURL: 'https://provider.example.com/oauth/token',
  clientID: process.env.CLIENT_ID,
  clientSecret: process.env.CLIENT_SECRET,
  callbackURL: 'https://app.example.com/auth/callback',
  state: true,    // <-- Passport generates, stores in session, and verifies on callback
}, verifyCallback));
```

```python
# Python — manual state generation, session storage, and callback comparison
import secrets

def start_oauth(request):
    state = secrets.token_urlsafe(32)
    request.session['oauth_state'] = state
    return redirect(oauth.get_authorization_url(state=state))

def oauth_callback(request):
    if request.GET.get('state') != request.session.pop('oauth_state', None):
        return HttpResponse('CSRF detected', status=403)
    token = oauth.fetch_token(code=request.GET.get('code'))
    # ... proceed
```

**3. PKCE (S256 method) for public clients**

The client generates a random `code_verifier`, computes `code_challenge = BASE64URL(SHA256(code_verifier))`, sends `code_challenge` and `code_challenge_method=S256` with the authorization request, and sends `code_verifier` with the token exchange:

```javascript
// Node.js — openid-client with PKCE
import { generators } from 'openid-client';

const codeVerifier = generators.codeVerifier();
const codeChallenge = generators.codeChallenge(codeVerifier);

// stored in session for the callback
req.session.codeVerifier = codeVerifier;

const authorizationUrl = client.authorizationUrl({
  scope: 'openid email profile',
  code_challenge: codeChallenge,
  code_challenge_method: 'S256',
});
```

```python
# Python — authlib with PKCE
from authlib.integrations.flask_client import OAuth
oauth = OAuth(app)
oauth.register('provider', ..., client_kwargs={'code_challenge_method': 'S256'})
# authlib auto-generates and verifies the PKCE pair
```

**4. Authorization-code grant (not implicit)**

The client requests `response_type=code` (and optionally `response_type=code id_token` for OIDC hybrid flows with a nonce), never `response_type=token`:

```javascript
// SECURE: authorization-code with PKCE
const authUrl = new URL('https://provider.example.com/authorize');
authUrl.searchParams.set('response_type', 'code');   // <-- not 'token'
authUrl.searchParams.set('client_id', CLIENT_ID);
authUrl.searchParams.set('redirect_uri', CALLBACK_URL);
authUrl.searchParams.set('scope', 'openid profile email');
authUrl.searchParams.set('state', state);
authUrl.searchParams.set('code_challenge', codeChallenge);
authUrl.searchParams.set('code_challenge_method', 'S256');
```

**5. OIDC nonce validation**

The client generates a random `nonce`, includes it in the authorization request, and verifies the `nonce` claim in the returned ID token matches before trusting the token:

```python
# Python — authlib automatically validates nonce when using parse_id_token
nonce = secrets.token_urlsafe(32)
session['oauth_nonce'] = nonce
redirect_url = oauth.provider.authorize_redirect(redirect_uri, nonce=nonce)
# On callback:
token = oauth.provider.authorize_access_token()
user_info = oauth.provider.parse_id_token(token, nonce=session.pop('oauth_nonce'))
```

---

## Vulnerability Sub-Classes

### Sub-class 1: Unvalidated redirect_uri (Authorization-Code Interception)

The most impactful OAuth flaw. An authorization URL is constructed using a `redirect_uri` that comes from a request parameter, a configuration value, or a URL builder that does not validate against a registered allowlist. The authorization server either accepts any subdomain/path/parameter variant (a common server misconfiguration), or the client itself acts as an open redirector after receiving the code. An attacker tricks the victim into visiting a crafted authorization URL; the code lands on the attacker's server; the attacker exchanges it for access and refresh tokens.

### Sub-class 2: Missing state Parameter (OAuth Callback CSRF)

The client does not include `state` in the authorization request, or includes it but the callback handler does not compare `req.query.state` to `req.session.oauthState` before exchanging the code. An attacker initiates an authorization flow on their own account, captures the resulting authorization URL (before exchanging the code), then delivers it to the victim's browser (e.g., in an `<img>` or `<iframe>`). The victim's authenticated session completes the OAuth flow, linking the attacker's OAuth credentials to the victim's account — effectively a session fixation via OAuth. This is directly analogous to CSRF; the `state` parameter is the CSRF token for the OAuth callback.

### Sub-class 3: Missing PKCE on a Public Client

Public clients (SPAs, mobile apps, desktop apps, CLI tools) cannot securely store a client secret. In the absence of PKCE, any party that intercepts the authorization code (via malicious redirect, referrer leak, browser history, or network position) can exchange it for tokens. With PKCE, the intercepted code is useless because the attacker does not have the `code_verifier`.

**Note on confidential clients**: A confidential server-side client that protects its client secret has a secondary defense. Missing PKCE on a confidential client is still a defense-in-depth concern but is lower severity (medium) unless the client secret is also weak or exposed.

### Sub-class 4: Implicit Grant Flow (response_type=token)

The implicit grant returns an access token in the URL fragment. Token exposure vectors:

- Browser history (the URL with the fragment is recorded)
- Server logs (if the SPA is a file served by a web server that logs the full URL, the fragment is logged in some configurations)
- `Referer` header on outbound navigation from the SPA page
- `window.location` access by injected third-party scripts
- JavaScript error reports that include the current URL

RFC 9700 and the OAuth 2.0 Security BCP deprecate the implicit grant. Flag any `response_type=token` usage.

### Sub-class 5: Missing or Bypassable nonce in OIDC

For OIDC flows, the `nonce` parameter is the equivalent of `state` at the ID-token level. If the client does not include a `nonce` in the authorization request, or includes it but does not compare the value in the returned ID token, the flow is vulnerable to token replay attacks: an attacker who obtains an ID token from one authorization session can replay it in another.

### Sub-class 6: Open Redirect via redirect_uri (also chains to sast-openredirect)

If the client application constructs a `redirect_uri` using user-supplied input and then redirects to it after a successful OAuth flow without validation, this is both an OAuth misconfiguration and a general open redirect. Chains with `sast-openredirect` (chain_id: `open-redirect-oauth`).

---

## Vulnerable vs. Secure Examples

### Node.js — Passport.js

```javascript
// VULNERABLE: state not enabled — no CSRF protection on the OAuth callback
passport.use(new OAuth2Strategy({
  authorizationURL: 'https://provider.example.com/oauth/authorize',
  tokenURL:         'https://provider.example.com/oauth/token',
  clientID:     process.env.CLIENT_ID,
  clientSecret: process.env.CLIENT_SECRET,
  callbackURL:  'https://app.example.com/auth/callback',
  // state option omitted — Passport will NOT generate or verify state
}, (accessToken, refreshToken, profile, done) => {
  User.findOrCreate(profile, done);
}));

// VULNERABLE: redirect_uri built from request parameter, no allowlist
app.get('/auth/start', (req, res) => {
  const redirectTo = req.query.redirect_uri;  // attacker-controlled
  const authUrl = `https://provider.example.com/oauth/authorize`
    + `?client_id=${CLIENT_ID}`
    + `&response_type=code`
    + `&redirect_uri=${encodeURIComponent(redirectTo)}`;  // no validation
  res.redirect(authUrl);
});

// SECURE: state: true tells Passport to generate, store, and verify state
passport.use(new OAuth2Strategy({
  authorizationURL: 'https://provider.example.com/oauth/authorize',
  tokenURL:         'https://provider.example.com/oauth/token',
  clientID:     process.env.CLIENT_ID,
  clientSecret: process.env.CLIENT_SECRET,
  callbackURL:  'https://app.example.com/auth/callback',
  state: true,   // <-- Passport generates random state, stores in session, verifies on callback
}, (accessToken, refreshToken, params, profile, done) => {
  User.findOrCreate(profile, done);
}));

// SECURE: redirect_uri validated against an allowlist
const ALLOWED_REDIRECT_URIS = new Set([
  'https://app.example.com/auth/callback',
]);

app.get('/auth/start', (req, res) => {
  const redirectUri = req.query.redirect_uri || 'https://app.example.com/auth/callback';
  if (!ALLOWED_REDIRECT_URIS.has(redirectUri)) {
    return res.status(400).json({ error: 'invalid redirect_uri' });
  }
  // proceed with validated redirectUri
});
```

### Node.js — Manual OAuth callback (no library)

```javascript
// VULNERABLE: callback handler reads code from query, exchanges immediately
// No state comparison; attacker can deliver a forged callback URL
app.get('/auth/callback', async (req, res) => {
  const code = req.query.code;
  const state = req.query.state; // received but never compared
  const tokenResponse = await exchangeCode(code);
  req.session.accessToken = tokenResponse.access_token;
  res.redirect('/dashboard');
});

// SECURE: state compared to session-stored value before exchanging code
app.get('/auth/callback', async (req, res) => {
  const { code, state } = req.query;

  if (!state || state !== req.session.oauthState) {
    return res.status(403).json({ error: 'state mismatch — possible CSRF' });
  }
  delete req.session.oauthState;   // consume the one-time value

  const tokenResponse = await exchangeCode(code);
  req.session.accessToken = tokenResponse.access_token;
  res.redirect('/dashboard');
});

// SECURE: PKCE with openid-client
import { Issuer, generators } from 'openid-client';

app.get('/auth/start', async (req, res) => {
  const issuer = await Issuer.discover('https://provider.example.com');
  const client = new issuer.Client({ client_id: CLIENT_ID, redirect_uris: [CALLBACK_URL] });

  const codeVerifier = generators.codeVerifier();
  const codeChallenge = generators.codeChallenge(codeVerifier);
  const state = generators.state();

  req.session.oauthState = state;
  req.session.codeVerifier = codeVerifier;

  const authUrl = client.authorizationUrl({
    scope: 'openid email profile',
    state,
    code_challenge: codeChallenge,
    code_challenge_method: 'S256',
  });
  res.redirect(authUrl);
});

app.get('/auth/callback', async (req, res) => {
  const params = client.callbackParams(req);
  const tokenSet = await client.callback(CALLBACK_URL, params, {
    state: req.session.oauthState,
    code_verifier: req.session.codeVerifier,
  });
  delete req.session.oauthState;
  delete req.session.codeVerifier;
  req.session.accessToken = tokenSet.access_token;
  res.redirect('/dashboard');
});
```

### Python — authlib

```python
# VULNERABLE: no server_metadata_url, no code_challenge_method, no state check
from authlib.integrations.flask_client import OAuth

oauth = OAuth(app)
oauth.register(
    'provider',
    client_id=os.environ['CLIENT_ID'],
    client_secret=os.environ['CLIENT_SECRET'],
    authorize_url='https://provider.example.com/oauth/authorize',
    access_token_url='https://provider.example.com/oauth/token',
    # client_kwargs missing code_challenge_method — PKCE not enforced
)

@app.route('/callback')
def callback():
    # VULNERABLE: state from session never compared to request state
    token = oauth.provider.authorize_access_token()  # skips state verification
    user = oauth.provider.userinfo()
    session['user'] = user
    return redirect('/')

# VULNERABLE: redirect_uri from request param, no validation
@app.route('/auth')
def auth():
    redirect_uri = request.args.get('redirect_uri', url_for('callback', _external=True))
    return oauth.provider.authorize_redirect(redirect_uri)

# SECURE: authlib with PKCE and automatic state management
oauth.register(
    'provider',
    client_id=os.environ['CLIENT_ID'],
    client_secret=os.environ['CLIENT_SECRET'],
    server_metadata_url='https://provider.example.com/.well-known/openid-configuration',
    client_kwargs={
        'scope': 'openid email profile',
        'code_challenge_method': 'S256',  # <-- authlib auto-generates and verifies PKCE pair
    },
)

@app.route('/auth')
def auth():
    # redirect_uri is always the registered, hardcoded callback — never from request
    return oauth.provider.authorize_redirect(
        url_for('callback', _external=True)
    )

@app.route('/callback')
def callback():
    # authlib verifies state automatically if it was set during authorize_redirect
    token = oauth.provider.authorize_access_token()
    user = oauth.provider.userinfo()
    session['user'] = user
    return redirect('/')
```

### Java — Spring Security OAuth2 Client

```java
// VULNERABLE: custom redirect_uri resolver reading from request parameter
@Configuration
public class OAuth2Config {
    @Bean
    public OAuth2AuthorizationRequestResolver customResolver(
            ClientRegistrationRepository repo) {
        DefaultOAuth2AuthorizationRequestResolver base =
            new DefaultOAuth2AuthorizationRequestResolver(repo, "/oauth2/authorization");

        base.setAuthorizationRequestCustomizer(builder -> {
            // VULNERABLE: redirect_uri taken from current request parameter
            String dynamicRedirect = getCurrentRequest().getParameter("redirect_uri");
            if (dynamicRedirect != null) {
                builder.redirectUri(dynamicRedirect);  // <-- no allowlist validation
            }
        });
        return base;
    }
}

// VULNERABLE: PKCE not configured for a public client (e.g., SPA or device flow)
@Bean
public ClientRegistrationRepository clientRegistrationRepository() {
    ClientRegistration reg = ClientRegistration.withRegistrationId("provider")
        .clientId(CLIENT_ID)
        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
        .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
        .scope("openid", "profile", "email")
        .authorizationUri("https://provider.example.com/oauth/authorize")
        .tokenUri("https://provider.example.com/oauth/token")
        .build();  // no pkce() call — missing PKCE for public client
    return new InMemoryClientRegistrationRepository(reg);
}

// SECURE: Spring Security default OAuth2 client — state handled automatically;
// add PKCE via PublicClientOAuth2AuthorizedClientProvider for public clients
@Bean
public OAuth2AuthorizedClientManager authorizedClientManager(
        ClientRegistrationRepository clients,
        OAuth2AuthorizedClientRepository authorizedClients) {

    DefaultOAuth2AuthorizedClientManager manager =
        new DefaultOAuth2AuthorizedClientManager(clients, authorizedClients);

    OAuth2AuthorizedClientProvider provider =
        OAuth2AuthorizedClientProviderBuilder.builder()
            .authorizationCode()
            .refreshToken()
            // For public clients: enable pkce via PublicClientOAuth2AuthorizedClientProvider
            .build();

    manager.setAuthorizedClientProvider(provider);
    return manager;
}

// SECURE: disallow dynamic redirect_uri, rely on registered value only
@Configuration
public class SecurityConfig {
    @Bean
    SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.oauth2Login(oauth -> oauth
            .authorizationEndpoint(auth -> auth
                // Use the default resolver — reads redirect_uri from client registration,
                // never from the incoming HTTP request.
                .authorizationRequestResolver(
                    new DefaultOAuth2AuthorizationRequestResolver(
                        clientRegistrationRepository,
                        "/oauth2/authorization")))
        );
        return http.build();
    }
}
```

### Python — Django-allauth / social-auth

```python
# VULNERABLE: SOCIAL_AUTH_ALLOWED_REDIRECT_HOSTS empty — no redirect validation
# settings.py
SOCIAL_AUTH_ALLOWED_REDIRECT_HOSTS = []   # effectively disables host validation
SOCIAL_AUTH_LOGIN_REDIRECT_URL = '/'
# An attacker can pass ?next=https://evil.example.com and social-auth will follow it

# VULNERABLE: implicit grant via response_type=token in a custom backend
class ImplicitGithubOAuth2(GithubOAuth2):
    ACCESS_TOKEN_METHOD = 'GET'
    RESPONSE_TYPE = 'token'   # <-- implicit grant, tokens exposed in URL

# SECURE: SOCIAL_AUTH_ALLOWED_REDIRECT_HOSTS restricts the ?next= parameter
# settings.py
SOCIAL_AUTH_ALLOWED_REDIRECT_HOSTS = ['app.example.com']  # only allow same host
SOCIAL_AUTH_LOGIN_REDIRECT_URL = '/'
SOCIAL_AUTH_LOGIN_ERROR_URL = '/login-error/'

# django-allauth >= 0.47 enforces PKCE + state by default:
SOCIALACCOUNT_PROVIDERS = {
    'google': {
        'APP': {
            'client_id': os.environ['GOOGLE_CLIENT_ID'],
            'secret': os.environ['GOOGLE_CLIENT_SECRET'],
        },
        'OAUTH_PKCE_ENABLED': True,   # explicit; default True from 0.47
    }
}
```

### JavaScript — SPA with implicit grant (generic)

```javascript
// VULNERABLE: response_type=token in the authorization URL — implicit grant
const authUrl = new URL('https://provider.example.com/authorize');
authUrl.searchParams.set('response_type', 'token');  // <-- implicit, deprecated by RFC 9700
authUrl.searchParams.set('client_id', CLIENT_ID);
authUrl.searchParams.set('redirect_uri', CALLBACK_URL);
authUrl.searchParams.set('scope', 'openid profile email');
window.location.href = authUrl.toString();

// After redirect, token is in window.location.hash — exposed to JS, history, Referer

// SECURE: response_type=code + PKCE
import { generateCodeVerifier, calculatePKCECodeChallenge } from 'oauth4webapi';

const codeVerifier = generateCodeVerifier();
const codeChallenge = await calculatePKCECodeChallenge(codeVerifier);
const state = crypto.randomUUID();

// Store in sessionStorage (not localStorage — sessionStorage is tab-scoped)
sessionStorage.setItem('oauth_code_verifier', codeVerifier);
sessionStorage.setItem('oauth_state', state);

const authUrl = new URL('https://provider.example.com/authorize');
authUrl.searchParams.set('response_type', 'code');
authUrl.searchParams.set('client_id', CLIENT_ID);
authUrl.searchParams.set('redirect_uri', CALLBACK_URL);
authUrl.searchParams.set('scope', 'openid profile email');
authUrl.searchParams.set('state', state);
authUrl.searchParams.set('code_challenge', codeChallenge);
authUrl.searchParams.set('code_challenge_method', 'S256');
window.location.href = authUrl.toString();

// Callback handler in the SPA
const params = new URLSearchParams(window.location.search);
const returnedState = params.get('state');
const storedState = sessionStorage.getItem('oauth_state');

if (!returnedState || returnedState !== storedState) {
  throw new Error('State mismatch — possible CSRF or replay attack');
}

const tokenResponse = await fetch('https://provider.example.com/token', {
  method: 'POST',
  body: new URLSearchParams({
    grant_type: 'authorization_code',
    code: params.get('code'),
    redirect_uri: CALLBACK_URL,
    client_id: CLIENT_ID,
    code_verifier: sessionStorage.getItem('oauth_code_verifier'),
  }),
});
```

### Go — golang.org/x/oauth2

```go
// VULNERABLE: state not generated or not verified on callback
var oauthConf = &oauth2.Config{
    ClientID:     os.Getenv("CLIENT_ID"),
    ClientSecret: os.Getenv("CLIENT_SECRET"),
    RedirectURL:  "https://app.example.com/auth/callback",
    Scopes:       []string{"openid", "profile", "email"},
    Endpoint:     provider.Endpoint(),
}

func startHandler(w http.ResponseWriter, r *http.Request) {
    // VULNERABLE: hardcoded or empty state
    url := oauthConf.AuthCodeURL("") // empty state = no CSRF protection
    http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func callbackHandler(w http.ResponseWriter, r *http.Request) {
    // VULNERABLE: state from URL never compared to anything
    code := r.URL.Query().Get("code")
    token, err := oauthConf.Exchange(r.Context(), code)
    if err != nil {
        http.Error(w, "exchange failed", http.StatusInternalServerError)
        return
    }
    setSession(w, token)
}

// VULNERABLE: redirect_uri accepted from query parameter without validation
func startHandlerDynamic(w http.ResponseWriter, r *http.Request) {
    redirectURI := r.URL.Query().Get("redirect_uri")
    // No allowlist check — attacker can inject arbitrary redirect_uri
    conf := *oauthConf
    conf.RedirectURL = redirectURI
    url := conf.AuthCodeURL(generateState())
    http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

// SECURE: state generated with crypto/rand, stored in session cookie, verified on callback
func startHandlerSecure(w http.ResponseWriter, r *http.Request) {
    b := make([]byte, 32)
    if _, err := rand.Read(b); err != nil {
        http.Error(w, "internal error", http.StatusInternalServerError)
        return
    }
    state := base64.URLEncoding.EncodeToString(b)

    http.SetCookie(w, &http.Cookie{
        Name:     "oauth_state",
        Value:    state,
        Path:     "/",
        HttpOnly: true,
        Secure:   true,
        SameSite: http.SameSiteLaxMode,
        MaxAge:   300,
    })

    url := oauthConf.AuthCodeURL(state)
    http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func callbackHandlerSecure(w http.ResponseWriter, r *http.Request) {
    cookie, err := r.Cookie("oauth_state")
    if err != nil || r.URL.Query().Get("state") != cookie.Value {
        http.Error(w, "state mismatch", http.StatusForbidden)
        return
    }
    // clear the one-time cookie
    http.SetCookie(w, &http.Cookie{Name: "oauth_state", MaxAge: -1, Path: "/"})

    code := r.URL.Query().Get("code")
    token, err := oauthConf.Exchange(r.Context(), code)
    if err != nil {
        http.Error(w, "exchange failed", http.StatusInternalServerError)
        return
    }
    setSession(w, token)
}
```

### Ruby — OmniAuth

```ruby
# VULNERABLE: OmniAuth configured to allow GET-based callbacks
# config/initializers/omniauth.rb
Rails.application.config.middleware.use OmniAuth::Builder do
  provider :github, ENV['GITHUB_KEY'], ENV['GITHUB_SECRET']
  # Missing: OmniAuth.config.allowed_request_methods = %i[post]
  # GET /auth/github/callback is allowed by default in OmniAuth < 2.x
  # — enables CSRF on the callback route
end

# VULNERABLE: redirect_uri from session-stored next parameter, not validated
class SessionsController < ApplicationController
  def create
    user = User.from_omniauth(request.env['omniauth.auth'])
    session[:user_id] = user.id
    redirect_to session.delete(:user_return_to) || root_path
    # VULNERABLE: session[:user_return_to] set from params[:return_to] without host check
  end
end

# SECURE: OmniAuth with CSRF protection via POST only + allowlist redirect
# config/initializers/omniauth.rb
OmniAuth.config.allowed_request_methods = %i[post]     # blocks GET-based CSRF
OmniAuth.config.silence_get_warning = false
OmniAuth.config.on_failure = proc { |env|
  OmniAuth::FailureEndpoint.new(env).redirect_to_failure
}

# SECURE: validate redirect origin before following it
class SessionsController < ApplicationController
  ALLOWED_REDIRECT_HOSTS = %w[app.example.com].freeze

  def create
    user = User.from_omniauth(request.env['omniauth.auth'])
    session[:user_id] = user.id
    redirect_to safe_return_url
  end

  private

  def safe_return_url
    return_url = session.delete(:user_return_to)
    uri = URI.parse(return_url.to_s)
    ALLOWED_REDIRECT_HOSTS.include?(uri.host) ? return_url : root_path
  rescue URI::InvalidURIError
    root_path
  end
end
```

---

## Execution

This skill runs in three phases using subagents. Pass the contents of `sast/architecture.md` to all subagents as context.

### Phase 1: Recon — Find OAuth / OIDC Authorization Flows

Launch a subagent with the following instructions:

> **Goal**: Build an inventory of every OAuth 2.0 / OIDC authorization flow, callback handler, and relevant configuration in the codebase. Write results to `sast/oauth-recon.md`.
>
> **Context**: You will be given the project's architecture summary. Use it to understand the tech stack, identity provider integrations, OAuth libraries in use, and any session/cookie configuration relevant to callback handling.
>
> **What to search for**:
>
> 1. **OAuth library detection** — identify which library or framework manages OAuth flows:
>    - Node.js: `passport-oauth2`, `passport-google-oauth20`, `openid-client`, `oauth4webapi`, `simple-oauth2`, `@auth/core`, `next-auth`, `oidc-client-ts`
>    - Python: `authlib`, `requests-oauthlib`, `social-auth-app-django`, `django-allauth`, `python-social-auth`, `oauthlib`
>    - Java/Spring: `spring-security-oauth2-client`, `spring-boot-starter-oauth2-client`, `spring-security-oauth2-resource-server`
>    - Ruby: `omniauth`, `omniauth-oauth2`, `devise` + OmniAuth
>    - Go: `golang.org/x/oauth2`, `coreos/go-oidc`, `zitadel/oidc`
>    - PHP: `league/oauth2-client`, `laravel/socialite`
>    - Note the library version if visible in `package.json`, `requirements.txt`, `pyproject.toml`, `pom.xml`, `go.mod`, `Gemfile`, `composer.json`, etc.
>
> 2. **Authorization initiation points** — locate every place the application starts an OAuth flow (builds and redirects to the authorization URL):
>    - Express/Node: `passport.authenticate('google', ...)`, `oauth2Client.generateAuthUrl(...)`, `authorizationUrl(...)`, `client.authorizationUrl(...)`
>    - Flask/Django/FastAPI: `oauth.provider.authorize_redirect(...)`, `redirect(authorization_url)`, `@app.route('/auth')` handlers
>    - Spring: `OAuth2AuthorizationRequestRedirectFilter`, custom `OAuth2AuthorizationRequestResolver`
>    - Rails: `redirect_to oauth.get_authorize_url(...)`, OmniAuth middleware routing to `/auth/:provider`
>    - For each, note:
>      - Is `state` included in the authorization URL? Is it generated with a CSPRNG or hardcoded/empty?
>      - Is `code_challenge` / `code_challenge_method=S256` (PKCE) included?
>      - What is `response_type`? (`code`, `token`, `id_token`, `code id_token`)
>      - Is `redirect_uri` hardcoded or dynamic? If dynamic, where does the value come from?
>
> 3. **Callback handlers** — locate every OAuth/OIDC callback endpoint (the handler that receives the `code` and `state` from the authorization server):
>    - Express: `app.get('/auth/callback', ...)`, `passport.authenticate('google', { session: false })` in callback position
>    - Flask: `@app.route('/callback')` or `@bp.route('/oauth/callback')`
>    - Django: `SocialAuthExceptionMiddleware`, `complete` views, `allauth.socialaccount.views`
>    - Spring: `/login/oauth2/code/{registrationId}` handler, custom `AuthenticationSuccessHandler`
>    - Rails: `SessionsController#create`, `Devise::OmniauthCallbacksController#google_oauth2`
>    - For each callback, note:
>      - Is `req.query.state` / `request.GET['state']` compared against a session-stored value?
>      - What happens if `state` is missing or mismatched — error raised, or silently ignored?
>      - Is the `code` exchanged for a token before the state check?
>      - For OIDC: is the `nonce` in the ID token validated?
>
> 4. **redirect_uri configuration and validation** — locate where `redirect_uri` is set or used:
>    - Is it hardcoded to a fixed URL?
>    - Is it read from a request parameter (`req.query.redirect_uri`, `request.GET.get('redirect_uri')`)? If so, is there an allowlist check?
>    - Is it built from a base URL + user-controlled path component?
>    - Is there any validation before the value is used in the authorization URL or before the token exchange?
>    - Grep for: `redirect_uri`, `redirectUri`, `redirect_url`, `callbackURL`, `ALLOWED_REDIRECT`, `SOCIAL_AUTH_ALLOWED_REDIRECT_HOSTS`
>
> 5. **Grant type and response_type configuration** — search for:
>    - `response_type=token`, `response_type: 'token'`, `RESPONSE_TYPE = 'token'` (implicit grant)
>    - `grant_type=implicit`, `grant_type: 'implicit'`
>    - `AuthorizationGrantType.IMPLICIT` (Spring)
>    - Note every location, even if the value appears in a config file or environment variable
>
> 6. **PKCE configuration** — search for:
>    - `code_challenge`, `codeChallenge`, `code_challenge_method`, `S256` (present = PKCE enabled)
>    - `generateCodeVerifier`, `code_verifier`, `codeVerifier`
>    - `client_kwargs={'code_challenge_method': 'S256'}` (authlib)
>    - `OAUTH_PKCE_ENABLED` (django-allauth)
>    - `PublicClientOAuth2AuthorizedClientProvider` (Spring)
>    - For each public-client flow (SPA, mobile, CLI) without one of the above, flag as a candidate
>
> 7. **Library defaults that enforce state/PKCE** — note when a library is known to enforce controls:
>    - Passport.js with `state: true` — library manages state automatically
>    - `django-allauth >= 0.47` — PKCE + state enabled by default
>    - `authlib` with `code_challenge_method` in `client_kwargs` — PKCE enforced
>    - `next-auth` (NextAuth.js) — manages state internally for its providers
>    - `openid-client` (`node-openid-client`) — full OIDC protocol, validates state + nonce when options passed
>    - Spring Security OAuth2 Client default configuration — state handled by `HttpSessionOAuth2AuthorizationRequestRepository`
>    - OmniAuth 2.x — CSRF protection via POST requirement (configurable)
>    - Mark these flows as "library-managed" and deprioritize unless a misconfiguration disables the default
>
> **What to ignore**:
> - Client-credentials flows with no redirect URI and no user agent — these have no CSRF or code-interception surface
> - Device authorization grant — different attack surface, no redirect_uri validation needed
> - OAuth flows that are already correctly implementing PKCE + state with library defaults (mark as Not Vulnerable)
> - Token-refresh flows that do not involve user authorization
>
> **Output format** — write to `sast/oauth-recon.md`:
>
> ```markdown
> # OAuth / OIDC Recon: [Project Name]
>
> ## Library Summary
> - OAuth/OIDC library: [name + version if known]
> - Identity providers: [Google, GitHub, custom OIDC server, etc.]
> - Client type: [confidential (server-side) / public (SPA, mobile, CLI) / mixed]
> - Library-managed state/PKCE: [yes — Passport state:true / django-allauth >=0.47 / no / partial]
>
> ## Flow Inventory
>
> ### 1. [Flow name / description — e.g., "GitHub Login", "Google OIDC", "Custom provider"]
> - **Authorization initiation file**: `path/to/file.ext` (lines X-Y)
> - **Callback handler file**: `path/to/file.ext` (lines X-Y)
> - **response_type**: [code / token / id_token / code id_token]
> - **state included**: [yes — CSPRNG / yes — hardcoded / no]
> - **state verified on callback**: [yes — session comparison / no / unknown]
> - **PKCE**: [yes — S256 / no / library default]
> - **redirect_uri source**: [hardcoded / request parameter / config / dynamic built]
> - **redirect_uri validated**: [yes — exact allowlist / yes — prefix match / no]
> - **nonce validated (OIDC)**: [yes / no / not OIDC]
> - **Sub-class concern**: [unvalidated redirect_uri / missing state / missing PKCE / implicit grant / missing nonce / none]
> - **Code snippet**:
>   ```
>   [authorization initiation + callback handler snippet]
>   ```
>
> [Repeat for each flow]
> ```

### Phase 2: Verify — OAuth / OIDC Protection Check (Batched)

After Phase 1 completes, read `sast/oauth-recon.md` and split the flow inventory into **batches of up to 3 flows each** (each numbered `### N.` under **Flow Inventory**). Launch **one subagent per batch in parallel**. Each subagent verifies only its assigned flows and writes results to its own batch file.

**Batching procedure** (you, the orchestrator, do this — not a subagent):

1. Read `sast/oauth-recon.md` and count the numbered flow sections under **Flow Inventory** (`### 1.`, `### 2.`, etc.).
2. Divide them into batches of up to 3. For example, 7 flows → 3 batches (1–3, 4–6, 7).
3. For each batch, extract the full text of those flow sections from the recon file.
4. Launch all batch subagents **in parallel**, passing each one only its assigned flows.
5. Each subagent writes to `sast/oauth-batch-N.md` where N is the 1-based batch number.
6. Identify the project's primary language/framework from `sast/architecture.md` and select **only the matching examples** from the "Vulnerable vs. Secure Examples" section above. Include these in each subagent's instructions where indicated by `[TECH-STACK EXAMPLES]` below.

Give each batch subagent the following instructions (substitute the batch-specific values):

> **Goal**: Verify the following OAuth / OIDC flows for security misconfigurations. Write results to `sast/oauth-batch-[N].md`.
>
> **Your assigned flows** (from the recon phase):
>
> [Paste the full text of the assigned flow sections here, preserving the original numbering]
>
> **Context**: You will be given the project's architecture summary. Use it to understand the tech stack, identity providers, library versions, and session configuration.
>
> **Vulnerability preconditions — evaluate each sub-class separately**:
>
> **Sub-class A — Unvalidated redirect_uri**:
> The flow is vulnerable if: (1) the authorization URL or the callback exchange uses a `redirect_uri` that can be influenced by an external user or request parameter, AND (2) there is no exact-match allowlist check before the value is used. Exploitability: `reachable` when the attacker can fully control the value and the authorization server does not validate it server-side; `conditional` when only partial matching or parameter-appending attacks are possible.
>
> **Sub-class B — Missing or unverified state (OAuth Callback CSRF)**:
> The flow is vulnerable if: (1) `state` is absent from the authorization request, OR (2) `state` is present in the request but the callback handler does not compare it to a session-stored value before exchanging the code. Exploitability: `reachable` when an attacker can initiate an authorization flow on their own account and deliver the callback URL to a victim's browser.
>
> **Sub-class C — Missing PKCE on a public client**:
> The flow is vulnerable if: (1) the client is a public client (SPA, mobile app, CLI, or any client that cannot protect a client secret), AND (2) `code_challenge` / `code_challenge_method=S256` is absent from the authorization request. Exploitability: `conditional` (requires code interception — e.g., a malicious redirect, referrer leak, or network position). For a confidential client with a strong client secret, severity is `medium`; for a public client, `high`.
>
> **Sub-class D — Implicit grant**:
> The flow is vulnerable if `response_type` includes `token` (the access token is delivered in the URL fragment). This is deprecated by RFC 9700 and always a finding. Exploitability: `reachable` — the token is in the URL, visible to browser history, same-origin JS, and referrer headers.
>
> **Sub-class E — Missing nonce validation (OIDC)**:
> The flow is vulnerable if: (1) the client uses OIDC (receives an `id_token`), AND (2) the client does not include a `nonce` in the authorization request, OR includes it but does not verify the `nonce` claim in the returned ID token. Exploitability: `conditional` (requires obtaining a valid ID token from another session to replay).
>
> **What this skill is NOT** — do NOT flag these here:
> - Classic CSRF on non-OAuth endpoints → sast-csrf
> - General open redirects on non-OAuth pages → sast-openredirect
> - Missing authentication altogether → sast-missingauth
> - Client-credentials flows with no user agent → out of scope
>
> **Protective patterns that make the flow safe**:
> 1. `redirect_uri` hardcoded to a fixed value OR validated against an exact-match allowlist — not from request parameters
> 2. `state` generated with a CSPRNG, stored in session, compared on callback before code exchange — or library default (Passport `state:true`, Spring Security default, authlib, etc.)
> 3. `code_challenge_method=S256` (PKCE) in the authorization request, `code_verifier` sent on token exchange — or library default (authlib `client_kwargs`, django-allauth >=0.47, openid-client)
> 4. `response_type=code` (not `token`) — authorization-code grant
> 5. `nonce` generated, sent with authorization request, and validated in ID token on callback (OIDC)
> 6. Library fully manages the flow with all controls enabled and no configuration override disabling them
>
> **Vulnerable vs. Secure examples for this project's tech stack**:
>
> [TECH-STACK EXAMPLES]
>
> **For each assigned flow, evaluate**:
>
> 1. **Identify the client type** — is this a confidential (server-side) or public (SPA/mobile/CLI) client? This affects PKCE severity.
>
> 2. **Check redirect_uri handling**:
>    - Trace where the `redirect_uri` value originates: request parameter, hardcoded constant, config value, dynamic construction.
>    - If from a request parameter or dynamic source: is there an exact-match allowlist check? Does the check happen before the value is used in the authorization URL AND before the token exchange?
>    - Substring or prefix checks (`startsWith`, `includes`, `in`) are bypassable — treat as vulnerable.
>    - An allowlist with wildcard entries (`*.example.com` accepted by the authorization server) combined with a client that does not further restrict subdomain — treat as a bypass risk.
>
> 3. **Check state parameter**:
>    - Is `state` generated with `crypto.randomBytes`, `secrets.token_urlsafe`, `generators.state()`, or equivalent CSPRNG output?
>    - Is it stored in the server-side session (or a `HttpOnly` cookie) before the redirect?
>    - Is it retrieved and compared on the callback before `code` is exchanged? What happens if `state` is missing in the callback — is it rejected or silently accepted?
>    - If a library manages state (`state: true` in Passport, authlib default, django-allauth >=0.47): confirm the option is not disabled or overridden.
>
> 4. **Check PKCE**:
>    - Is `code_challenge` present in the outgoing authorization URL?
>    - Is `code_verifier` sent with the token exchange request?
>    - Is `code_challenge_method` set to `S256` (not `plain`, which provides no security)?
>    - For library defaults: confirm `code_challenge_method: 'S256'` in `client_kwargs` (authlib), `OAUTH_PKCE_ENABLED: True` (django-allauth), or equivalent. Confirm no config overrides disable it.
>
> 5. **Check grant type**:
>    - Is `response_type` set to `token` anywhere in the flow? Flag unconditionally.
>    - Is `grant_type` set to `implicit`? Flag unconditionally.
>
> 6. **Check nonce (OIDC flows only)**:
>    - Is `nonce` included in the authorization request?
>    - Is the `nonce` value stored in session and compared to the `nonce` claim in the returned ID token before the token is accepted?
>    - Library defaults: `openid-client` validates nonce automatically when passed; confirm it is passed.
>
> 7. **Edge cases and bypasses**:
>    - `redirect_uri` validated only at the start of the flow but overridden by a later `redirect` call that reads from request parameters — the code may land at the wrong destination even if the authorization URL was built correctly.
>    - State stored in a cookie without `HttpOnly` — XSS can read and forge it.
>    - State compared with `==` in a timing-observable way — minor, note as info.
>    - PKCE `code_verifier` stored in `localStorage` on a shared device — consider for context-specific risk notes.
>    - `response_type=code id_token` hybrid flow without a nonce — the `id_token` in the fragment is still exposed.
>    - OmniAuth configured with `allowed_request_methods` including `:get` — GET-based CSRF on `/auth/:provider/callback`.
>    - `SOCIAL_AUTH_ALLOWED_REDIRECT_HOSTS` set to `[]` in django-social-auth — validates nothing.
>
> **Classification**:
> - **Vulnerable**: A sub-class precondition is met, no effective defense is present, exploitation is practical.
> - **Likely Vulnerable**: A defense is partially applied but plausibly bypassable (substring allowlist, state stored but not compared on mismatch, PKCE `plain` method, library default disabled in part).
> - **Not Vulnerable**: All relevant sub-classes are addressed by correct implementation or verified library defaults.
> - **Needs Manual Review**: Cannot determine with confidence (e.g., complex middleware chain, library version unknown, dynamic flow construction not traceable from static analysis).
>
> **Chain_id assignment**:
> - If an unvalidated `redirect_uri` also constitutes a general open redirect exploitable outside the OAuth flow, set `chain_id: "open-redirect-oauth"` on the finding and note that `sast-openredirect` may produce a companion finding.
> - If a missing `state` parameter is on a flow that also lacks any form of CSRF protection, set `chain_id: "csrf-oauth"` to link with a potential `sast-csrf` finding on the same callback route.
>
> **Severity assignment**:
> - **Critical**: Unvalidated `redirect_uri` + authorization server issues refresh tokens with `offline_access` scope — attacker gains persistent, user-independent access.
> - **High**: Unvalidated `redirect_uri` (auth-code interception → full account takeover); missing `state` (OAuth callback CSRF → account linkage); implicit grant (access token exposed).
> - **Medium**: Missing PKCE on a public client (requires code interception); missing PKCE on a confidential client (defense-in-depth gap); missing nonce on OIDC (requires token replay under specific conditions).
> - **Low**: Timing-observable state comparison; PKCE `plain` method rather than `S256`; `state` stored in non-HttpOnly cookie on an app without known XSS.
> - **Info**: Library default used but version predates enforcement; warning about potential drift.
>
> **Output format** — write to `sast/oauth-batch-[N].md`:
>
> ```markdown
> # OAuth Batch [N] Results
>
> ## Findings
>
> ### [VULNERABLE] Flow name
> - **Authorization initiation**: `path/to/file.ext` (lines X-Y)
> - **Callback handler**: `path/to/file.ext` (lines X-Y)
> - **Sub-class**: [unvalidated redirect_uri / missing state / missing PKCE / implicit grant / missing nonce]
> - **Issue**: [Specific reason — redirect_uri from req.query without allowlist, state not compared on callback, response_type=token, etc.]
> - **Impact**: [What an attacker can achieve — account takeover, CSRF authorization, token exposure]
> - **chain_id**: ["open-redirect-oauth" / "csrf-oauth" / null]
> - **Severity**: [critical / high / medium / low]
> - **exploitability**: [reachable / conditional / unreachable / unknown]
> - **confidence**: [high / medium / low]
> - **Proof**: [Show the authorization initiation code, callback code, and the missing/broken check — highlight the exact line(s)]
> - **Remediation**: [Concrete fix — add exact-match allowlist, add state generation + session storage + callback comparison, add PKCE, change response_type to code, etc.]
> - **Dynamic Test**:
>   For missing state:
>   ```
>   1. Log in to the target app on the attacker's account and start an OAuth flow.
>   2. Capture the authorization URL before clicking "Authorize".
>   3. Log out (or use a different browser).
>   4. Log in to the target app as the victim (different OAuth account).
>   5. In the same victim browser, navigate to the attacker's captured authorization URL.
>   6. The victim's session completes the authorization, linking the attacker's OAuth credentials to the victim's account.
>   ```
>   For unvalidated redirect_uri:
>   ```
>   Craft: https://provider.example.com/authorize?client_id=CLIENT_ID
>     &response_type=code&scope=openid+profile
>     &redirect_uri=https%3A%2F%2Fattacker.example.com%2Fcapture
>     &state=attacker-state
>   Deliver this URL to a logged-in victim. The authorization code lands at attacker.example.com.
>   ```
>
> ### [LIKELY VULNERABLE] Flow name
> - **Authorization initiation**: `path/to/file.ext` (lines X-Y)
> - **Callback handler**: `path/to/file.ext` (lines X-Y)
> - **Sub-class**: [...]
> - **Issue**: [What's incomplete — prefix-match allowlist, state checked only when header is present, PKCE plain method]
> - **Concern**: [Why the partial defense can be defeated]
> - **chain_id**: [or null]
> - **Proof**: [Code path showing the weak check]
> - **Remediation**: [Specific hardening]
>
> ### [NOT VULNERABLE] Flow name
> - **Authorization initiation**: `path/to/file.ext` (lines X-Y)
> - **Callback handler**: `path/to/file.ext` (lines X-Y)
> - **Protection**: [Which defense applies for each sub-class — exact allowlist, library state:true, PKCE S256, response_type=code, nonce validated]
>
> ### [NEEDS MANUAL REVIEW] Flow name
> - **Authorization initiation**: `path/to/file.ext` (lines X-Y)
> - **Callback handler**: `path/to/file.ext` (lines X-Y)
> - **Uncertainty**: [Why static analysis couldn't determine — dynamic middleware, unknown library version, obfuscated flow]
> - **Suggestion**: [What to inspect manually — check library version, add logging to callback to observe state value, trace redirect_uri origin at runtime]
> ```
>
> **Canonical JSON output**: In addition to the markdown batch file, write your findings to `sast/oauth-batch-[N].json` (create it). Each finding must follow the canonical schema:
>
> ```json
> {
>   "id": "oauth-<sequential>",
>   "skill": "sast-oauth",
>   "severity": "critical|high|medium|low|info",
>   "title": "short one-line description",
>   "description": "full explanation including exploitability",
>   "location": { "file": "relative/path.ext", "line": 123, "column": 10 },
>   "remediation": "how to fix",
>   "exploitability": "reachable|conditional|unreachable|unknown",
>   "confidence": "high|medium|low",
>   "chain_id": "open-redirect-oauth|csrf-oauth|null"
> }
> ```
>
> The merge step (Phase 3) will consolidate per-batch JSON contributions into the final `sast/oauth-results.json`. If your batch has no findings, still contribute `{ "findings": [] }`.

### Phase 3: Merge — Consolidate Batch Results

After **all** Phase 2 batch subagents complete, read every `sast/oauth-batch-*.md` and `sast/oauth-batch-*.json` file and merge them into a single human-readable report and a single canonical JSON file.

**Merge procedure**:

1. Read all `sast/oauth-batch-1.md`, `sast/oauth-batch-2.md`, ... files.
2. Collect all findings from each batch file and combine them into one list, preserving the original classification and every detail field.
3. Count totals across all batches for the executive summary.
4. Write the merged report to `sast/oauth-results.md` using the format in the **Findings** section below.
5. Consolidate all `sast/oauth-batch-*.json` files into a single `sast/oauth-results.json` as `{ "findings": [...] }`. Map classifications to severities: VULNERABLE → critical/high/medium per severity assigned; LIKELY VULNERABLE → medium or low; NEEDS MANUAL REVIEW → info. NOT VULNERABLE findings are not emitted to JSON. If no findings exist, still write `{ "findings": [] }` so the aggregator can confirm the scan ran.
6. After writing `sast/oauth-results.md` and `sast/oauth-results.json`, **delete all intermediate files**: `sast/oauth-recon.md`, `sast/oauth-batch-*.md`, and `sast/oauth-batch-*.json`.

---

## Findings

Final human-readable report template for `sast/oauth-results.md`:

```markdown
# OAuth / OIDC Analysis Results: [Project Name]

## Executive Summary
- Flows analyzed: [total across all batches]
- Vulnerable: [N]
- Likely Vulnerable: [N]
- Not Vulnerable: [N]
- Needs Manual Review: [N]
- OAuth library: [name + version]
- Client type: [confidential / public / mixed]

## Sub-Class Summary
| Sub-class | Count |
|---|---|
| Unvalidated redirect_uri | N |
| Missing state (OAuth callback CSRF) | N |
| Missing PKCE | N |
| Implicit grant | N |
| Missing nonce (OIDC) | N |

## Findings

[All findings from all batches, grouped by classification:
 VULNERABLE first (sorted by sub-class: unvalidated redirect_uri > missing state > implicit grant > missing PKCE > missing nonce),
 then LIKELY VULNERABLE,
 then NEEDS MANUAL REVIEW,
 then NOT VULNERABLE.
 Preserve every field from the batch results exactly as written.]
```

The canonical `sast/oauth-results.json` is emitted alongside, matching the project schema defined in `sast-files/CLAUDE.md`.

---

## Chain IDs

The following `chain_id` values are used by this skill. Findings from other skills that share a `chain_id` compose into a single multi-step attack chain:

| chain_id | This skill's finding | Companion skill | Composed attack |
|---|---|---|---|
| `open-redirect-oauth` | Unvalidated `redirect_uri` used to intercept auth code | `sast-openredirect` | The same URI-validation gap enables a general open redirect on non-OAuth pages — attacker gets both code interception and a phishing redirect |
| `csrf-oauth` | Missing or unverified `state` on OAuth callback | `sast-csrf` | The OAuth callback route also lacks standard CSRF protection — both attack paths exploit the same absent origin check on the callback |

---

## Important Reminders

- Read `sast/architecture.md` and pass its content to all subagents as context.
- Phase 2 must run AFTER Phase 1 completes — it depends on the recon output.
- Phase 3 must run AFTER all Phase 2 batches complete — it depends on all batch outputs.
- Batch size is **3 flows per subagent**. If there are 1–3 flows total, use a single subagent. If there are 10, use 4 subagents (3+3+3+1).
- Launch all batch subagents **in parallel** — do not run them sequentially.
- Each batch subagent receives only its assigned flows' text from the recon file, not the entire recon file.
- Client-credentials flows (machine-to-machine, no user agent, no redirect) are **out of scope** — do not flag them.
- A `state` value present in the authorization URL but never compared on the callback is just as bad as no `state` at all. The comparison step is the critical control.
- PKCE severity depends on client type: `high` for public clients (SPA, mobile, CLI); `medium` for confidential clients where the client secret is the primary protection.
- `response_type=code id_token` (OIDC hybrid) with a `nonce` is generally acceptable; without a `nonce`, the `id_token` in the fragment is a replay risk.
- Substring or prefix `redirect_uri` matches (`startsWith`, `match`, `includes`) are bypassable — require exact-match set membership.
- Library defaults (Passport `state:true`, authlib `code_challenge_method`, django-allauth >=0.47, Spring Security default) are protective only if they are not overridden by a local configuration or a version too old to enforce them. Always check the library version when it is available.
- OmniAuth `allowed_request_methods` including `:get` is a CSRF risk on the callback route — equivalent to missing state.
- `SOCIAL_AUTH_ALLOWED_REDIRECT_HOSTS = []` in django-social-auth performs no validation — flag it.
- When in doubt, classify as "Needs Manual Review" rather than "Not Vulnerable". False negatives in auth flows are high-impact.
- Clean up intermediate files: delete `sast/oauth-recon.md`, all `sast/oauth-batch-*.md`, and all `sast/oauth-batch-*.json` files after the final `sast/oauth-results.md` and `sast/oauth-results.json` are written.
