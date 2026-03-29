# Self-Hosted OAuth 2.0 & OpenID Connect — Complete Mastery Guide

This directory contains a fully working self-hosted OAuth 2.0 Authorization Server built in Go, along with four client applications that demonstrate every major OAuth flow. Reading this document from top to bottom — and running the code — will give you a complete mental model of how identity and authorization work on the internet.

---

## Table of Contents

1. [The Core Insight — Protocol vs Product](#1-the-core-insight--protocol-vs-product)
2. [OAuth 2.0 and OpenID Connect — What They Actually Are](#2-oauth-20-and-openid-connect--what-they-actually-are)
3. [The Provider Landscape — Who Are the "Speakers"](#3-the-provider-landscape--who-are-the-speakers)
4. [Self-Hosted vs External Providers — The Real Difference](#4-self-hosted-vs-external-providers--the-real-difference)
5. [When to Self-Host vs Use a Provider](#5-when-to-self-host-vs-use-a-provider)
6. [The Four OAuth 2.0 Flows](#6-the-four-oauth-20-flows)
   - [6.1 Authorization Code + PKCE — Browser & Mobile](#61-authorization-code--pkce--browser--mobile)
   - [6.2 Client Credentials — Machine to Machine](#62-client-credentials--machine-to-machine)
   - [6.3 Device Authorization — CLI & Smart TVs](#63-device-authorization--cli--smart-tvs)
   - [6.4 Refresh Token — Staying Logged In](#64-refresh-token--staying-logged-in)
7. [This Implementation — Architecture](#7-this-implementation--architecture)
8. [Deep Dive: The Auth Server](#8-deep-dive-the-auth-server)
   - [8.1 RSA Keys and JWT Signing](#81-rsa-keys-and-jwt-signing)
   - [8.2 OIDC Discovery](#82-oidc-discovery)
   - [8.3 The Token Endpoint — One Endpoint, Four Flows](#83-the-token-endpoint--one-endpoint-four-flows)
   - [8.4 PKCE Verification](#84-pkce-verification)
   - [8.5 Token Audience Separation](#85-token-audience-separation)
9. [Deep Dive: The Clients](#9-deep-dive-the-clients)
   - [9.1 Web App — Authorization Code + PKCE](#91-web-app--authorization-code--pkce)
   - [9.2 Transaction API — Token Validation](#92-transaction-api--token-validation)
   - [9.3 Cron Job — Client Credentials](#93-cron-job--client-credentials)
   - [9.4 CLI Tool — Device Flow](#94-cli-tool--device-flow)
10. [How to Run Everything](#10-how-to-run-everything)
11. [What Makes This Different from Google/Okta](#11-what-makes-this-different-from-googleokta)
12. [Production Checklist](#12-production-checklist)
13. [Further Mastery Path](#13-further-mastery-path)

---

## 1. The Core Insight — Protocol vs Product

The single most important thing to understand about OAuth 2.0 and OpenID Connect is this:

**They are protocols (languages), not products. Providers are just speakers of those languages.**

When your app talks to Google for "Sign in with Google", it is speaking the OAuth 2.0 + OIDC protocol. When it talks to Microsoft, GitHub, or your own Keycloak server, it speaks the exact same protocol. The only thing that changes is the URL.

```
Your Go app:
  "Hello, I'd like to authenticate a user. Here is my client_id
   and a PKCE challenge. Please redirect the user back to me with
   an authorization code."

Google: "Sure. Here is the code."
GitHub: "Sure. Here is the code."
Your Keycloak: "Sure. Here is the code."
This auth server (localhost:9000): "Sure. Here is the code."

Your Go app: "Thank you. Here is the code and the PKCE verifier.
              Please give me the tokens."

All of the above: "Here are your tokens."
```

This is why swapping Google for your own server requires changing **two strings** in your Go code — the discovery URL and the client credentials. Everything else is identical.

```go
// Before (Google):
provider, _ := oidc.NewProvider(ctx, "https://accounts.google.com")
oauth2Config := &oauth2.Config{ClientID: "...google-id...", ClientSecret: "..."}

// After (self-hosted):
provider, _ := oidc.NewProvider(ctx, "http://localhost:9000")
oauth2Config := &oauth2.Config{ClientID: "web-app", ClientSecret: "webapp-secret"}

// The rest of your code — PKCE, state, token exchange, session management — is unchanged.
```

---

## 2. OAuth 2.0 and OpenID Connect — What They Actually Are

These two protocols are often confused because they are always used together. They solve different problems.

### OAuth 2.0 — "Can I access your stuff?"

OAuth 2.0 ([RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749)) is an **authorization** framework. It answers the question:

> "Can this application access these resources on behalf of this user?"

The result is an **Access Token** — a credential that proves a user authorized an app to do something specific. The access token tells a resource server (like the Google Drive API, or our Transaction API) "this app is allowed to do X for user Y."

**Crucially: an access token alone does not tell you who the user is.** It only tells you what was authorized.

### OpenID Connect — "Who is this person?"

OpenID Connect ([OIDC Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)) is an **authentication** layer built on top of OAuth 2.0. It adds one thing: an **ID Token** — a signed JWT that cryptographically proves the user's identity.

```
OAuth 2.0 alone:
  Someone authorized this app to read their Drive files.
  (We don't know who "someone" is from the token alone.)

OAuth 2.0 + OIDC:
  bob@gmail.com (ID: 1234567) authorized this app to read their Drive files.
  (The ID token proves the identity; the access token proves the authorization.)
```

### The Three Tokens and Their Roles

| Token | Format | Purpose | Audience | Lifetime |
|---|---|---|---|---|
| **Authorization Code** | Opaque string | One-time-use; exchanged for real tokens | Your server only | 60 seconds |
| **Access Token** | Signed JWT | Prove authorization to a resource server | The resource server (e.g. transaction-api) | ~1 hour |
| **ID Token** | Signed JWT | Prove user identity to the client app | The client app (e.g. web-app) | ~1 hour |
| **Refresh Token** | Opaque string | Get new access tokens without re-login | The authorization server | Days to weeks |

**The audience separation is critical and often misunderstood:**
- Access tokens have `aud: "transaction-api"` — they're for the resource server
- ID tokens have `aud: "web-app"` — they're for your app to read the user's identity
- Using an ID token to authorize API calls (or vice versa) is a security mistake

---

## 3. The Provider Landscape — Who Are the "Speakers"

Because OAuth 2.0 and OIDC are open standards, virtually every major technology platform implements them. Your Go code can talk to all of them using the same pattern.

### Social Identity Providers

| Provider | Discovery URL | What you can do with scopes |
|---|---|---|
| Google | `https://accounts.google.com` | Read Gmail, Drive, Calendar |
| Microsoft / Entra ID | `https://login.microsoftonline.com/{tenant}/v2.0` | Read Outlook, Teams, SharePoint |
| Apple | `https://appleid.apple.com` | Identity only |
| Facebook | *(custom endpoint — predates OIDC)* | Profile, friends |
| LinkedIn | *(custom endpoint)* | Profile, connections |

### Developer Platforms

| Provider | Notes |
|---|---|
| GitHub | Uses OAuth 2.0 but not OIDC (predates the standard). Use the `github` endpoint package. |
| GitLab | Full OIDC support |
| Bitbucket | OAuth 2.0 with limited OIDC |

### Enterprise Identity Providers

| Provider | Discovery URL | Strength |
|---|---|---|
| Okta | `https://{domain}.okta.com` | Enterprise SSO, MFA policies |
| Auth0 | `https://{domain}.auth0.com` | Easy setup, many integrations |
| AWS Cognito | `https://cognito-idp.{region}.amazonaws.com/{pool-id}` | AWS-native |
| Ping Identity | `https://{domain}.pingone.com` | Large enterprise |

### Self-Hosted Open Source Servers

| Software | Language | Strength |
|---|---|---|
| **Ory Hydra** | Go | Headless, just the protocol — you build the login UI |
| **Keycloak** | Java | Full-featured, built-in admin UI, user management |
| **Dex** | Go | Lightweight, great for Kubernetes/LDAP federation |
| **HashiCorp Vault** | Go | Secrets management + OIDC provider for machine auth |
| **This implementation** | Go | Educational — shows exactly how it works inside |

---

## 4. Self-Hosted vs External Providers — The Real Difference

This is the most important conceptual distinction in this entire document.

### External Provider Model (e.g. "Login with Google")

```
┌────────────────────────────────────────────────────────────────────┐
│  Who owns the user?                                                │
│                                                                    │
│  Google owns:                                                      │
│    - The username and password                                     │
│    - The user database                                             │
│    - The identity verification                                     │
│    - The MFA policy                                                │
│                                                                    │
│  You own:                                                          │
│    - The application and its data                                  │
│    - The user's profile within your app                            │
│    - The access token (temporarily)                                │
│                                                                    │
│  Bob must have a Google account.                                   │
│  If Google is down, your login is down.                            │
│  If Google changes their API, your login may break.                │
└────────────────────────────────────────────────────────────────────┘
```

### Self-Hosted Model (Keycloak / This Server)

```
┌────────────────────────────────────────────────────────────────────┐
│  Who owns the user?                                                │
│                                                                    │
│  YOU own everything:                                               │
│    - The username and password (hashed in your database)           │
│    - The user database (on your infrastructure)                    │
│    - The identity verification logic                               │
│    - The MFA policy                                                │
│    - The session policy                                            │
│    - The private key that signs all tokens                         │
│                                                                    │
│  Bob has an account in YOUR database. No Google account needed.    │
│  If your auth server is down, your login is down — but it's        │
│  YOUR server, so you control the uptime and the fix.               │
│  You are not dependent on any third party for authentication.      │
└────────────────────────────────────────────────────────────────────┘
```

### The Hybrid Model — Self-Hosted That Also Talks to Google

This is the most powerful real-world setup. Keycloak (or your own server) acts as a **federation layer**:

```
                    ┌──────────────────────────────────┐
                    │       YOUR Auth Server           │
                    │       auth.yourdomain.com        │
                    │                                  │
                    │  Local users: bob, alice, admin  │
                    │  Also federates: Google, GitHub  │
                    └───────────────┬──────────────────┘
                                    │ Issues tokens to everyone
                                    │
         ┌──────────────────────────┼──────────────────────────┐
         │                          │                          │
         ▼                          ▼                          ▼
   Bob logs in with          Alice logs in            Charlie logs in
   username/password         "via Google"             via company LDAP
   (your DB)                 (your server talks       (your server talks
                              to Google; your          to LDAP; your
                              apps never do)           apps never do)
```

**Your applications only ever talk to your auth server.** The federation with Google, GitHub, or LDAP is an internal detail of your auth server. This gives you:
- One consistent token format for all your services
- One place to add/remove users
- One place to change MFA policy
- Ability to merge accounts (same person via different providers)

---

## 5. When to Self-Host vs Use a Provider

### Use an External Provider When:

- Your users already have Google/GitHub/Microsoft accounts and expect "Login with X"
- You are building a consumer app and don't want to manage passwords
- You need to access Google/GitHub APIs (you need their tokens specifically)
- You want the fastest possible time to a working login
- You are comfortable with vendor dependency for authentication

### Self-Host When:

- **Data sovereignty**: user data must not leave your infrastructure (healthcare, finance, government)
- **No internet dependency**: your app runs in air-gapped or private networks
- **Custom authentication**: smart cards, hardware tokens, biometrics, custom MFA
- **Enterprise SSO**: you need to integrate with company LDAP/Active Directory
- **Multi-tenant**: you are building a platform where each customer brings their own IdP
- **Compliance**: GDPR, HIPAA, SOC 2 require knowing exactly where user data is stored
- **Cost at scale**: at millions of users, per-MAU pricing of Auth0/Okta becomes significant

### Use Both (Federated Self-Hosted) When:

- You need "Login with Google" AND local accounts AND enterprise SSO
- You want a single token format for all your internal services
- You want to add/change external providers without touching your apps

---

## 6. The Four OAuth 2.0 Flows

A "flow" is just a sequence of HTTP requests. The protocol defines four main flows for different scenarios. All four are implemented in this project.

---

### 6.1 Authorization Code + PKCE — Browser & Mobile

**When to use:** A human user is present at a browser or mobile app.

**Files:** `webapp/main.go` ← client | `authserver/main.go` ← server

This is the most common and most secure flow for user-facing applications. PKCE (Proof Key for Code Exchange) is now required for all clients, including confidential web apps.

```
Browser              Your Go Server (webapp)           Auth Server (:9000)
   |                          |                                |
   | GET /login               |                               |
   |─────────────────────────►|                               |
   |                          |                               |
   |                          | 1. Generate PKCE verifier     |
   |                          |    verifier = randomBytes(32) |
   |                          |    challenge = SHA256(verifier)|
   |                          |                               |
   |                          | 2. Generate state (CSRF)      |
   |                          |    state = randomBytes(32)    |
   |                          |                               |
   |                          | 3. Store both in HttpOnly     |
   |                          |    cookies (5 min TTL)        |
   |                          |                               |
   | 302 → /authorize         |                               |
   |   ?client_id=web-app     |                               |
   |   &code_challenge=HASH   |                               |
   |   &state=RANDOM          |                               |
   |   &scope=openid+profile  |                               |
   |◄─────────────────────────|                               |
   |                          |                               |
   | GET /authorize?...       |                               |
   |─────────────────────────────────────────────────────────►|
   |                          |                               |
   |         ← auth server shows login form →                 |
   |                          |                               |
   | POST /authorize (form)   |                               |
   |   username=bob           |                               |
   |   password=password123   |                               |
   |─────────────────────────────────────────────────────────►|
   |                          |                               |
   |                          |       auth server validates   |
   |                          |       credentials, creates    |
   |                          |       AuthCode (60s TTL)      |
   |                          |                               |
   | 302 → /callback          |                               |
   |   ?code=AUTHCODE         |                               |
   |   &state=RANDOM          |                               |
   |◄─────────────────────────────────────────────────────────|
   |                          |                               |
   | GET /callback?code=...   |                               |
   |─────────────────────────►|                               |
   |                          |                               |
   |                          | 4. Verify state cookie ✓     |
   |                          | 5. Retrieve verifier cookie  |
   |                          |                               |
   |                          | POST /token (back-channel)   |
   |                          |   grant_type=authorization_code
   |                          |   code=AUTHCODE              |
   |                          |   code_verifier=RAW_SECRET   |
   |                          |   client_secret=webapp-secret|
   |                          |──────────────────────────────►|
   |                          |                               |
   |                          |       auth server verifies:  |
   |                          |       PKCE challenge ✓       |
   |                          |       code not expired ✓     |
   |                          |       client_secret ✓        |
   |                          |                               |
   |                          |   access_token (aud=txn-api) |
   |                          |   id_token (aud=web-app)     |
   |                          |   refresh_token              |
   |                          |◄──────────────────────────────|
   |                          |                               |
   |                          | 6. Verify ID token signature |
   |                          |    check iss, aud, exp ✓     |
   |                          | 7. Extract claims (sub, email)|
   |                          | 8. Create server-side session|
   |                          |                               |
   | Set-Cookie: session_id=X |                               |
   | 302 → /profile           |                               |
   |◄─────────────────────────|                               |
```

**Why PKCE matters:** The authorization code appears in the browser URL (visible in history, logs, referrer headers). An attacker who steals the code cannot exchange it — they don't have the `code_verifier` which was stored in an HttpOnly cookie and never transmitted in a URL.

---

### 6.2 Client Credentials — Machine to Machine

**When to use:** Two servers communicate with no human involved (cron jobs, microservices, background workers).

**Files:** `cronjob/main.go` ← client | `authserver/main.go` ← server

There is no browser, no user, no redirect. The service authenticates using its own Client ID and Secret — like a service account password.

```
Cron Job Server                    Auth Server (:9000)         Transaction API (:9001)
      |                                    |                            |
      | POST /token                        |                            |
      |   grant_type=client_credentials    |                            |
      |   client_id=cron-job-service       |                            |
      |   client_secret=cronjob-secret     |                            |
      |   scope=transactions:read          |                            |
      |───────────────────────────────────►|                            |
      |                                    |                            |
      |                                    | Verify secret ✓           |
      |                                    | Check scope allowed ✓     |
      |                                    | sub = client_id (no user) |
      |                                    | No id_token (no user)     |
      |                                    | No refresh_token          |
      |                                    |                            |
      |   access_token                     |                            |
      |◄───────────────────────────────────|                            |
      |                                    |                            |
      | GET /transactions                  |                            |
      |   Authorization: Bearer TOKEN      |                            |
      |────────────────────────────────────────────────────────────────►|
      |                                    |                            |
      |                                    |   Verify token signature  |
      |                                    |   (no auth server call)   |
      |                                    |   Check scope ✓           |
      |                                    |   email="" → service token|
      |                                    |                            |
      |   { caller_type: "service", ... }  |                            |
      |◄────────────────────────────────────────────────────────────────|
```

**Key differences from user login:**
- `sub` claim = the client's own ID (`"cron-job-service"`), not a user ID
- No `id_token` — there's no user identity to assert
- No `refresh_token` — when the access token expires, simply call `/token` again
- The transaction API's `caller_type` field will show `"service"` (no `email` claim)

---

### 6.3 Device Authorization — CLI & Smart TVs

**When to use:** The device cannot open a browser or receive a redirect (CLI tools, smart TVs, game consoles, IoT devices).

**Files:** `cli/main.go` ← client | `authserver/main.go` ← server

The flow delegates the authentication step to a different device (the user's phone or laptop).

```
CLI Tool (:terminal)               Auth Server (:9000)          User's Browser
      |                                    |                            |
      | POST /device/code                  |                            |
      |   client_id=cli-tool               |                            |
      |   scope=openid profile             |                            |
      |───────────────────────────────────►|                            |
      |                                    |                            |
      |   device_code=LONGOPAQUE           |                            |
      |   user_code=BDFH-JLNP             |                            |
      |   verification_uri=.../device     |                            |
      |   expires_in=600                   |                            |
      |   interval=5                       |                            |
      |◄───────────────────────────────────|                            |
      |                                    |                            |
      | Prints to terminal:                |                            |
      | "Open http://localhost:9000/device |                            |
      |  Enter code: BDFH-JLNP"           |                            |
      |                                    |                            |
      | Poll every 5s:                     |   User opens browser      |
      | POST /token                        |   visits /device          |
      |   grant_type=device_code           |   enters BDFH-JLNP       |
      |   device_code=LONGOPAQUE           |   enters username+password|
      |   client_id=cli-tool               |   clicks "Approve"        |
      |───────────────────────────────────►|◄──────────────────────────|
      | 400 authorization_pending          |                            |
      |◄───────────────────────────────────|   Auth server sets        |
      |                                    |   DeviceCode.Approved=true|
      |                                    |   UserID=user.ID          |
      |                                    |                            |
      | Poll again:                        |                            |
      | POST /token (same)                 |                            |
      |───────────────────────────────────►|                            |
      |                                    |                            |
      |   200 access_token                 |                            |
      |   refresh_token                    |                            |
      |   id_token                         |                            |
      |◄───────────────────────────────────|                            |
      |                                    |                            |
      | Calls Transaction API with token   |                            |
```

**The shared pointer trick:** In `authserver/main.go`, the same `*DeviceCode` struct is stored in two maps: `deviceCodes[device_code]` and `userCodes[user_code]`. When the browser handler sets `dc.Approved = true`, the polling handler sees the update immediately — they point to the same struct in memory. No channel or callback needed.

```go
// Both maps hold the same pointer:
s.deviceCodes[dc.DeviceCode] = dc
s.userCodes[dc.UserCode] = dc  // same *DeviceCode

// Browser handler (in /device/verify POST):
dc.UserID = user.ID
dc.Approved = true             // polling handler sees this immediately

// Polling handler (in /token with grant_type=device_code):
if dc.Approved { /* issue tokens */ }
```

---

### 6.4 Refresh Token — Staying Logged In

**When to use:** After any flow that issued a refresh token (Auth Code, Device Flow). Runs automatically in the background when the access token expires.

```
Your Server / CLI                  Auth Server (:9000)
      |                                    |
      | (Access token expired after 1hr)   |
      |                                    |
      | POST /token                        |
      |   grant_type=refresh_token         |
      |   refresh_token=STORED_OPAQUE      |
      |   client_id=web-app                |
      |   client_secret=webapp-secret      |
      |───────────────────────────────────►|
      |                                    |
      |                                    | Validate refresh token ✓ |
      |                                    | Issue new access token   |
      |                                    |                          |
      |   new access_token                 |
      |◄───────────────────────────────────|
```

In the webapp, this happens **completely transparently** via `oauth2.TokenSource`:

```go
// In handleCallback — created once per session:
tokenSource := a.oauth2Config.TokenSource(context.Background(), token)
// Stores the token AND the refresh_token internally.

// In handleDrive — just use the client:
client := oauth2.NewClient(r.Context(), sess.TokenSource)
resp, _ := client.Get("http://localhost:9001/transactions")
// If access token is expired, TokenSource calls /token with refresh_token automatically.
// The handler has no idea a refresh happened.
```

**Why Client Credentials doesn't use refresh tokens:** Services can call `/token` any time. There's no "session" to maintain across requests. When the access token expires, the cron job just calls `/token` again with its client_secret. It's simpler and the secret never changes.

---

## 7. This Implementation — Architecture

```
┌────────────────────────────────────────────────────────────────────────┐
│                    AUTH SERVER  :9000                                  │
│                    authserver/main.go                                  │
│                                                                        │
│  ┌─────────────┐  ┌──────────────────┐  ┌──────────────────────────┐  │
│  │  Users DB   │  │  Clients DB      │  │  RSA-2048 Key Pair       │  │
│  │  (in-memory)│  │  (in-memory)     │  │  Generated on startup    │  │
│  │             │  │                  │  │  Private → signs JWTs    │  │
│  │  bob        │  │  web-app         │  │  Public  → at /jwks      │  │
│  │  alice      │  │  mobile-app      │  │  (anyone can verify)     │  │
│  └─────────────┘  │  cron-job-service│  └──────────────────────────┘  │
│                   │  cli-tool        │                                 │
│                   └──────────────────┘                                 │
│                                                                        │
│  Endpoints:                                                            │
│  /.well-known/openid-configuration  ← OIDC Discovery                  │
│  /jwks                              ← Public keys                      │
│  /authorize  (GET+POST)             ← Login form + code issuance      │
│  /token      (POST)                 ← All four grant types             │
│  /device/code (POST)                ← Start device flow               │
│  /device     (GET+POST)             ← User enters code + approves     │
└───────────────────────────┬────────────────────────────────────────────┘
                            │ Issues tokens to all clients
                            │ (only called to ISSUE tokens)
    ┌───────────────────────┼──────────────────────────────────────────┐
    │                       │                                          │
    ▼                       ▼                                          ▼
┌───────────┐       ┌───────────────┐                          ┌──────────────┐
│  webapp   │       │  cronjob      │                          │  cli         │
│  :8080    │       │  (exits)      │                          │  (exits)     │
│           │       │               │                          │              │
│  Auth Code│       │  Client Creds │                          │  Device Flow │
│  + PKCE   │       │  No user      │                          │  Polls /token│
│  + session│       │  No browser   │                          │  User uses   │
│  store    │       │               │                          │  browser     │
└─────┬─────┘       └──────┬────────┘                          └──────┬───────┘
      │                    │                                          │
      └────────────────────┴──────────────────────────────────────────┘
                           │ Call with Bearer token
                           ▼
              ┌────────────────────────────┐
              │  TRANSACTION API  :9001    │
              │  transactionapi/main.go    │
              │                            │
              │  Validates tokens LOCALLY  │
              │  (fetches JWKS once on     │
              │   startup; no auth server  │
              │   call per request)        │
              │                            │
              │  Checks:                   │
              │  - RSA signature ✓         │
              │  - iss == :9000 ✓          │
              │  - aud == transaction-api ✓│
              │  - exp in future ✓         │
              │  - scope contains read ✓   │
              └────────────────────────────┘
```

---

## 8. Deep Dive: The Auth Server

### 8.1 RSA Keys and JWT Signing

Every JWT issued by this server is signed with an RSA-2048 private key generated fresh on startup.

```go
// On startup:
privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
// privateKey.PublicKey is exposed at /jwks
// privateKey is used in every signJWT call
```

JWT signing is implemented manually to show exactly what happens inside libraries like `go-jose`:

```go
func (s *server) signJWT(claims map[string]interface{}) (string, error) {
    // 1. Encode header: {"alg":"RS256","typ":"JWT","kid":"key-1"}
    header := map[string]interface{}{"alg": "RS256", "typ": "JWT", "kid": s.keyID}
    headerJSON, _ := json.Marshal(header)
    headerEnc := base64.RawURLEncoding.EncodeToString(headerJSON)

    // 2. Encode payload: the claims map as JSON
    claimsJSON, _ := json.Marshal(claims)
    claimsEnc := base64.RawURLEncoding.EncodeToString(claimsJSON)

    // 3. signingInput = "base64url(header).base64url(payload)"
    sigInput := headerEnc + "." + claimsEnc

    // 4. Sign: RSA-SHA256(signingInput, privateKey)
    h := crypto.SHA256.New()
    h.Write([]byte(sigInput))
    digest := h.Sum(nil)
    sig, _ := rsa.SignPKCS1v15(rand.Reader, s.privateKey, crypto.SHA256, digest)

    // 5. JWT = "header.payload.signature" (all base64url)
    return sigInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}
```

**Why RSA instead of HMAC (HS256)?** With HMAC, the same key is used to sign and verify — every service that needs to verify tokens would need the secret key, creating a large attack surface. With RSA, the private key stays on the auth server and only the public key (at `/jwks`) is distributed. Compromise of any resource server does not compromise the private key.

### 8.2 OIDC Discovery

The discovery endpoint is what `oidc.NewProvider()` calls on startup in every client application.

```go
// Any client (webapp, transactionapi):
provider, _ := oidc.NewProvider(ctx, "http://localhost:9000")
// This fetches: GET http://localhost:9000/.well-known/openid-configuration
```

Our server responds with:

```json
{
  "issuer": "http://localhost:9000",
  "authorization_endpoint": "http://localhost:9000/authorize",
  "token_endpoint": "http://localhost:9000/token",
  "jwks_uri": "http://localhost:9000/jwks",
  "device_authorization_endpoint": "http://localhost:9000/device/code",
  "grant_types_supported": [
    "authorization_code",
    "client_credentials",
    "refresh_token",
    "urn:ietf:params:oauth:grant-type:device_code"
  ],
  "id_token_signing_alg_values_supported": ["RS256"],
  "code_challenge_methods_supported": ["S256", "plain"]
}
```

`go-oidc` validates that `issuer` in this document exactly matches the URL passed to `NewProvider`. This prevents a server from claiming to be a different issuer.

### 8.3 The Token Endpoint — One Endpoint, Four Flows

All four grant types go through the same `POST /token` endpoint. The server reads `grant_type` and routes:

```go
func (s *server) handleToken(w http.ResponseWriter, r *http.Request) {
    r.ParseForm()
    w.Header().Set("Cache-Control", "no-store") // tokens must never be cached

    switch r.FormValue("grant_type") {
    case "authorization_code":
        s.handleAuthCodeGrant(w, r)
    case "client_credentials":
        s.handleClientCredentialsGrant(w, r)
    case "refresh_token":
        s.handleRefreshTokenGrant(w, r)
    case "urn:ietf:params:oauth:grant-type:device_code":
        s.handleDeviceCodeGrant(w, r)
    default:
        jsonError(w, "unsupported_grant_type", http.StatusBadRequest)
    }
}
```

`Cache-Control: no-store` is required by RFC 6749 §5.1 — token responses must never be stored in any cache (HTTP cache, browser cache, CDN).

### 8.4 PKCE Verification

PKCE verification happens during the `authorization_code` grant:

```go
func verifyCodeChallenge(verifier, challenge, method string) bool {
    switch method {
    case "S256":
        // Recompute what was sent at authorization time:
        // base64url(SHA-256(verifier))
        h := sha256.Sum256([]byte(verifier))
        return base64.RawURLEncoding.EncodeToString(h[:]) == challenge
    case "plain":
        return verifier == challenge
    }
    return false
}
```

The sequence:
1. Client generates `verifier = randomBytes(32)` → sends `challenge = SHA256(verifier)` to `/authorize`
2. Auth server stores `challenge` in the `AuthCode`
3. Client sends `verifier` to `/token`
4. Auth server recomputes `SHA256(verifier)` and compares to stored `challenge`
5. If they match: the same client that started the flow is completing it

An attacker who intercepts the authorization code does not have the verifier (stored in an HttpOnly cookie on the legitimate client). The token exchange fails for them.

### 8.5 Token Audience Separation

This is a subtle but critical design decision. We issue two separate JWTs:

```go
// Access token — for calling resource servers:
func (s *server) makeAccessToken(userID, clientID string, scopes []string, audience string) {
    claims := map[string]interface{}{
        "iss":       s.issuer,
        "sub":       userID,              // user ID or client ID for service tokens
        "aud":       []string{audience},  // "transaction-api"
        "exp":       now.Add(time.Hour).Unix(),
        "scope":     strings.Join(scopes, " "),
        "client_id": clientID,
        // email included only for user tokens
    }
}

// ID token — for the client to learn the user's identity:
func (s *server) makeIDToken(user *User, clientID string) {
    claims := map[string]interface{}{
        "iss": s.issuer,
        "sub": user.ID,
        "aud": []string{clientID},   // "web-app" — the CLIENT, not the resource server
        "exp": now.Add(time.Hour).Unix(),
        "email": user.Email,
        "name":  user.Name,
        "roles": user.Roles,
    }
}
```

**Why different audiences?**

If the transaction API accepted ID tokens:
- A malicious app could request an ID token from the auth server
- Forward it to the transaction API pretending to be an access token
- The transaction API would accept it (same signature, same issuer)

The audience claim prevents this. The transaction API's verifier is configured with `ClientID: "transaction-api"` — it rejects tokens with `aud: "web-app"` even though they're from the same issuer and have valid signatures.

---

## 9. Deep Dive: The Clients

### 9.1 Web App — Authorization Code + PKCE

`webapp/main.go` is structurally identical to the parent project's `main.go`. The only difference is the provider URL and client credentials. This proves the "protocol, not product" point.

```go
// Parent project (talks to Google):
provider, _ := oidc.NewProvider(ctx, "https://accounts.google.com")
// ClientID: from Google Cloud Console JSON file

// This webapp (talks to our auth server):
provider, _ := oidc.NewProvider(ctx, "http://localhost:9000")
// ClientID: "web-app", ClientSecret: "webapp-secret"
```

The webapp verifies the **ID token** (to know who the user is) using `ClientID: "web-app"` — the ID token's audience. It stores the **access token** in the session's `TokenSource` for making API calls.

### 9.2 Transaction API — Token Validation

`transactionapi/main.go` validates access tokens without ever calling the auth server at runtime:

```go
// Startup — fetch public key once:
provider, _ := oidc.NewProvider(ctx, "http://localhost:9000")
verifier := provider.Verifier(&oidc.Config{ClientID: "transaction-api"})
// go-oidc fetches /jwks and caches the RSA public key.

// Per request — validate locally:
idToken, err := verifier.Verify(r.Context(), rawToken)
// Checks signature (cached RSA key), iss, aud, exp — NO network call.
```

Distinguishing user tokens from service tokens:

```go
var claims struct {
    Sub      string `json:"sub"`
    Scope    string `json:"scope"`
    ClientID string `json:"client_id"`
    Email    string `json:"email"` // present in user tokens, absent in service tokens
}
idToken.Claims(&claims)

callerType := "service"
if claims.Email != "" {
    callerType = "user"
}
// User token: sub="user-001", email="bob@example.com", client_id="web-app"
// Service token: sub="cron-job-service", email="", client_id="cron-job-service"
```

### 9.3 Cron Job — Client Credentials

`cronjob/main.go` uses `golang.org/x/oauth2/clientcredentials` — three meaningful lines:

```go
config := &clientcredentials.Config{
    ClientID:     "cron-job-service",
    ClientSecret: "cronjob-secret",
    TokenURL:     "http://localhost:9000/token",
    Scopes:       []string{"transactions:read"},
}

// config.Client() returns an *http.Client that:
// 1. Calls /token with grant_type=client_credentials on first use
// 2. Caches the token
// 3. Automatically re-fetches when expired
// 4. Injects Authorization: Bearer <token> into every request
client := config.Client(context.Background())

resp, _ := client.Get("http://localhost:9001/transactions")
// No token management code. No expiry checks. Just call the API.
```

### 9.4 CLI Tool — Device Flow

`cli/main.go` implements device flow polling manually to show the raw wire protocol:

```go
// Step 1: Request device and user codes
resp, _ := http.PostForm("http://localhost:9000/device/code", url.Values{
    "client_id": {"cli-tool"},
    "scope":     {"openid profile transactions:read"},
})
// Returns: device_code, user_code="BDFH-JLNP", verification_uri, interval=5

// Step 2: Print instructions (user does this part on their phone/laptop)
fmt.Printf("Open: %s\nEnter code: %s\n", verificationURI, userCode)

// Step 3: Poll until approved or expired
for {
    time.Sleep(time.Duration(interval) * time.Second)

    resp, _ := http.PostForm("http://localhost:9000/token", url.Values{
        "grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
        "device_code": {deviceCode},
        "client_id":   {"cli-tool"},
    })

    var tokenResp struct {
        AccessToken string `json:"access_token"`
        Error       string `json:"error"`
    }
    json.NewDecoder(resp.Body).Decode(&tokenResp)

    switch tokenResp.Error {
    case "authorization_pending":
        fmt.Println("Waiting...") // keep polling
    case "access_denied":
        log.Fatal("User denied access")
    case "":
        // Success — use tokenResp.AccessToken
        callTransactionAPI(tokenResp.AccessToken)
        return
    }
}
```

---

## 10. How to Run Everything

**Prerequisites:** Go 1.23+. No other dependencies — run `go mod tidy` once.

```bash
cd self-hosted
go mod tidy
```

**Start in this order** (each in a separate terminal):

```bash
# Terminal 1 — Auth Server (must start first)
# webapp and transactionapi do OIDC discovery on startup; auth server must be up
go run ./authserver/

# Terminal 2 — Transaction API
go run ./transactionapi/

# Terminal 3 — Web App (browser login demo)
go run ./webapp/
# Open http://localhost:8080
# Log in with bob/password123 or alice/password123
# Visit /drive to see it call the transaction API

# Terminal 4 — Cron Job (runs once and exits)
go run ./cronjob/
# Gets a token via client_credentials, calls /transactions, prints result

# Terminal 4 — CLI Tool (device flow)
go run ./cli/
# Prints a URL and code → open it in browser → log in → approve
# CLI polls and gets the token, calls /transactions
```

### Pre-seeded Credentials

**Users:**
| Username | Password | Roles |
|---|---|---|
| bob | password123 | user |
| alice | password123 | user, admin |

**Clients:**
| Client ID | Secret | Flow | Port |
|---|---|---|---|
| web-app | webapp-secret | Authorization Code + PKCE | :8080 |
| mobile-app | *(none — public)* | Authorization Code + PKCE | myapp://callback |
| cron-job-service | cronjob-secret | Client Credentials | — |
| cli-tool | *(none — public)* | Device Flow | — |

### What to Look For

**In the auth server logs** when the web app logs in:
```
auth server: new AuthRequest req-xxx for client web-app
auth server: user bob authenticated, code issued
auth server: code exchanged for tokens (auth code grant)
```

**In the transaction API** when the cron job calls it:
```json
{
  "caller_type": "service",
  "caller_sub": "cron-job-service",
  "caller_email": "",
  "caller_client": "cron-job-service",
  "scope": "transactions:read"
}
```

**In the transaction API** when the web app calls it (via /drive):
```json
{
  "caller_type": "user",
  "caller_sub": "user-001",
  "caller_email": "bob@example.com",
  "caller_client": "web-app",
  "scope": "openid profile email transactions:read"
}
```

Same endpoint, same validation code, completely different caller context — that's the power of token-based authorization.

---

## 11. What Makes This Different from Google/Okta

From your app's code perspective: **nothing**. From an infrastructure perspective: everything.

| Aspect | Google/Okta | This Auth Server |
|---|---|---|
| Discovery URL | `https://accounts.google.com` | `http://localhost:9000` |
| Who stores passwords | Google's servers | Your Go process (in-memory) |
| Who generates RSA keys | Google | `rsa.GenerateKey()` on startup |
| Who hosts `/jwks` | Google's CDN | Your server |
| Who shows the login form | Google's branded UI | Your HTML templates |
| Who signs the JWT | Google's HSM | `rsa.SignPKCS1v15()` in your process |
| Token verification | Same (RSA signature check) | Same (RSA signature check) |
| Protocol flow | Identical | Identical |
| Your app code changes | — | Two strings (URL + client creds) |

**The key realization:** When `go-oidc` verifies a token, it does not care whether it came from Google or from your auth server running on `localhost`. It fetches the public key from the `jwks_uri` in the discovery document and verifies the RSA signature. If the math checks out and the claims are valid, the token is accepted. The source of the token is irrelevant to the verification logic.

This is what "open standard" means in practice. The protocol defines the handshake. Anyone who implements the handshake correctly is interoperable.

---

## 12. Production Checklist

This implementation is educational. Here is what a production deployment needs:

| Item | Current State | Production Requirement |
|---|---|---|
| Password storage | Plain text | bcrypt with cost ≥ 12 (`golang.org/x/crypto/bcrypt`) |
| RSA key persistence | Generated fresh on startup (all tokens invalidated on restart) | Load from a secure key store (Vault, KMS, or encrypted file) |
| Session store | In-memory map (lost on restart) | Redis or PostgreSQL |
| User database | In-memory map | PostgreSQL or similar |
| HTTPS | None | Required; set `Secure: true` on all cookies |
| Token revocation | Not implemented | Maintain a revocation list or use short-lived tokens |
| Refresh token rotation | Returns same token | Issue a new refresh token on each use |
| Rate limiting | None | Rate limit `/token` and `/authorize` endpoints |
| Brute force protection | None | Account lockout after N failed attempts |
| CORS | Not configured | Configure for cross-origin requests if needed |
| Structured logging | `log.Printf` | Use `slog` with request IDs |
| Health checks | None | `/health` endpoint for load balancer |
| Token introspection | Not implemented | `POST /introspect` per RFC 7662 |
| PKCE enforcement | Optional for confidential clients | Make mandatory for all clients |
| Key rotation | Not implemented | Rotate signing keys periodically, keep multiple in JWKS |

---

## 13. Further Mastery Path

Having implemented and understood the full stack, here is the natural progression:

**Level 1 — Done (this project)**
- Authorization Code + PKCE (browser)
- Client Credentials (machine-to-machine)
- Device Flow (CLI / TV)
- Refresh tokens
- JWKS and JWT signing
- OIDC Discovery
- Self-hosted auth server

**Level 2 — Next Steps**
- Add a second provider to the webapp (e.g. GitHub alongside local login) — proves provider agnosticism
- Add LDAP/Active Directory federation to the auth server — enterprise login
- Add MFA (TOTP) to the auth server — adds time-based OTP step after password

**Level 3 — Advanced**
- Resource Indicators ([RFC 8707](https://datatracker.ietf.org/doc/html/rfc8707)) — request tokens scoped to a specific resource URL
- Token introspection ([RFC 7662](https://datatracker.ietf.org/doc/html/rfc7662)) — let resource servers validate opaque tokens
- Token exchange ([RFC 8693](https://datatracker.ietf.org/doc/html/rfc8693)) — a service gets a token on behalf of a user ("delegation")
- Dynamic client registration ([RFC 7591](https://datatracker.ietf.org/doc/html/rfc7591)) — clients register themselves programmatically

**Level 4 — Mastery Proof**
Replace this educational auth server with **Ory Hydra** by changing only the discovery URL and client credentials in the four client applications. If everything still works, you have mastered the protocol. The apps don't know or care which server signed the tokens.
