// Package main implements a web application that authenticates users via the
// self-hosted OAuth 2.0 / OIDC authorization server (http://localhost:9000).
//
// Flow:
//  1. User visits / — sees a "Sign In" link if not logged in.
//  2. GET /login     — generates PKCE verifier + state, redirects to auth server.
//  3. GET /callback  — exchanges code for tokens, verifies ID token, creates session.
//  4. GET /profile   — protected: shows identity claims from the ID token.
//  5. GET /drive     — protected: calls the Transaction API using the access token.
//  6. GET /logout    — destroys the server-side session, clears the cookie.
//
// Key design: only an opaque session ID is stored in the browser cookie.
// The access/refresh tokens and all user data live server-side.
package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// ─── Session store ────────────────────────────────────────────────────────────

// Session holds all server-side data for one logged-in user.
// The browser only ever sees an opaque session ID cookie.
type Session struct {
	UserSub   string            // stable unique user identifier (OIDC "sub" claim)
	Email     string
	Name      string
	Picture   string
	CreatedAt time.Time
	// TokenSource transparently refreshes the access token when it expires.
	// Stored server-side so any handler can call APIs without knowing about tokens.
	TokenSource oauth2.TokenSource
}

// SessionStore is a thread-safe in-memory store for sessions.
// In production, replace with Redis / a database so sessions survive restarts
// and can be shared across multiple server instances.
type SessionStore struct {
	mu   sync.RWMutex
	data map[string]*Session
}

func newSessionStore() *SessionStore {
	return &SessionStore{data: make(map[string]*Session)}
}

func (s *SessionStore) Get(id string) (*Session, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sess, ok := s.data[id]
	return sess, ok
}

func (s *SessionStore) Set(id string, sess *Session) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[id] = sess
}

func (s *SessionStore) Delete(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.data, id)
}

// ─── App state ────────────────────────────────────────────────────────────────

// app bundles all the dependencies needed by the HTTP handlers.
type app struct {
	oauth2Config *oauth2.Config
	// verifier validates the ID token returned by the auth server.
	// It checks: signature (JWKS), issuer, audience, and expiry.
	verifier *oidc.IDTokenVerifier
	sessions *SessionStore
}

// ─── Session cookie helpers ───────────────────────────────────────────────────

const sessionCookieName = "session_id"

// getSession reads the session_id cookie and looks up the server-side session.
func (a *app) getSession(r *http.Request) (*Session, string, bool) {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return nil, "", false
	}
	sess, ok := a.sessions.Get(cookie.Value)
	return sess, cookie.Value, ok
}

func (a *app) setSessionCookie(w http.ResponseWriter, sessionID string) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    sessionID,
		MaxAge:   24 * 60 * 60, // 24 hours
		HttpOnly: true,         // not accessible to JavaScript — protects against XSS
		SameSite: http.SameSiteLaxMode,
		Path:     "/",
		// Secure: true, // uncomment in production (requires HTTPS)
	})
}

func (a *app) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:   sessionCookieName,
		MaxAge: -1,
		Path:   "/",
	})
}

// ─── Middleware ───────────────────────────────────────────────────────────────

// requireAuth wraps a handler and redirects unauthenticated users to the home
// page. Protected routes never run their inner logic without a valid session.
func (a *app) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_, _, ok := a.getSession(r)
		if !ok {
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
		next(w, r)
	}
}

// ─── Main ─────────────────────────────────────────────────────────────────────

func main() {
	ctx := context.Background()

	// ── OIDC Discovery ───────────────────────────────────────────────────────
	// go-oidc fetches /.well-known/openid-configuration from the issuer and
	// automatically discovers the authorization, token, and JWKS endpoints.
	// The auth server must be running before this call.
	provider, err := oidc.NewProvider(ctx, "http://localhost:9000")
	if err != nil {
		log.Fatalf("OIDC discovery failed — is the auth server running? %v", err)
	}

	a := &app{
		oauth2Config: &oauth2.Config{
			ClientID:     "web-app",
			ClientSecret: "webapp-secret",
			RedirectURL:  "http://localhost:8080/callback",
			Endpoint:     provider.Endpoint(),
			Scopes:       []string{oidc.ScopeOpenID, "profile", "email", "transactions:read"},
		},
		// Verify the ID token with ClientID="web-app" because our auth server
		// issues ID tokens with aud=["web-app"].
		verifier: provider.Verifier(&oidc.Config{ClientID: "web-app"}),
		sessions: newSessionStore(),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", a.handleHome)
	mux.HandleFunc("/login", a.handleLogin)
	mux.HandleFunc("/callback", a.handleCallback)
	// requireAuth wraps these routes — they only run when a session exists.
	mux.HandleFunc("/profile", a.requireAuth(a.handleProfile))
	mux.HandleFunc("/drive", a.requireAuth(a.handleDrive))
	mux.HandleFunc("/logout", a.handleLogout)

	log.Println("Web app listening on http://localhost:8080")
	log.Println("Auth server must be running at http://localhost:9000")
	log.Println("Transaction API must be running at http://localhost:9001")
	log.Fatal(http.ListenAndServe(":8080", mux))
}

// ─── Handlers ─────────────────────────────────────────────────────────────────

func (a *app) handleHome(w http.ResponseWriter, r *http.Request) {
	sess, _, ok := a.getSession(r)

	data := struct {
		LoggedIn bool
		Email    string
	}{LoggedIn: ok}
	if ok {
		data.Email = sess.Email
	}

	tmpl := `<!DOCTYPE html>
<html>
<head><title>Self-Hosted OAuth 2.0 + OIDC Demo</title>
<style>
  body { font-family: sans-serif; max-width: 600px; margin: 80px auto; padding: 0 1rem; }
  a { color: #4f46e5; }
  .badge { display: inline-block; background: #ecfdf5; color: #065f46;
    padding: .25rem .75rem; border-radius: 9999px; font-size: .875rem; }
</style>
</head>
<body>
  <h1>Self-Hosted OAuth 2.0 &amp; OIDC Demo</h1>
  {{if .LoggedIn}}
    <p><span class="badge">&#10003; Signed in</span> as <strong>{{.Email}}</strong></p>
    <ul>
      <li><a href="/profile">View profile (ID token claims)</a></li>
      <li><a href="/drive">Call Transaction API (access token)</a></li>
      <li><a href="/logout">Sign out</a></li>
    </ul>
  {{else}}
    <p>This demo uses a <strong>self-hosted</strong> authorization server running
    at <code>http://localhost:9000</code>.</p>
    <a href="/login" style="display:inline-block;margin-top:1rem;padding:.75rem 1.5rem;
      background:#4f46e5;color:white;border-radius:4px;text-decoration:none;">
      Sign in with Local Auth Server
    </a>
  {{end}}
</body>
</html>`

	t := template.Must(template.New("").Parse(tmpl))
	if err := t.Execute(w, data); err != nil {
		log.Printf("render home: %v", err)
	}
}

// handleLogin starts the Authorization Code Flow with PKCE + CSRF state.
//
//  1. Generate a PKCE code_verifier (cryptographically random string).
//  2. Compute code_challenge = base64url(SHA-256(verifier)).
//  3. Generate a random CSRF state token.
//  4. Store both in short-lived HttpOnly cookies.
//  5. Redirect to the auth server with the challenge (never the verifier).
//
// PKCE prevents authorization code interception attacks: even if an attacker
// intercepts the code in the redirect URI, they can't exchange it without
// the verifier that was never transmitted over the network.
func (a *app) handleLogin(w http.ResponseWriter, r *http.Request) {
	// oauth2.GenerateVerifier returns a cryptographically random URL-safe string
	// (43 chars = 32 bytes base64url-encoded without padding).
	verifier := oauth2.GenerateVerifier()

	// Store the verifier in a short-lived HttpOnly cookie so handleCallback can
	// retrieve it and send it during the token exchange.
	http.SetCookie(w, &http.Cookie{
		Name:     "pkce_verifier",
		Value:    verifier,
		MaxAge:   300, // 5 minutes — enough time to complete the login
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Path:     "/",
	})

	// Random state token for CSRF protection: prevents an attacker from tricking
	// our callback into processing a response they initiated.
	state, err := randomToken()
	if err != nil {
		http.Error(w, "failed to generate state", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "oauth_state",
		Value:    state,
		MaxAge:   300,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Path:     "/",
	})

	// S256ChallengeOption computes base64url(SHA-256(verifier)) and adds
	// code_challenge and code_challenge_method=S256 to the auth URL.
	// The raw verifier never leaves this server.
	authURL := a.oauth2Config.AuthCodeURL(state,
		oauth2.S256ChallengeOption(verifier),
	)
	http.Redirect(w, r, authURL, http.StatusFound)
}

// handleCallback is the redirect_uri registered with the auth server.
// After the user signs in, the auth server redirects here with:
//
//	?code=<authorization_code>&state=<our_state>
func (a *app) handleCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// ── Step 1: Verify CSRF state ─────────────────────────────────────────────
	stateCookie, err := r.Cookie("oauth_state")
	if err != nil {
		http.Error(w, "missing state cookie", http.StatusBadRequest)
		return
	}
	if r.URL.Query().Get("state") != stateCookie.Value {
		http.Error(w, "state mismatch — possible CSRF attack", http.StatusBadRequest)
		return
	}
	// Consume the state cookie — it's one-time use.
	http.SetCookie(w, &http.Cookie{Name: "oauth_state", MaxAge: -1, Path: "/"})

	// ── Step 2: Retrieve the PKCE verifier ────────────────────────────────────
	verifierCookie, err := r.Cookie("pkce_verifier")
	if err != nil {
		http.Error(w, "missing PKCE verifier cookie", http.StatusBadRequest)
		return
	}
	verifier := verifierCookie.Value
	http.SetCookie(w, &http.Cookie{Name: "pkce_verifier", MaxAge: -1, Path: "/"})

	// ── Step 3: Exchange the authorization code for tokens ────────────────────
	// This is a back-channel (server-to-server) request. The code_verifier is
	// sent here so the auth server can verify it matches the code_challenge from
	// the authorization request.
	code := r.URL.Query().Get("code")
	token, err := a.oauth2Config.Exchange(ctx, code, oauth2.VerifierOption(verifier))
	if err != nil {
		http.Error(w, "token exchange failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// ── Step 4: Verify the ID Token ───────────────────────────────────────────
	// go-oidc checks:
	//   • JWT signature against the auth server's JWKS
	//   • iss == "http://localhost:9000"
	//   • aud == "web-app" (our client_id — prevents tokens for other clients)
	//   • exp is in the future
	//
	// Note: the access token has aud=["transaction-api"] and is NOT verified here.
	// It will be verified by the transaction API when we call it.
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		http.Error(w, "no id_token in response", http.StatusInternalServerError)
		return
	}
	idToken, err := a.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		http.Error(w, "ID token verification failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// ── Step 5: Extract identity claims from the ID token ─────────────────────
	var claims struct {
		Sub     string `json:"sub"`
		Email   string `json:"email"`
		Name    string `json:"name"`
		Picture string `json:"picture"`
	}
	if err := idToken.Claims(&claims); err != nil {
		http.Error(w, "failed to parse ID token claims: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// ── Step 6: Build a TokenSource for automatic token refresh ───────────────
	// oauth2.Config.TokenSource wraps the token in a reuseTokenSource. When the
	// access token expires, calling .Token() automatically uses the refresh token
	// to get a new one (transparent to callers).
	//
	// We use context.Background() — NOT the request context — so the token source
	// remains usable after this HTTP request is done.
	tokenSource := a.oauth2Config.TokenSource(context.Background(), token)

	// ── Step 7: Create server-side session ────────────────────────────────────
	// Only an opaque random ID goes into the browser cookie. All sensitive data
	// (tokens, user info) lives server-side in the session store.
	sessionID, err := randomToken()
	if err != nil {
		http.Error(w, "failed to create session", http.StatusInternalServerError)
		return
	}
	a.sessions.Set(sessionID, &Session{
		UserSub:     claims.Sub,
		Email:       claims.Email,
		Name:        claims.Name,
		Picture:     claims.Picture,
		CreatedAt:   time.Now(),
		TokenSource: tokenSource,
	})

	a.setSessionCookie(w, sessionID)
	http.Redirect(w, r, "/profile", http.StatusFound)
}

// handleProfile shows the user's identity information extracted from the ID token.
// Protected by requireAuth — only reachable with a valid session.
func (a *app) handleProfile(w http.ResponseWriter, r *http.Request) {
	sess, _, _ := a.getSession(r) // requireAuth guarantees this succeeds

	tmpl := `<!DOCTYPE html>
<html>
<head><title>Profile</title>
<style>
  body { font-family: sans-serif; max-width: 600px; margin: 80px auto; padding: 0 1rem; }
  table { border-collapse: collapse; width: 100%; margin-top: 1rem; }
  td { padding: .5rem .75rem; border: 1px solid #e5e7eb; }
  td:first-child { font-weight: bold; background: #f9fafb; width: 30%; }
  a { color: #4f46e5; }
</style>
</head>
<body>
  <h1>Your Profile</h1>
  {{if .Picture}}<img src="{{.Picture}}" width="80" style="border-radius:50%;margin-bottom:1rem;">{{end}}
  <table>
    <tr><td>Name</td><td>{{.Name}}</td></tr>
    <tr><td>Email</td><td>{{.Email}}</td></tr>
    <tr><td>Subject (sub)</td><td style="font-family:monospace;font-size:.85rem;">{{.Sub}}</td></tr>
  </table>
  <p style="margin-top:1.5rem;">
    <a href="/">Home</a> &nbsp;|&nbsp;
    <a href="/drive">Call Transaction API</a> &nbsp;|&nbsp;
    <a href="/logout">Sign out</a>
  </p>
</body>
</html>`

	t := template.Must(template.New("").Parse(tmpl))
	data := struct{ Sub, Name, Email, Picture string }{
		Sub:     sess.UserSub,
		Name:    sess.Name,
		Email:   sess.Email,
		Picture: sess.Picture,
	}
	if err := t.Execute(w, data); err != nil {
		log.Printf("render profile: %v", err)
	}
}

// handleDrive calls the Transaction API using the session's access token.
//
// Key concept: oauth2.NewClient creates an http.Client that automatically
// injects a valid Bearer token into every outbound request. If the access token
// has expired, the TokenSource silently refreshes it using the stored refresh
// token. The handler never touches the token directly.
//
// Note on token audiences:
//   - access_token has aud=["transaction-api"] — accepted by the Transaction API
//   - id_token     has aud=["web-app"]          — verified in handleCallback
//
// These are TWO different JWTs. The Transaction API only ever sees the access token.
func (a *app) handleDrive(w http.ResponseWriter, r *http.Request) {
	sess, _, _ := a.getSession(r) // requireAuth guarantees this succeeds

	// Inject a fresh Bearer token into every request automatically.
	client := oauth2.NewClient(r.Context(), sess.TokenSource)

	resp, err := client.Get("http://localhost:9001/transactions")
	if err != nil {
		http.Error(w, "Transaction API request failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, "failed to read response body", http.StatusInternalServerError)
		return
	}

	// Pretty-print the JSON for display.
	var pretty interface{}
	prettyJSON := string(body)
	if err := json.Unmarshal(body, &pretty); err == nil {
		b, _ := json.MarshalIndent(pretty, "", "  ")
		prettyJSON = string(b)
	}

	tmpl := `<!DOCTYPE html>
<html>
<head><title>Transaction API Response</title>
<style>
  body { font-family: sans-serif; max-width: 700px; margin: 80px auto; padding: 0 1rem; }
  pre { background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 6px;
    padding: 1rem; overflow-x: auto; font-size: .875rem; line-height: 1.5; }
  a { color: #4f46e5; }
  .status { display: inline-block; padding: .25rem .75rem; border-radius: 9999px;
    font-size: .875rem; font-weight: bold; }
  .ok { background: #ecfdf5; color: #065f46; }
  .err { background: #fef2f2; color: #991b1b; }
</style>
</head>
<body>
  <h1>Transaction API Response</h1>
  <p>HTTP Status: <span class="status {{if eq .Status 200}}ok{{else}}err{{end}}">{{.Status}}</span></p>
  <pre>{{.Body}}</pre>
  <p>
    <a href="/profile">Profile</a> &nbsp;|&nbsp;
    <a href="/">Home</a>
  </p>
</body>
</html>`

	t := template.Must(template.New("").Parse(tmpl))
	data := struct {
		Status int
		Body   string
	}{resp.StatusCode, prettyJSON}
	if err := t.Execute(w, data); err != nil {
		log.Printf("render drive: %v", err)
	}
}

func (a *app) handleLogout(w http.ResponseWriter, r *http.Request) {
	_, sessionID, ok := a.getSession(r)
	if ok {
		// Destroy the server-side session so the ID becomes useless.
		a.sessions.Delete(sessionID)
	}
	a.clearSessionCookie(w)
	http.Redirect(w, r, "/", http.StatusFound)
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

// randomToken generates a cryptographically random URL-safe string.
func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("rand.Read: %w", err)
	}
	return base64.URLEncoding.EncodeToString(b), nil
}
