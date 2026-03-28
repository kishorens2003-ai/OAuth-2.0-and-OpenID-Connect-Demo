package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"html/template"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// ─── Credential loading ───────────────────────────────────────────────────────

// googleCredentials mirrors the structure of the client secret JSON downloaded
// from the Google Cloud Console.
type googleCredentials struct {
	Web struct {
		ClientID     string   `json:"client_id"`
		ClientSecret string   `json:"client_secret"`
		RedirectURIs []string `json:"redirect_uris"`
	} `json:"web"`
}

func loadCredentials(path string) googleCredentials {
	data, err := os.ReadFile(path)
	if err != nil {
		log.Fatalf("read credentials: %v", err)
	}
	var creds googleCredentials
	if err := json.Unmarshal(data, &creds); err != nil {
		log.Fatalf("parse credentials: %v", err)
	}
	return creds
}

// ─── Server-side session store ────────────────────────────────────────────────

// Session is the server-side record for one logged-in user.
// The browser only ever holds an opaque session ID — no tokens, no user data.
type Session struct {
	UserSub   string
	Email     string
	Name      string
	Picture   string
	CreatedAt time.Time
	// TokenSource transparently refreshes the access token when it expires.
	// Storing it here means any handler can make authenticated API calls
	// without knowing anything about token lifetimes.
	TokenSource oauth2.TokenSource
}

// SessionStore is a thread-safe in-memory session store.
// In production, replace the map with Redis or a database so sessions survive
// server restarts and can be shared across multiple instances.
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

type app struct {
	oauth2Config *oauth2.Config
	verifier     *oidc.IDTokenVerifier
	sessions     *SessionStore
}

// ─── Session cookie helpers ───────────────────────────────────────────────────

const sessionCookieName = "session_id"

// getSession reads the session ID cookie and looks up the server-side session.
// Returns the session, its ID, and whether it was found.
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
		HttpOnly: true,         // not accessible to JavaScript
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

// requireAuth is a middleware that protects routes. It wraps any HandlerFunc
// and redirects unauthenticated requests to the home page before the inner
// handler ever runs. This means individual handlers don't need auth checks.
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
	creds := loadCredentials("client_secret_827076828039-13ps1mv0pvugacrmelcs17o9u9fa4feg.apps.googleusercontent.com.json")

	ctx := context.Background()

	// ── OIDC Discovery ───────────────────────────────────────────────────────
	// go-oidc fetches /.well-known/openid-configuration from the issuer URL and
	// extracts the authorization, token, and JWKS endpoints automatically.
	provider, err := oidc.NewProvider(ctx, "https://accounts.google.com")
	if err != nil {
		log.Fatalf("OIDC discovery: %v", err)
	}

	a := &app{
		oauth2Config: &oauth2.Config{
			ClientID:     creds.Web.ClientID,
			ClientSecret: creds.Web.ClientSecret,
			RedirectURL:  creds.Web.RedirectURIs[0],
			Endpoint:     provider.Endpoint(),
			Scopes: []string{
				oidc.ScopeOpenID, // required for OIDC — makes the server return an ID Token
				"profile",        // name, picture
				"email",          // email, email_verified
				// ── Step 6: uncomment to enable Google Drive access ──────────
				// "https://www.googleapis.com/auth/drive.readonly",
			},
		},
		// The verifier checks signature (JWKS), issuer, audience, and expiry.
		verifier: provider.Verifier(&oidc.Config{ClientID: creds.Web.ClientID}),
		sessions: newSessionStore(),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", a.handleHome)
	mux.HandleFunc("/login", a.handleLogin)
	mux.HandleFunc("/auth/google/callback", a.handleCallback)
	// requireAuth wraps these routes — they only run if a session exists.
	mux.HandleFunc("/profile", a.requireAuth(a.handleProfile))
	mux.HandleFunc("/drive", a.requireAuth(a.handleDrive))
	mux.HandleFunc("/logout", a.handleLogout)

	log.Println("Listening on http://localhost:8080")
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
<head><title>OAuth 2.0 + OIDC Demo</title></head>
<body>
  <h1>OAuth 2.0 & OpenID Connect Demo</h1>
  {{if .LoggedIn}}
    <p>Signed in as <strong>{{.Email}}</strong></p>
    <a href="/profile">View profile</a> &nbsp;|&nbsp;
    <a href="/drive">Google Drive files</a> &nbsp;|&nbsp;
    <a href="/logout">Sign out</a>
  {{else}}
    <a href="/login">Sign in with Google</a>
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
//  1. Generate a PKCE code_verifier (high-entropy random string).
//  2. Compute code_challenge = base64url(SHA-256(verifier)).
//  3. Generate a random CSRF state token.
//  4. Store both in short-lived HttpOnly cookies.
//  5. Redirect to Google with the challenge (not the verifier).
//
// PKCE prevents authorization code interception: even if an attacker intercepts
// the code in the redirect URL, they can't exchange it without the verifier that
// was never sent over the network.
func (a *app) handleLogin(w http.ResponseWriter, r *http.Request) {
	// oauth2.GenerateVerifier returns a cryptographically random URL-safe string
	// (43 chars, which is 32 bytes base64url-encoded without padding).
	verifier := oauth2.GenerateVerifier()

	// Store the verifier in a short-lived cookie so handleCallback can retrieve
	// it and send it during the token exchange.
	http.SetCookie(w, &http.Cookie{
		Name:     "pkce_verifier",
		Value:    verifier,
		MaxAge:   300, // 5 minutes — plenty of time to complete the login flow
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Path:     "/",
	})

	// Random state token for CSRF protection.
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

	// S256ChallengeOption computes base64url(SHA-256(verifier)) and appends:
	//   code_challenge=<hash>&code_challenge_method=S256
	// to the authorization URL. The raw verifier never leaves our server.
	authURL := a.oauth2Config.AuthCodeURL(state,
		oauth2.AccessTypeOffline, // request a refresh token
		oauth2.S256ChallengeOption(verifier),
	)
	http.Redirect(w, r, authURL, http.StatusFound)
}

// handleCallback is the redirect_uri registered with Google.
// After the user approves (or denies) access, Google sends them here with:
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
		http.Error(w, "state mismatch — possible CSRF", http.StatusBadRequest)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "oauth_state", MaxAge: -1, Path: "/"})

	// ── Step 2: Retrieve the PKCE verifier ────────────────────────────────────
	verifierCookie, err := r.Cookie("pkce_verifier")
	if err != nil {
		http.Error(w, "missing PKCE verifier cookie", http.StatusBadRequest)
		return
	}
	verifier := verifierCookie.Value
	http.SetCookie(w, &http.Cookie{Name: "pkce_verifier", MaxAge: -1, Path: "/"})

	// ── Step 3: Exchange the authorization code for tokens (back-channel) ─────
	// VerifierOption sends code_verifier in the token request.
	// Google re-computes SHA-256(verifier) and checks it matches the challenge
	// from step 1 — proving the same client initiated both requests.
	code := r.URL.Query().Get("code")
	token, err := a.oauth2Config.Exchange(ctx, code, oauth2.VerifierOption(verifier))
	if err != nil {
		http.Error(w, "token exchange failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// ── Step 4: Verify the ID Token ───────────────────────────────────────────
	// go-oidc checks:
	//   • JWT signature against Google's JWKS (public keys rotated by Google)
	//   • iss == "https://accounts.google.com"
	//   • aud == our ClientID (prevents tokens meant for another app)
	//   • exp is in the future
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

	// ── Step 5: Extract claims ────────────────────────────────────────────────
	var claims struct {
		Sub           string `json:"sub"` // stable, unique user ID
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
		Name          string `json:"name"`
		Picture       string `json:"picture"`
	}
	if err := idToken.Claims(&claims); err != nil {
		http.Error(w, "failed to parse claims: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// ── Step 6: Build a TokenSource for automatic token refresh ───────────────
	// oauth2.Config.TokenSource wraps token in a reuseTokenSource. When the
	// access token expires, calling .Token() automatically POSTs the refresh
	// token to Google's token endpoint and returns a fresh access token.
	//
	// We use context.Background() (not the request context) so the token source
	// remains usable long after this HTTP request ends.
	tokenSource := a.oauth2Config.TokenSource(context.Background(), token)

	// ── Step 7: Create a server-side session ──────────────────────────────────
	// Only an opaque random ID goes into the browser cookie — no user data,
	// no tokens. The full session lives on the server (in this map).
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

// handleProfile is protected by requireAuth — it only runs when a session exists.
func (a *app) handleProfile(w http.ResponseWriter, r *http.Request) {
	sess, _, _ := a.getSession(r) // requireAuth guarantees this succeeds

	tmpl := `<!DOCTYPE html>
<html>
<head><title>Profile</title></head>
<body>
  <h1>Your Profile</h1>
  <img src="{{.Picture}}" width="80" style="border-radius:50%">
  <table>
    <tr><td><b>Name</b></td><td>{{.Name}}</td></tr>
    <tr><td><b>Email</b></td><td>{{.Email}}</td></tr>
    <tr><td><b>Subject (sub)</b></td><td>{{.Sub}}</td></tr>
  </table>
  <br>
  <a href="/">Home</a> &nbsp;|&nbsp;
  <a href="/drive">Google Drive files</a> &nbsp;|&nbsp;
  <a href="/logout">Sign out</a>
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

// handleDrive calls the Google Drive API using the session's TokenSource.
//
// Key concept: oauth2.NewClient wraps an http.Client so that before every
// outbound request it calls sess.TokenSource.Token(). If the access token
// has expired, the TokenSource silently refreshes it using the stored refresh
// token. The handler doesn't need to know anything about token lifetimes.
//
// Requires the Drive scope to be uncommented in oauth2Config.Scopes and the
// user to re-authorize. Without the scope, the API returns a 403 and the
// handler surfaces a helpful hint.
func (a *app) handleDrive(w http.ResponseWriter, r *http.Request) {
	sess, _, _ := a.getSession(r) // requireAuth guarantees this succeeds

	// oauth2.NewClient injects a valid Bearer token into every request.
	client := oauth2.NewClient(r.Context(), sess.TokenSource)

	resp, err := client.Get("https://www.googleapis.com/drive/v3/files?pageSize=10&fields=files(name,mimeType,webViewLink)")
	if err != nil {
		http.Error(w, "Drive API request failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	var driveResp struct {
		Files []struct {
			Name        string `json:"name"`
			MimeType    string `json:"mimeType"`
			WebViewLink string `json:"webViewLink"`
		} `json:"files"`
		Error *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&driveResp); err != nil {
		http.Error(w, "failed to decode Drive response", http.StatusInternalServerError)
		return
	}

	if driveResp.Error != nil {
		// Surface a friendly hint when the scope is missing.
		http.Error(w, "Drive API error: "+driveResp.Error.Message+
			"\n\nHint: uncomment the Drive scope in oauth2Config.Scopes and sign in again.",
			http.StatusForbidden)
		return
	}

	tmpl := `<!DOCTYPE html>
<html>
<head><title>Google Drive Files</title></head>
<body>
  <h1>Your Google Drive (first 10 files)</h1>
  {{if .Files}}
  <ul>
    {{range .Files}}
    <li><a href="{{.WebViewLink}}" target="_blank">{{.Name}}</a> <em>({{.MimeType}})</em></li>
    {{end}}
  </ul>
  {{else}}
  <p>No files found.</p>
  {{end}}
  <br>
  <a href="/profile">Profile</a> &nbsp;|&nbsp; <a href="/">Home</a>
</body>
</html>`

	t := template.Must(template.New("").Parse(tmpl))
	if err := t.Execute(w, driveResp); err != nil {
		log.Printf("render drive: %v", err)
	}
}

func (a *app) handleLogout(w http.ResponseWriter, r *http.Request) {
	_, sessionID, ok := a.getSession(r)
	if ok {
		// Delete the server-side session so the ID becomes useless.
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
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}
