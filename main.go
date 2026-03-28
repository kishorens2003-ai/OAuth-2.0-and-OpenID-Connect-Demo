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

// ─── App state ────────────────────────────────────────────────────────────────

// app holds the OAuth2 config and the OIDC verifier so they can be shared
// across handlers without global variables.
type app struct {
	oauth2Config *oauth2.Config
	verifier     *oidc.IDTokenVerifier
}

// ─── Main ─────────────────────────────────────────────────────────────────────

func main() {
	creds := loadCredentials("client_secret_827076828039-13ps1mv0pvugacrmelcs17o9u9fa4feg.apps.googleusercontent.com.json")

	ctx := context.Background()

	// ── OIDC Discovery ───────────────────────────────────────────────────────
	// go-oidc fetches /.well-known/openid-configuration from the issuer URL and
	// extracts the authorization, token, and JWKS endpoints automatically.
	// This is the recommended approach instead of hard-coding endpoint URLs.
	provider, err := oidc.NewProvider(ctx, "https://accounts.google.com")
	if err != nil {
		log.Fatalf("OIDC discovery: %v", err)
	}

	a := &app{
		// ── OAuth2 Config ────────────────────────────────────────────────────
		oauth2Config: &oauth2.Config{
			ClientID:     creds.Web.ClientID,
			ClientSecret: creds.Web.ClientSecret,
			RedirectURL:  creds.Web.RedirectURIs[0], // http://localhost:8080/auth/google/callback
			Endpoint:     provider.Endpoint(),        // populated from OIDC discovery
			Scopes: []string{
				oidc.ScopeOpenID, // required for OIDC — makes the server return an ID Token
				"profile",        // name, picture
				"email",          // email, email_verified
			},
		},
		// ── ID Token Verifier ────────────────────────────────────────────────
		// The verifier checks the token's signature (using Google's public keys),
		// expiry, issuer (iss), and audience (aud == our ClientID).
		verifier: provider.Verifier(&oidc.Config{ClientID: creds.Web.ClientID}),
	}

	http.HandleFunc("/", a.handleHome)
	http.HandleFunc("/login", a.handleLogin)
	http.HandleFunc("/auth/google/callback", a.handleCallback)
	http.HandleFunc("/profile", a.handleProfile)
	http.HandleFunc("/logout", a.handleLogout)

	log.Println("Listening on http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

// ─── Handlers ─────────────────────────────────────────────────────────────────

func (a *app) handleHome(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("user_email")

	data := struct {
		LoggedIn bool
		Email    string
	}{
		LoggedIn: err == nil,
	}
	if err == nil {
		data.Email = cookie.Value
	}

	tmpl := `<!DOCTYPE html>
<html>
<head><title>OAuth 2.0 + OIDC Demo</title></head>
<body>
  <h1>OAuth 2.0 & OpenID Connect Demo</h1>
  {{if .LoggedIn}}
    <p>Signed in as <strong>{{.Email}}</strong></p>
    <a href="/profile">View profile</a> &nbsp;|&nbsp; <a href="/logout">Sign out</a>
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

// handleLogin starts the Authorization Code Flow.
//
//  1. Generate a random "state" token.
//  2. Store it in a short-lived cookie so we can verify it on the callback.
//  3. Redirect the browser to Google's authorization endpoint.
func (a *app) handleLogin(w http.ResponseWriter, r *http.Request) {
	state, err := randomToken()
	if err != nil {
		http.Error(w, "failed to generate state", http.StatusInternalServerError)
		return
	}

	// The state cookie is HttpOnly + SameSite=Lax so JavaScript cannot read it
	// and it won't be sent on cross-site POST requests.
	http.SetCookie(w, &http.Cookie{
		Name:     "oauth_state",
		Value:    state,
		MaxAge:   300, // 5 minutes — plenty of time to complete the login
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Path:     "/",
	})

	// oauth2.AccessTypeOffline requests a refresh token so we can renew the
	// access token without sending the user back to Google.
	authURL := a.oauth2Config.AuthCodeURL(state, oauth2.AccessTypeOffline)
	http.Redirect(w, r, authURL, http.StatusFound)
}

// handleCallback is the redirect_uri registered with Google.
// After the user approves (or denies) access, Google sends them here with:
//
//	?code=<authorization_code>&state=<our_state>
func (a *app) handleCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// ── Step 1: Verify state (CSRF protection) ───────────────────────────────
	// If the state doesn't match, someone may be attempting a CSRF attack.
	stateCookie, err := r.Cookie("oauth_state")
	if err != nil {
		http.Error(w, "missing state cookie", http.StatusBadRequest)
		return
	}
	if r.URL.Query().Get("state") != stateCookie.Value {
		http.Error(w, "state mismatch — possible CSRF", http.StatusBadRequest)
		return
	}
	// Consume the state cookie immediately.
	http.SetCookie(w, &http.Cookie{Name: "oauth_state", MaxAge: -1, Path: "/"})

	// ── Step 2: Exchange the authorization code for tokens ───────────────────
	// This is a back-channel (server-to-server) request — the code never leaves
	// the server, so the client secret stays secret.
	code := r.URL.Query().Get("code")
	token, err := a.oauth2Config.Exchange(ctx, code)
	if err != nil {
		http.Error(w, "token exchange failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// ── Step 3: Extract the raw ID Token from the token response ─────────────
	// The ID Token is a JWT returned alongside the access token.
	// It is specific to OpenID Connect — plain OAuth 2.0 does not include it.
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		http.Error(w, "no id_token in response", http.StatusInternalServerError)
		return
	}

	// ── Step 4: Verify the ID Token ──────────────────────────────────────────
	// go-oidc checks:
	//   • JWT signature against Google's published public keys (JWKS)
	//   • iss (issuer) == "https://accounts.google.com"
	//   • aud (audience) == our ClientID
	//   • exp (expiry) is in the future
	idToken, err := a.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		http.Error(w, "ID token verification failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// ── Step 5: Extract claims ───────────────────────────────────────────────
	// Claims are the key-value pairs inside the JWT payload.
	var claims struct {
		Sub           string `json:"sub"`            // unique, stable user ID
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
		Name          string `json:"name"`
		Picture       string `json:"picture"`
	}
	if err := idToken.Claims(&claims); err != nil {
		http.Error(w, "failed to parse claims: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// ── Step 6: Establish a session ──────────────────────────────────────────
	// For this demo we use plain cookies. In production you would store the
	// session ID server-side (e.g. in Redis) and only put the ID in the cookie,
	// so the user data isn't readable in the browser (even if HttpOnly prevents
	// JS access, the browser's DevTools can still show cookie values).
	for _, c := range []http.Cookie{
		{Name: "user_sub", Value: claims.Sub, HttpOnly: true, SameSite: http.SameSiteLaxMode, Path: "/"},
		{Name: "user_email", Value: claims.Email, HttpOnly: true, SameSite: http.SameSiteLaxMode, Path: "/"},
		{Name: "user_name", Value: claims.Name, HttpOnly: true, SameSite: http.SameSiteLaxMode, Path: "/"},
		{Name: "user_picture", Value: claims.Picture, HttpOnly: true, SameSite: http.SameSiteLaxMode, Path: "/"},
	} {
		http.SetCookie(w, &c)
	}

	http.Redirect(w, r, "/profile", http.StatusFound)
}

// handleProfile is a protected page — redirect to home if not signed in.
func (a *app) handleProfile(w http.ResponseWriter, r *http.Request) {
	get := func(name string) string {
		c, err := r.Cookie(name)
		if err != nil {
			return ""
		}
		return c.Value
	}

	email := get("user_email")
	if email == "" {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	data := struct{ Sub, Name, Email, Picture string }{
		Sub:     get("user_sub"),
		Name:    get("user_name"),
		Email:   email,
		Picture: get("user_picture"),
	}

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
  <a href="/">Home</a> &nbsp;|&nbsp; <a href="/logout">Sign out</a>
</body>
</html>`

	t := template.Must(template.New("").Parse(tmpl))
	if err := t.Execute(w, data); err != nil {
		log.Printf("render profile: %v", err)
	}
}

func (a *app) handleLogout(w http.ResponseWriter, r *http.Request) {
	for _, name := range []string{"user_sub", "user_email", "user_name", "user_picture"} {
		http.SetCookie(w, &http.Cookie{Name: name, MaxAge: -1, Path: "/"})
	}
	http.Redirect(w, r, "/", http.StatusFound)
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

// randomToken generates a cryptographically random URL-safe string.
// Used for the OAuth2 state parameter.
func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}
