// Package main implements a self-hosted OAuth 2.0 Authorization Server with
// OpenID Connect (OIDC) support. It demonstrates all four major grant types:
//
//   - Authorization Code (+ PKCE) – for web and mobile apps
//   - Client Credentials           – for machine-to-machine (M2M) services
//   - Refresh Token                – for long-lived sessions
//   - Device Authorization         – for CLI tools / TV apps
//
// This is an educational implementation. In production you would use a
// hardened library (e.g. Ory Hydra, Keycloak, Dex) rather than rolling
// your own auth server.
package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"html/template"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	// crypto/rsa.SignPKCS1v15 requires a crypto.Hash value.
	// Importing _ "crypto/sha256" registers the hash so crypto.SHA256.New() works.
	_ "crypto/sha256"
)

// ─── Domain types ─────────────────────────────────────────────────────────────

// User represents an end-user account. In production, store passwords as bcrypt
// hashes (golang.org/x/crypto/bcrypt) — never plain text.
type User struct {
	ID       string
	Username string
	Password string // plain text FOR DEMO ONLY — use bcrypt in production
	Email    string
	Name     string
	Roles    []string
}

// Client represents a registered OAuth 2.0 client application.
type Client struct {
	ID           string
	Secret       string   // empty for public clients
	Name         string
	Public       bool     // true = no secret, PKCE required for auth-code flow
	GrantTypes   []string // allowed grant type strings
	RedirectURIs []string
	Scopes       []string // allowed scopes for this client
}

// AuthRequest holds the parameters of an in-progress authorization request.
// It is created when the user arrives at /authorize and consumed after login.
type AuthRequest struct {
	ID                  string
	ClientID            string
	RedirectURI         string
	Scopes              []string
	State               string
	CodeChallenge       string
	CodeChallengeMethod string
	ExpiresAt           time.Time
}

// AuthCode is a one-time-use short-lived code returned to the client after
// the user authenticates. The client exchanges it for tokens at /token.
type AuthCode struct {
	Code                string
	ClientID            string
	UserID              string
	RedirectURI         string
	Scopes              []string
	CodeChallenge       string
	CodeChallengeMethod string
	ExpiresAt           time.Time
}

// DeviceCode represents an in-progress Device Authorization flow. The same
// struct is referenced from two maps: deviceCodes (keyed by DeviceCode) and
// userCodes (keyed by UserCode), so approval updates both automatically via
// shared pointer.
type DeviceCode struct {
	DeviceCode string
	UserCode   string
	ClientID   string
	Scopes     []string
	ExpiresAt  time.Time
	UserID     string // set when the user approves on /device
	Approved   bool
	Denied     bool
}

// RefreshToken is a long-lived token that lets the client obtain new access
// tokens without re-authenticating the user.
type RefreshToken struct {
	Token     string
	ClientID  string
	UserID    string
	Scopes    []string
	ExpiresAt time.Time
}

// ─── Server ───────────────────────────────────────────────────────────────────

// Server is the central state of the authorization server.
type Server struct {
	issuer     string
	privateKey *rsa.PrivateKey
	keyID      string

	// Static registries — read-only after startup.
	users   map[string]*User   // keyed by username
	clients map[string]*Client // keyed by client_id

	// Mutable state — all protected by mu.
	mu            sync.RWMutex
	authRequests  map[string]*AuthRequest // keyed by request ID
	authCodes     map[string]*AuthCode    // keyed by code
	deviceCodes   map[string]*DeviceCode  // keyed by device_code
	userCodes     map[string]*DeviceCode  // keyed by user_code (same pointers as deviceCodes)
	refreshTokens map[string]*RefreshToken
}

// newServer creates and seeds the authorization server.
func newServer() *Server {
	// Generate a 2048-bit RSA key pair used for signing JWTs.
	// In production, load from a persistent key store (HSM, Vault, KMS).
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("generate RSA key: %v", err)
	}

	s := &Server{
		issuer:        "http://localhost:9000",
		privateKey:    privKey,
		keyID:         "key-1",
		authRequests:  make(map[string]*AuthRequest),
		authCodes:     make(map[string]*AuthCode),
		deviceCodes:   make(map[string]*DeviceCode),
		userCodes:     make(map[string]*DeviceCode),
		refreshTokens: make(map[string]*RefreshToken),
	}

	// ── Pre-seed users ───────────────────────────────────────────────────────
	// In production use a database and store password hashes (bcrypt), not plain text.
	s.users = map[string]*User{
		"bob": {
			ID:       "user-bob",
			Username: "bob",
			Password: "password123",
			Email:    "bob@example.com",
			Name:     "Bob Smith",
			Roles:    []string{"user"},
		},
		"alice": {
			ID:       "user-alice",
			Username: "alice",
			Password: "password123",
			Email:    "alice@example.com",
			Name:     "Alice Johnson",
			Roles:    []string{"user", "admin"},
		},
	}

	// ── Pre-seed clients ─────────────────────────────────────────────────────
	s.clients = map[string]*Client{
		// Confidential web app — has a secret, uses Authorization Code + PKCE.
		"web-app": {
			ID:           "web-app",
			Secret:       "webapp-secret",
			Name:         "Demo Web App",
			Public:       false,
			GrantTypes:   []string{"authorization_code", "refresh_token"},
			RedirectURIs: []string{"http://localhost:8080/callback"},
			Scopes:       []string{"openid", "profile", "email", "transactions:read", "transactions:write"},
		},
		// Public mobile app — no secret, PKCE is mandatory.
		"mobile-app": {
			ID:           "mobile-app",
			Secret:       "",
			Name:         "Demo Mobile App",
			Public:       true,
			GrantTypes:   []string{"authorization_code", "refresh_token"},
			RedirectURIs: []string{"myapp://callback"},
			Scopes:       []string{"openid", "profile", "email", "transactions:read"},
		},
		// Service account — uses Client Credentials, no user involved.
		"cron-job-service": {
			ID:         "cron-job-service",
			Secret:     "cronjob-secret",
			Name:       "Cron Job Service",
			Public:     false,
			GrantTypes: []string{"client_credentials"},
			Scopes:     []string{"transactions:read"},
		},
		// Public CLI tool — uses Device Authorization flow.
		"cli-tool": {
			ID:         "cli-tool",
			Secret:     "",
			Name:       "Demo CLI Tool",
			Public:     true,
			GrantTypes: []string{"urn:ietf:params:oauth:grant-type:device_code", "refresh_token"},
			Scopes:     []string{"openid", "profile", "transactions:read"},
		},
	}

	return s
}

// ─── JWT signing ──────────────────────────────────────────────────────────────

// signJWT manually creates and signs a JWT using RSA-SHA256 (RS256).
//
// JWT structure: base64url(header) + "." + base64url(payload) + "." + base64url(signature)
//
// The signing input is "header.payload" encoded as ASCII/UTF-8.
// The signature is RSA-PKCS1v15(SHA-256(signing_input)).
func (s *Server) signJWT(claims map[string]interface{}) (string, error) {
	// Header identifies the algorithm and key used to verify the signature.
	header := map[string]interface{}{
		"alg": "RS256",
		"typ": "JWT",
		"kid": s.keyID,
	}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("marshal header: %w", err)
	}
	payloadJSON, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("marshal payload: %w", err)
	}

	// Base64url-encode without padding (RFC 7515 §2).
	encodedHeader := base64.RawURLEncoding.EncodeToString(headerJSON)
	encodedPayload := base64.RawURLEncoding.EncodeToString(payloadJSON)
	signingInput := encodedHeader + "." + encodedPayload

	// Hash the signing input with SHA-256, then sign with the private RSA key.
	hash := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, s.privateKey, crypto.SHA256, hash[:])
	if err != nil {
		return "", fmt.Errorf("RSA sign: %w", err)
	}

	encodedSig := base64.RawURLEncoding.EncodeToString(sig)
	return signingInput + "." + encodedSig, nil
}

// makeAccessToken issues a signed access token for a given user (or service).
// audience is the resource server that will validate the token (e.g. "transaction-api").
func (s *Server) makeAccessToken(userID, clientID string, scopes []string, audience string) (string, error) {
	now := time.Now()
	claims := map[string]interface{}{
		"iss":       s.issuer,
		"sub":       userID,
		"aud":       []string{audience},
		"exp":       now.Add(time.Hour).Unix(),
		"iat":       now.Unix(),
		"scope":     strings.Join(scopes, " "),
		"client_id": clientID,
	}

	// For user tokens (not service accounts), include the email claim so the
	// resource server can identify the end-user who authorized the request.
	if strings.HasPrefix(userID, "user-") {
		if u := s.userByID(userID); u != nil {
			claims["email"] = u.Email
		}
	}

	return s.signJWT(claims)
}

// makeIDToken issues a signed ID Token as defined by OpenID Connect Core §2.
//
// KEY DISTINCTION:
//   - Access token  → audience = resource server  ("transaction-api")
//   - ID token      → audience = client (relying party) ("web-app")
//
// The ID token proves the user's identity TO THE CLIENT. The resource server
// never sees or needs the ID token. This separation is intentional — mixing
// them is a security anti-pattern (confused deputy).
func (s *Server) makeIDToken(user *User, clientID string) (string, error) {
	now := time.Now()
	claims := map[string]interface{}{
		"iss":            s.issuer,
		"sub":            user.ID,
		"aud":            []string{clientID},
		"exp":            now.Add(time.Hour).Unix(),
		"iat":            now.Unix(),
		"email":          user.Email,
		"email_verified": true,
		"name":           user.Name,
		"roles":          user.Roles,
	}
	return s.signJWT(claims)
}

// ─── OIDC Discovery & JWKS ────────────────────────────────────────────────────

// handleDiscovery serves the OIDC Discovery document at
// /.well-known/openid-configuration (RFC 8414, OpenID Connect Discovery 1.0).
// Clients fetch this once on startup to locate all endpoints and metadata.
func (s *Server) handleDiscovery(w http.ResponseWriter, r *http.Request) {
	doc := map[string]interface{}{
		"issuer":                                s.issuer,
		"authorization_endpoint":                s.issuer + "/authorize",
		"token_endpoint":                        s.issuer + "/token",
		"jwks_uri":                              s.issuer + "/jwks",
		"device_authorization_endpoint":         s.issuer + "/device/code",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "client_credentials", "refresh_token", "urn:ietf:params:oauth:grant-type:device_code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"scopes_supported":                      []string{"openid", "profile", "email", "transactions:read", "transactions:write"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_post", "client_secret_basic", "none"},
		"code_challenge_methods_supported":      []string{"S256", "plain"},
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(doc)
}

// handleJWKS exposes the RSA public key in JWK (JSON Web Key) format (RFC 7517).
// Resource servers download this to validate access token signatures without
// contacting the auth server on every request (offline verification).
func (s *Server) handleJWKS(w http.ResponseWriter, r *http.Request) {
	pub := &s.privateKey.PublicKey

	// RSA public key = modulus N + exponent E, both encoded as big-endian
	// byte arrays, then base64url-encoded per RFC 7518 §6.3.
	nBytes := pub.N.Bytes()
	eBytes := big.NewInt(int64(pub.E)).Bytes()

	jwk := map[string]interface{}{
		"kty": "RSA",
		"kid": s.keyID,
		"use": "sig",
		"alg": "RS256",
		"n":   base64.RawURLEncoding.EncodeToString(nBytes),
		"e":   base64.RawURLEncoding.EncodeToString(eBytes),
	}
	doc := map[string]interface{}{
		"keys": []interface{}{jwk},
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(doc)
}

// ─── /authorize ───────────────────────────────────────────────────────────────

// handleAuthorize dispatches GET (show login form) and POST (process login).
func (s *Server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.handleAuthorizeGet(w, r)
	case http.MethodPost:
		s.handleAuthorizePost(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleAuthorizeGet validates the authorization request parameters and renders
// the login form. It does NOT authenticate the user — it only validates the
// client and stores the request parameters for the subsequent POST.
func (s *Server) handleAuthorizeGet(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	clientID := q.Get("client_id")
	redirectURI := q.Get("redirect_uri")
	responseType := q.Get("response_type")
	scopeStr := q.Get("scope")
	state := q.Get("state")
	codeChallenge := q.Get("code_challenge")
	codeChallengeMethod := q.Get("code_challenge_method")

	// Validate client — errors here can't use redirect because we don't know
	// if the redirect_uri is trustworthy yet.
	client, ok := s.clients[clientID]
	if !ok {
		http.Error(w, "unknown client_id", http.StatusBadRequest)
		return
	}

	// Validate redirect_uri — must match exactly one of the registered URIs.
	// (RFC 6749 §10.6 — open redirect prevention)
	if !containsString(client.RedirectURIs, redirectURI) {
		http.Error(w, "redirect_uri not registered for this client", http.StatusBadRequest)
		return
	}

	// Only "code" response_type is supported (Authorization Code flow).
	if responseType != "code" {
		redirectError(w, r, redirectURI, state, "unsupported_response_type", "only 'code' is supported")
		return
	}

	// For public clients, PKCE (code_challenge) is mandatory. Without it, an
	// attacker who intercepts the authorization code could exchange it directly.
	if client.Public && codeChallenge == "" {
		redirectError(w, r, redirectURI, state, "invalid_request", "code_challenge required for public clients")
		return
	}

	// Validate requested scopes against the client's registered scopes.
	requestedScopes := strings.Fields(scopeStr)
	for _, sc := range requestedScopes {
		if !containsString(client.Scopes, sc) {
			redirectError(w, r, redirectURI, state, "invalid_scope", "scope '"+sc+"' not allowed for this client")
			return
		}
	}

	// Store the auth request so POST /authorize can look it up by ID.
	// The hidden request_id in the form ties the POST back to these parameters.
	reqID := randomString(16)
	s.mu.Lock()
	s.authRequests[reqID] = &AuthRequest{
		ID:                  reqID,
		ClientID:            clientID,
		RedirectURI:         redirectURI,
		Scopes:              requestedScopes,
		State:               state,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
		ExpiresAt:           time.Now().Add(10 * time.Minute),
	}
	s.mu.Unlock()

	renderLoginForm(w, client.Name, reqID, "")
}

// handleAuthorizePost processes the submitted login credentials.
func (s *Server) handleAuthorizePost(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form data", http.StatusBadRequest)
		return
	}

	reqID := r.FormValue("request_id")
	username := r.FormValue("username")
	password := r.FormValue("password")

	// Retrieve and validate the stored auth request.
	s.mu.RLock()
	authReq, ok := s.authRequests[reqID]
	s.mu.RUnlock()

	if !ok || time.Now().After(authReq.ExpiresAt) {
		http.Error(w, "authorization request expired or not found", http.StatusBadRequest)
		return
	}

	client := s.clients[authReq.ClientID]

	// Validate credentials. In production: bcrypt.CompareHashAndPassword.
	user, exists := s.users[username]
	if !exists || user.Password != password {
		renderLoginForm(w, client.Name, reqID, "Invalid username or password. Try bob/password123 or alice/password123.")
		return
	}

	// Credentials valid — consume the auth request and issue an authorization code.
	// The code is valid for only 60 seconds and must be used exactly once.
	s.mu.Lock()
	delete(s.authRequests, reqID)
	code := randomString(32)
	s.authCodes[code] = &AuthCode{
		Code:                code,
		ClientID:            authReq.ClientID,
		UserID:              user.ID,
		RedirectURI:         authReq.RedirectURI,
		Scopes:              authReq.Scopes,
		CodeChallenge:       authReq.CodeChallenge,
		CodeChallengeMethod: authReq.CodeChallengeMethod,
		ExpiresAt:           time.Now().Add(60 * time.Second),
	}
	s.mu.Unlock()

	// Redirect back to the client with the code (and state for CSRF verification).
	redirectURL, _ := url.Parse(authReq.RedirectURI)
	q := redirectURL.Query()
	q.Set("code", code)
	if authReq.State != "" {
		q.Set("state", authReq.State)
	}
	redirectURL.RawQuery = q.Encode()
	http.Redirect(w, r, redirectURL.String(), http.StatusFound)
}

// ─── /token ───────────────────────────────────────────────────────────────────

// handleToken is the token endpoint. It dispatches to the appropriate grant
// type handler based on the grant_type form field.
func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		jsonError(w, "invalid_request", http.StatusBadRequest)
		return
	}

	// RFC 6749 §5.1 requires these headers to prevent caching of token responses.
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")

	grantType := r.FormValue("grant_type")
	switch grantType {
	case "authorization_code":
		s.handleTokenAuthCode(w, r)
	case "client_credentials":
		s.handleTokenClientCredentials(w, r)
	case "refresh_token":
		s.handleTokenRefresh(w, r)
	case "urn:ietf:params:oauth:grant-type:device_code":
		s.handleTokenDevice(w, r)
	default:
		jsonError(w, "unsupported_grant_type", http.StatusBadRequest)
	}
}

// handleTokenAuthCode implements RFC 6749 §4.1.3 — exchanging an authorization
// code for access token + ID token + refresh token.
func (s *Server) handleTokenAuthCode(w http.ResponseWriter, r *http.Request) {
	clientID, _, client, ok := s.authenticateClient(w, r)
	if !ok {
		return
	}

	if !containsString(client.GrantTypes, "authorization_code") {
		jsonError(w, "unauthorized_client", http.StatusBadRequest)
		return
	}

	code := r.FormValue("code")
	redirectURI := r.FormValue("redirect_uri")
	codeVerifier := r.FormValue("code_verifier")

	// Look up and validate the authorization code.
	s.mu.RLock()
	authCode, exists := s.authCodes[code]
	s.mu.RUnlock()

	if !exists || time.Now().After(authCode.ExpiresAt) || authCode.ClientID != clientID {
		jsonError(w, "invalid_grant", http.StatusBadRequest)
		return
	}
	// redirect_uri must match the one used in the authorization request (RFC 6749 §4.1.3).
	if authCode.RedirectURI != redirectURI {
		jsonError(w, "invalid_grant", http.StatusBadRequest)
		return
	}

	// Verify PKCE — if the original /authorize request included a code_challenge,
	// the token request must include the matching code_verifier. This binds the
	// token exchange to the same party that initiated the auth request (RFC 7636).
	if authCode.CodeChallenge != "" {
		if codeVerifier == "" {
			jsonError(w, "invalid_grant", http.StatusBadRequest)
			return
		}
		if !verifyCodeChallenge(codeVerifier, authCode.CodeChallenge, authCode.CodeChallengeMethod) {
			jsonError(w, "invalid_grant", http.StatusBadRequest)
			return
		}
	}

	// Consume the code — authorization codes are single-use (RFC 6749 §10.5).
	s.mu.Lock()
	delete(s.authCodes, code)
	s.mu.Unlock()

	// Look up the user who authenticated during the authorization request.
	user := s.userByID(authCode.UserID)
	if user == nil {
		jsonError(w, "server_error", http.StatusInternalServerError)
		return
	}

	// Issue tokens:
	//   access_token  → audience "transaction-api" (for calling APIs)
	//   id_token      → audience "web-app" client_id (for identity proof)
	//   refresh_token → long-lived, used to obtain new access tokens
	accessToken, err := s.makeAccessToken(user.ID, clientID, authCode.Scopes, "transaction-api")
	if err != nil {
		jsonError(w, "server_error", http.StatusInternalServerError)
		return
	}
	idToken, err := s.makeIDToken(user, clientID)
	if err != nil {
		jsonError(w, "server_error", http.StatusInternalServerError)
		return
	}

	refreshToken := randomString(32)
	s.mu.Lock()
	s.refreshTokens[refreshToken] = &RefreshToken{
		Token:     refreshToken,
		ClientID:  clientID,
		UserID:    user.ID,
		Scopes:    authCode.Scopes,
		ExpiresAt: time.Now().Add(30 * 24 * time.Hour), // 30 days
	}
	s.mu.Unlock()

	writeTokenResponse(w, accessToken, idToken, refreshToken, strings.Join(authCode.Scopes, " "))
}

// handleTokenClientCredentials implements RFC 6749 §4.4 — machine-to-machine
// flow where no user is involved. Only confidential clients may use this grant.
func (s *Server) handleTokenClientCredentials(w http.ResponseWriter, r *http.Request) {
	clientID, _, client, ok := s.authenticateClient(w, r)
	if !ok {
		return
	}

	// Public clients MUST NOT use client_credentials — they have no secret to
	// prove their identity, so any attacker could impersonate them.
	if client.Public {
		jsonError(w, "unauthorized_client", http.StatusBadRequest)
		return
	}
	if !containsString(client.GrantTypes, "client_credentials") {
		jsonError(w, "unauthorized_client", http.StatusBadRequest)
		return
	}

	// Validate requested scopes against the client's registered scopes.
	scopeStr := r.FormValue("scope")
	var scopes []string
	if scopeStr != "" {
		for _, sc := range strings.Fields(scopeStr) {
			if !containsString(client.Scopes, sc) {
				jsonError(w, "invalid_scope", http.StatusBadRequest)
				return
			}
			scopes = append(scopes, sc)
		}
	} else {
		// Default to all allowed scopes if none requested.
		scopes = client.Scopes
	}

	// For client_credentials the sub is the client_id (service identity), not a user.
	// No ID token or refresh token is issued — there is no user session.
	accessToken, err := s.makeAccessToken(clientID, clientID, scopes, "transaction-api")
	if err != nil {
		jsonError(w, "server_error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"access_token": accessToken,
		"token_type":   "Bearer",
		"expires_in":   3600,
		"scope":        strings.Join(scopes, " "),
	})
}

// handleTokenRefresh implements RFC 6749 §6 — using a refresh token to obtain
// a new access token without requiring the user to log in again.
func (s *Server) handleTokenRefresh(w http.ResponseWriter, r *http.Request) {
	clientID, _, client, ok := s.authenticateClient(w, r)
	if !ok {
		return
	}

	if !containsString(client.GrantTypes, "refresh_token") {
		jsonError(w, "unauthorized_client", http.StatusBadRequest)
		return
	}

	refreshTokenVal := r.FormValue("refresh_token")

	s.mu.RLock()
	rt, exists := s.refreshTokens[refreshTokenVal]
	s.mu.RUnlock()

	if !exists || time.Now().After(rt.ExpiresAt) || rt.ClientID != clientID {
		jsonError(w, "invalid_grant", http.StatusBadRequest)
		return
	}

	// Issue a new access token with the same scopes as the original.
	accessToken, err := s.makeAccessToken(rt.UserID, clientID, rt.Scopes, "transaction-api")
	if err != nil {
		jsonError(w, "server_error", http.StatusInternalServerError)
		return
	}

	// We do not rotate the refresh token for simplicity. In a production system,
	// rotation (invalidating the old token, issuing a new one) limits the blast
	// radius of a stolen refresh token (RFC 6749 §10.4).
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"access_token":  accessToken,
		"token_type":    "Bearer",
		"expires_in":    3600,
		"refresh_token": refreshTokenVal,
		"scope":         strings.Join(rt.Scopes, " "),
	})
}

// handleTokenDevice implements the Device Authorization Grant polling endpoint
// (RFC 8628 §3.4). The device keeps POSTing here until the user approves or
// the device_code expires.
func (s *Server) handleTokenDevice(w http.ResponseWriter, r *http.Request) {
	deviceCodeVal := r.FormValue("device_code")
	clientID := r.FormValue("client_id")

	s.mu.RLock()
	dc, exists := s.deviceCodes[deviceCodeVal]
	s.mu.RUnlock()

	if !exists || dc.ClientID != clientID {
		jsonError(w, "invalid_grant", http.StatusBadRequest)
		return
	}

	if time.Now().After(dc.ExpiresAt) {
		jsonError(w, "expired_token", http.StatusBadRequest)
		return
	}

	// User explicitly denied access.
	if dc.Denied {
		jsonError(w, "access_denied", http.StatusBadRequest)
		return
	}

	// User hasn't acted yet — device should keep polling at the specified interval.
	if !dc.Approved {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "authorization_pending"})
		return
	}

	// User approved — issue tokens and consume the device code (single-use).
	user := s.userByID(dc.UserID)
	if user == nil {
		jsonError(w, "server_error", http.StatusInternalServerError)
		return
	}

	accessToken, err := s.makeAccessToken(user.ID, clientID, dc.Scopes, "transaction-api")
	if err != nil {
		jsonError(w, "server_error", http.StatusInternalServerError)
		return
	}
	idToken, err := s.makeIDToken(user, clientID)
	if err != nil {
		jsonError(w, "server_error", http.StatusInternalServerError)
		return
	}
	refreshToken := randomString(32)

	s.mu.Lock()
	// Delete from both maps — the device code and user code are now consumed.
	delete(s.deviceCodes, dc.DeviceCode)
	delete(s.userCodes, strings.ToUpper(dc.UserCode))
	s.refreshTokens[refreshToken] = &RefreshToken{
		Token:     refreshToken,
		ClientID:  clientID,
		UserID:    user.ID,
		Scopes:    dc.Scopes,
		ExpiresAt: time.Now().Add(30 * 24 * time.Hour),
	}
	s.mu.Unlock()

	writeTokenResponse(w, accessToken, idToken, refreshToken, strings.Join(dc.Scopes, " "))
}

// ─── /device/code ─────────────────────────────────────────────────────────────

// handleDeviceCode implements RFC 8628 §3.2 — the device requests a user_code
// and device_code from the authorization server.
func (s *Server) handleDeviceCode(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		jsonError(w, "invalid_request", http.StatusBadRequest)
		return
	}

	clientID := r.FormValue("client_id")
	client, ok := s.clients[clientID]
	if !ok {
		jsonError(w, "invalid_client", http.StatusUnauthorized)
		return
	}
	if !containsString(client.GrantTypes, "urn:ietf:params:oauth:grant-type:device_code") {
		jsonError(w, "unauthorized_client", http.StatusBadRequest)
		return
	}

	// Intersect requested scopes with client's allowed scopes.
	scopeStr := r.FormValue("scope")
	var scopes []string
	for _, sc := range strings.Fields(scopeStr) {
		if containsString(client.Scopes, sc) {
			scopes = append(scopes, sc)
		}
	}

	// device_code: cryptographically random, shown to the device but NOT the user.
	deviceCodeVal := randomString(32)
	// user_code: human-readable, short enough to type from a phone or TV remote.
	userCode := randomUserCode()

	dc := &DeviceCode{
		DeviceCode: deviceCodeVal,
		UserCode:   userCode,
		ClientID:   clientID,
		Scopes:     scopes,
		ExpiresAt:  time.Now().Add(10 * time.Minute),
	}

	s.mu.Lock()
	s.deviceCodes[deviceCodeVal] = dc
	// Store the same pointer under the uppercase user_code for case-insensitive lookup.
	s.userCodes[strings.ToUpper(userCode)] = dc
	s.mu.Unlock()

	verificationURI := s.issuer + "/device"
	verificationURIComplete := s.issuer + "/device?code=" + url.QueryEscape(userCode)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"device_code":               deviceCodeVal,
		"user_code":                 userCode,
		"verification_uri":          verificationURI,
		"verification_uri_complete": verificationURIComplete,
		"expires_in":                600,
		"interval":                  5, // poll every 5 seconds
	})
}

// ─── /device (user-facing verification page) ──────────────────────────────────

// handleDevice serves the user-facing device verification page where a human
// types in the user_code shown on their TV / CLI / IoT device.
func (s *Server) handleDevice(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.handleDeviceGet(w, r)
	case http.MethodPost:
		s.handleDevicePost(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleDeviceGet renders the device verification form.
// If ?code= is present in the URL, the user_code field is prefilled
// (from the verification_uri_complete link displayed on the device).
func (s *Server) handleDeviceGet(w http.ResponseWriter, r *http.Request) {
	prefillCode := r.URL.Query().Get("code")
	renderDeviceForm(w, prefillCode, "")
}

// handleDevicePost processes the submitted device verification form.
func (s *Server) handleDevicePost(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form data", http.StatusBadRequest)
		return
	}

	// Normalize user_code: uppercase and trim whitespace for friendly input.
	userCodeInput := strings.ToUpper(strings.TrimSpace(r.FormValue("user_code")))
	username := r.FormValue("username")
	password := r.FormValue("password")

	// Look up the device code by user_code (case-insensitive).
	s.mu.RLock()
	dc, exists := s.userCodes[userCodeInput]
	s.mu.RUnlock()

	if !exists || time.Now().After(dc.ExpiresAt) {
		renderDeviceForm(w, r.FormValue("user_code"), "Invalid or expired code. Please try again.")
		return
	}

	// Authenticate the user.
	user, userExists := s.users[username]
	if !userExists || user.Password != password {
		renderDeviceForm(w, r.FormValue("user_code"), "Invalid username or password. Try bob/password123 or alice/password123.")
		return
	}

	// Set the user ID and mark as approved. The polling device will detect this
	// on its next poll cycle (at most `interval` seconds from now).
	s.mu.Lock()
	dc.UserID = user.ID
	dc.Approved = true
	s.mu.Unlock()

	// Show a success page. The user can close this tab.
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintln(w, `<!DOCTYPE html>
<html>
<head><title>Access Approved</title>
<style>
  body { font-family: sans-serif; max-width: 480px; margin: 80px auto; text-align: center; padding: 0 1rem; }
  .check { font-size: 4rem; color: #22c55e; }
  p { color: #374151; }
</style>
</head>
<body>
  <div class="check">&#10003;</div>
  <h1>Access Approved</h1>
  <p>You have successfully authorized the device.</p>
  <p><strong>You can close this window.</strong></p>
</body>
</html>`)
}

// ─── Client authentication helper ─────────────────────────────────────────────

// authenticateClient reads client credentials from the token request.
// Supports both client_secret_basic (HTTP Basic Auth) and client_secret_post
// (form body). Public clients only need to provide client_id.
func (s *Server) authenticateClient(w http.ResponseWriter, r *http.Request) (string, string, *Client, bool) {
	// Try HTTP Basic Auth first: Authorization: Basic base64(client_id:secret)
	clientID, clientSecret, hasBasic := r.BasicAuth()
	if !hasBasic {
		// Fall back to form body parameters.
		clientID = r.FormValue("client_id")
		clientSecret = r.FormValue("client_secret")
	}

	client, ok := s.clients[clientID]
	if !ok {
		jsonError(w, "invalid_client", http.StatusUnauthorized)
		return "", "", nil, false
	}

	// Confidential clients must provide the correct secret.
	// Public clients have no secret — we only check the client_id.
	if !client.Public && client.Secret != clientSecret {
		jsonError(w, "invalid_client", http.StatusUnauthorized)
		return "", "", nil, false
	}

	return clientID, clientSecret, client, true
}

// ─── HTML rendering helpers ───────────────────────────────────────────────────

var loginFormTmpl = template.Must(template.New("login").Parse(`<!DOCTYPE html>
<html>
<head>
  <title>Sign in — {{.ClientName}}</title>
  <style>
    body { font-family: sans-serif; max-width: 400px; margin: 80px auto; padding: 0 1rem; }
    h2 { margin-bottom: 1.5rem; }
    label { display: block; margin-top: 1rem; font-weight: bold; }
    input[type=text], input[type=password] {
      width: 100%; padding: .5rem; box-sizing: border-box;
      border: 1px solid #ccc; border-radius: 4px; margin-top: .25rem;
    }
    button { margin-top: 1.5rem; width: 100%; padding: .75rem;
      background: #4f46e5; color: white; border: none; border-radius: 4px;
      font-size: 1rem; cursor: pointer; }
    button:hover { background: #4338ca; }
    .error { color: #dc2626; margin-top: 1rem; font-weight: bold; }
    .hint { margin-top: 1.5rem; font-size: .85rem; color: #6b7280;
      background: #f9fafb; padding: .75rem; border-radius: 4px; }
  </style>
</head>
<body>
  <h2>Sign in to {{.ClientName}}</h2>
  {{if .Error}}<p class="error">{{.Error}}</p>{{end}}
  <form method="POST" action="/authorize">
    <input type="hidden" name="request_id" value="{{.RequestID}}">
    <label>Username
      <input type="text" name="username" autocomplete="username" autofocus>
    </label>
    <label>Password
      <input type="password" name="password" autocomplete="current-password">
    </label>
    <button type="submit">Sign In</button>
  </form>
  <div class="hint">
    <strong>Demo credentials:</strong><br>
    bob / password123<br>
    alice / password123
  </div>
</body>
</html>`))

func renderLoginForm(w http.ResponseWriter, clientName, requestID, errMsg string) {
	data := struct {
		ClientName string
		RequestID  string
		Error      string
	}{clientName, requestID, errMsg}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := loginFormTmpl.Execute(w, data); err != nil {
		log.Printf("render login form: %v", err)
	}
}

var deviceFormTmpl = template.Must(template.New("device").Parse(`<!DOCTYPE html>
<html>
<head>
  <title>Authorize Device</title>
  <style>
    body { font-family: sans-serif; max-width: 400px; margin: 80px auto; padding: 0 1rem; }
    h2 { margin-bottom: .5rem; }
    p { color: #6b7280; margin-top: 0; }
    label { display: block; margin-top: 1rem; font-weight: bold; }
    input[type=text], input[type=password] {
      width: 100%; padding: .5rem; box-sizing: border-box;
      border: 1px solid #ccc; border-radius: 4px; margin-top: .25rem;
    }
    button { margin-top: 1.5rem; width: 100%; padding: .75rem;
      background: #059669; color: white; border: none; border-radius: 4px;
      font-size: 1rem; cursor: pointer; }
    button:hover { background: #047857; }
    .error { color: #dc2626; margin-top: 1rem; font-weight: bold; }
    .hint { margin-top: 1.5rem; font-size: .85rem; color: #6b7280;
      background: #f9fafb; padding: .75rem; border-radius: 4px; }
  </style>
</head>
<body>
  <h2>Authorize Device</h2>
  <p>Enter the code shown on your device, then sign in to approve access.</p>
  {{if .Error}}<p class="error">{{.Error}}</p>{{end}}
  <form method="POST" action="/device">
    <label>Device Code
      <input type="text" name="user_code" value="{{.PrefillCode}}"
             placeholder="XXXX-XXXX" autocomplete="off" autofocus
             style="font-family: monospace; font-size: 1.2rem; letter-spacing: .1em; text-transform: uppercase;">
    </label>
    <label>Username
      <input type="text" name="username" autocomplete="username">
    </label>
    <label>Password
      <input type="password" name="password" autocomplete="current-password">
    </label>
    <button type="submit">Sign In &amp; Approve Access</button>
  </form>
  <div class="hint">
    <strong>Demo credentials:</strong><br>
    bob / password123<br>
    alice / password123
  </div>
</body>
</html>`))

func renderDeviceForm(w http.ResponseWriter, prefillCode, errMsg string) {
	data := struct {
		PrefillCode string
		Error       string
	}{prefillCode, errMsg}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := deviceFormTmpl.Execute(w, data); err != nil {
		log.Printf("render device form: %v", err)
	}
}

// ─── Utility functions ────────────────────────────────────────────────────────

// randomString generates n random bytes and returns them as a base64url-encoded
// string (no padding). Used for opaque tokens and request IDs.
func randomString(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("rand.Read failed: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// randomUserCode generates a human-readable 9-character code in XXXX-XXXX format
// using consonants only (no vowels, no digits, to avoid accidentally forming words
// or visually confusing characters like 0/O).
func randomUserCode() string {
	const consonants = "BCDFGHJKLMNPQRSTVWXZ"
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		panic("rand.Read failed: " + err.Error())
	}
	// Build XXXX-XXXX
	code := make([]byte, 9)
	for i := 0; i < 4; i++ {
		code[i] = consonants[int(b[i])%len(consonants)]
	}
	code[4] = '-'
	for i := 0; i < 4; i++ {
		code[5+i] = consonants[int(b[4+i])%len(consonants)]
	}
	return string(code)
}

// verifyCodeChallenge checks the PKCE code_verifier against the stored challenge.
//
//	S256:  challenge == base64url(SHA-256(verifier))  (recommended, RFC 7636 §4.2)
//	plain: challenge == verifier                       (only if S256 not available)
func verifyCodeChallenge(verifier, challenge, method string) bool {
	switch method {
	case "S256", "": // treat missing method as S256 (default per spec)
		h := sha256.Sum256([]byte(verifier))
		computed := base64.RawURLEncoding.EncodeToString(h[:])
		return computed == challenge
	case "plain":
		return verifier == challenge
	default:
		return false
	}
}

// containsString reports whether s is present in slice.
func containsString(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}

// jsonError writes a JSON error response: {"error": "<errCode>"}.
func jsonError(w http.ResponseWriter, errCode string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": errCode})
}

// redirectError redirects the user-agent to the redirect_uri with an error
// query parameter, as required by RFC 6749 §4.1.2.1.
func redirectError(w http.ResponseWriter, r *http.Request, redirectURI, state, errCode, desc string) {
	u, err := url.Parse(redirectURI)
	if err != nil {
		http.Error(w, "invalid redirect_uri", http.StatusBadRequest)
		return
	}
	q := u.Query()
	q.Set("error", errCode)
	if desc != "" {
		q.Set("error_description", desc)
	}
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

// writeTokenResponse serializes and sends the standard OAuth 2.0 token response.
func writeTokenResponse(w http.ResponseWriter, accessToken, idToken, refreshToken, scope string) {
	resp := map[string]interface{}{
		"access_token": accessToken,
		"token_type":   "Bearer",
		"expires_in":   3600,
		"scope":        scope,
	}
	if refreshToken != "" {
		resp["refresh_token"] = refreshToken
	}
	if idToken != "" {
		resp["id_token"] = idToken
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// userByID performs a linear scan of the users map to find a user by ID.
// In production, use a database with an index on the user ID.
func (s *Server) userByID(id string) *User {
	for _, u := range s.users {
		if u.ID == id {
			return u
		}
	}
	return nil
}

// ─── Main ─────────────────────────────────────────────────────────────────────

func main() {
	s := newServer()

	// Log the RSA public key so operators can verify the active signing key.
	pubDER, _ := x509.MarshalPKIXPublicKey(&s.privateKey.PublicKey)
	_ = pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})

	mux := http.NewServeMux()

	// OIDC Discovery & key material
	mux.HandleFunc("/.well-known/openid-configuration", s.handleDiscovery)
	mux.HandleFunc("/jwks", s.handleJWKS)

	// Authorization Code flow
	mux.HandleFunc("/authorize", s.handleAuthorize)

	// Token endpoint (all four grant types)
	mux.HandleFunc("/token", s.handleToken)

	// Device Authorization flow
	mux.HandleFunc("/device/code", s.handleDeviceCode)
	mux.HandleFunc("/device", s.handleDevice)

	log.Println("╔══════════════════════════════════════════════════════════╗")
	log.Println("║          Self-Hosted OAuth 2.0 / OIDC Auth Server        ║")
	log.Println("╠══════════════════════════════════════════════════════════╣")
	log.Println("║  Listening on  http://localhost:9000                     ║")
	log.Println("║                                                          ║")
	log.Println("║  Endpoints:                                              ║")
	log.Println("║    Discovery  GET  /.well-known/openid-configuration     ║")
	log.Println("║    JWKS       GET  /jwks                                 ║")
	log.Println("║    Authorize  GET/POST /authorize                        ║")
	log.Println("║    Token      POST /token                                ║")
	log.Println("║    Device     POST /device/code                          ║")
	log.Println("║    Device UI  GET/POST /device                           ║")
	log.Println("║                                                          ║")
	log.Println("║  Demo users:  bob / password123                          ║")
	log.Println("║               alice / password123                        ║")
	log.Println("║                                                          ║")
	log.Println("║  Start transactionapi and webapp AFTER this server.      ║")
	log.Println("╚══════════════════════════════════════════════════════════╝")

	log.Fatal(http.ListenAndServe(":9000", mux))
}
