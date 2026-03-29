// Package main implements the Transaction API — a protected resource server
// that validates OAuth 2.0 Bearer access tokens issued by the self-hosted
// authorization server at http://localhost:9000.
//
// Key design points:
//   - Uses go-oidc OIDC Discovery to fetch the JWKS (public keys) automatically.
//   - Creates an IDTokenVerifier with ClientID="transaction-api" because our
//     auth server issues access tokens with aud=["transaction-api"].
//   - The /transactions endpoint requires a valid token with scope "transactions:read".
//   - Distinguishes user tokens (have an email claim) from service tokens (no email).
//
// Start order: authserver → transactionapi → webapp
package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
)

// ─── Context key for passing claims between middleware and handler ─────────────

// contextKey is an unexported type used as a context key to avoid collisions
// with keys from other packages.
type contextKey string

const claimsContextKey contextKey = "token_claims"

// tokenClaims holds the validated claims extracted from the Bearer token.
type tokenClaims struct {
	Sub      string `json:"sub"`       // subject: user ID (user token) or client_id (service token)
	Scope    string `json:"scope"`     // space-separated list of granted scopes
	ClientID string `json:"client_id"` // which client application made the request
	Email    string `json:"email"`     // present for user tokens, empty for service tokens
}

// ─── App state ────────────────────────────────────────────────────────────────

// app holds the OIDC token verifier used by the auth middleware.
type app struct {
	verifier *oidc.IDTokenVerifier
}

// ─── Auth middleware ──────────────────────────────────────────────────────────

// requireAuth is a middleware that validates the Bearer token in the Authorization
// header before passing the request to the next handler.
//
// Validation steps:
//  1. Extract "Bearer <token>" from the Authorization header.
//  2. Call verifier.Verify() which checks: signature (JWKS), issuer, audience, expiry.
//  3. Extract claims from the verified token.
//  4. Check that the "transactions:read" scope is present.
//  5. Attach claims to the request context for the downstream handler.
func (a *app) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// ── Extract the Bearer token ─────────────────────────────────────────
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, `{"error":"missing Authorization header"}`, http.StatusUnauthorized)
			return
		}
		if !strings.HasPrefix(authHeader, "Bearer ") {
			http.Error(w, `{"error":"Authorization header must use Bearer scheme"}`, http.StatusUnauthorized)
			return
		}
		rawToken := strings.TrimPrefix(authHeader, "Bearer ")

		// ── Verify the JWT ───────────────────────────────────────────────────
		// oidc.IDTokenVerifier (despite its name) works for access tokens too
		// when you configure it with the right ClientID (audience).
		// It verifies: signature against JWKS, iss, aud=["transaction-api"], exp.
		idToken, err := a.verifier.Verify(r.Context(), rawToken)
		if err != nil {
			log.Printf("token verification failed: %v", err)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"error": "invalid_token", "error_description": err.Error()})
			return
		}

		// ── Extract claims ───────────────────────────────────────────────────
		var claims tokenClaims
		if err := idToken.Claims(&claims); err != nil {
			http.Error(w, `{"error":"failed to parse token claims"}`, http.StatusUnauthorized)
			return
		}

		// ── Check required scope ─────────────────────────────────────────────
		// RFC 6750 §3.1: 403 Forbidden when the token is valid but lacks the
		// required scope (as opposed to 401 Unauthorized for invalid tokens).
		if !hasScope(claims.Scope, "transactions:read") {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]string{
				"error":             "insufficient_scope",
				"error_description": "token does not have the 'transactions:read' scope",
			})
			return
		}

		// ── Pass claims to the handler via context ────────────────────────────
		ctx := context.WithValue(r.Context(), claimsContextKey, &claims)
		next(w, r.WithContext(ctx))
	}
}

// ─── Handlers ─────────────────────────────────────────────────────────────────

// handleTransactions returns a fake list of transactions along with metadata
// about WHO called the API (user token vs service/machine token).
func (a *app) handleTransactions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Retrieve the validated claims injected by requireAuth.
	claims, ok := r.Context().Value(claimsContextKey).(*tokenClaims)
	if !ok {
		http.Error(w, `{"error":"internal error: claims not found in context"}`, http.StatusInternalServerError)
		return
	}

	// Determine whether the caller is an end-user or a service account.
	// User tokens have an email claim; service tokens do not (sub == client_id).
	callerType := "service"
	if claims.Email != "" {
		callerType = "user"
	}

	// Hardcoded fake transactions for demo purposes.
	type Transaction struct {
		ID          string  `json:"id"`
		Amount      float64 `json:"amount"`
		Description string  `json:"description"`
	}
	transactions := []Transaction{
		{ID: "txn_001", Amount: 42.50, Description: "Coffee shop"},
		{ID: "txn_002", Amount: 120.00, Description: "Grocery store"},
		{ID: "txn_003", Amount: 9.99, Description: "Streaming service"},
		{ID: "txn_004", Amount: 250.75, Description: "Online electronics"},
		{ID: "txn_005", Amount: 15.00, Description: "Bookstore"},
	}

	resp := map[string]interface{}{
		// Caller identity — shows the difference between user vs service tokens.
		"caller_type":   callerType,
		"caller_sub":    claims.Sub,
		"caller_email":  claims.Email,
		"caller_client": claims.ClientID,
		"scope":         claims.Scope,
		// The actual resource data.
		"transactions": transactions,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// handleHealth is a public endpoint for liveness/readiness checks.
func (a *app) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

// hasScope checks whether the target scope is present in the space-separated
// scope string from the token claims.
func hasScope(scopeStr, target string) bool {
	for _, s := range strings.Fields(scopeStr) {
		if s == target {
			return true
		}
	}
	return false
}

// ─── Main ─────────────────────────────────────────────────────────────────────

func main() {
	ctx := context.Background()

	// ── OIDC Discovery ───────────────────────────────────────────────────────
	// oidc.NewProvider fetches /.well-known/openid-configuration to discover
	// the JWKS URI and other metadata. The auth server must be running first.
	provider, err := oidc.NewProvider(ctx, "http://localhost:9000")
	if err != nil {
		log.Fatalf("OIDC discovery failed — is the auth server running at :9000? %v", err)
	}

	// Configure the verifier with ClientID="transaction-api" because our access
	// tokens are issued with aud=["transaction-api"]. If we used "web-app" here,
	// the verification would fail — that's intentional security isolation.
	a := &app{
		verifier: provider.Verifier(&oidc.Config{ClientID: "transaction-api"}),
	}

	mux := http.NewServeMux()

	// Public health check — no auth required.
	mux.HandleFunc("/health", a.handleHealth)

	// Protected endpoint — requireAuth validates the Bearer token before the
	// handler runs. Callers must have the "transactions:read" scope.
	mux.HandleFunc("/transactions", a.requireAuth(a.handleTransactions))

	log.Println("Transaction API listening on http://localhost:9001")
	log.Println("Auth server must be running at http://localhost:9000")
	log.Fatal(http.ListenAndServe(":9001", mux))
}
