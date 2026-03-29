// Package main demonstrates the OAuth 2.0 Client Credentials grant type.
//
// The Client Credentials flow is used for machine-to-machine (M2M) communication
// where no user is involved. The service authenticates itself using its client_id
// and client_secret and receives an access token directly — there is no browser
// redirect, no login form, no user consent.
//
// Flow:
//  1. POST /token with grant_type=client_credentials, client_id, client_secret, scope
//  2. Auth server validates credentials and issues an access token (sub=client_id)
//  3. Service calls the protected API with the access token as a Bearer header
//
// Run after starting the auth server and transaction API:
//
//	go run ./authserver/    # in one terminal
//	go run ./transactionapi/ # in another terminal
//	go run ./cronjob/       # in a third terminal
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"

	"golang.org/x/oauth2/clientcredentials"
)

func main() {
	// ── Step 1: Configure the Client Credentials token source ────────────────
	// The clientcredentials package handles:
	//   • POSTing client_id + client_secret + grant_type to the token endpoint
	//   • Caching the token and automatically refreshing it when it expires
	//   • Injecting the Bearer token into every HTTP request
	//
	// Unlike the authorization_code flow, there is no user involved and no
	// redirect URI. The client authenticates itself directly.
	config := &clientcredentials.Config{
		ClientID:     "cron-job-service",
		ClientSecret: "cronjob-secret",
		TokenURL:     "http://localhost:9000/token",
		Scopes:       []string{"transactions:read"},
	}

	log.Println("Getting access token via Client Credentials grant...")

	// Client() returns an *http.Client that automatically obtains and caches
	// an access token, refreshing it transparently when it expires.
	// This is the idiomatic way to make M2M API calls with oauth2 in Go.
	httpClient := config.Client(context.Background())

	// ── Step 2: Call the Transaction API ─────────────────────────────────────
	// oauth2.Client injects "Authorization: Bearer <access_token>" automatically.
	// The access token has sub=cron-job-service (the client_id) and no email claim,
	// so the Transaction API will identify this as a "service" caller.
	log.Println("Token obtained. Calling Transaction API...")

	resp, err := httpClient.Get("http://localhost:9001/transactions")
	if err != nil {
		log.Fatalf("API call failed: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("read response body: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		log.Fatalf("unexpected status %d: %s", resp.StatusCode, string(body))
	}

	// ── Step 3: Pretty-print the response ────────────────────────────────────
	var result interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		log.Fatalf("decode JSON: %v", err)
	}

	pretty, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		log.Fatalf("format JSON: %v", err)
	}

	log.Println("Response:")
	fmt.Println(string(pretty))
}
