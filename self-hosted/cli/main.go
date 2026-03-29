// Package main demonstrates the OAuth 2.0 Device Authorization Grant (RFC 8628).
//
// The Device flow is designed for devices that cannot run a browser or have
// limited input capability (CLI tools, smart TVs, game consoles, IoT devices).
// Instead of redirecting the user, the device displays a short code and a URL.
// The user visits the URL on a separate device (phone/PC), enters the code, and
// approves access. Meanwhile, the device polls the token endpoint until it gets
// an access token.
//
// Flow:
//  1. Device POSTs to /device/code → gets device_code, user_code, verification_uri
//  2. Device prints the URL and code to the terminal
//  3. User opens the URL in their browser, enters the code, and logs in
//  4. Device polls /token every N seconds until:
//     - authorization_pending → keep polling
//     - access_denied         → user refused, exit
//     - expired_token         → code expired, exit
//     - 200 OK                → got the token, proceed
//  5. Device calls the Transaction API with the access token
//
// Run after starting the auth server and transaction API:
//
//	go run ./authserver/    # terminal 1
//	go run ./transactionapi/ # terminal 2
//	go run ./cli/           # terminal 3 — then follow the printed instructions
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"time"
)

// deviceCodeResponse is the response from POST /device/code.
type deviceCodeResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"` // seconds between polls
}

// tokenResponse is the successful response from POST /token.
type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope"`
	IDToken     string `json:"id_token"`
}

// tokenErrorResponse is the error body returned while polling /token.
type tokenErrorResponse struct {
	Error string `json:"error"`
}

func main() {
	// ── Step 1: Request a device code from the authorization server ───────────
	fmt.Println("Requesting device authorization...")

	dcResp, err := requestDeviceCode()
	if err != nil {
		log.Fatalf("device code request failed: %v", err)
	}

	// ── Step 2: Prompt the user to visit the verification URL ─────────────────
	// Print instructions in a prominent box so the user knows exactly what to do.
	fmt.Println()
	fmt.Println("============================================")
	fmt.Println("  ACTION REQUIRED")
	fmt.Println("  Open this URL in your browser:")
	fmt.Printf("    %s\n", dcResp.VerificationURIComplete)
	fmt.Println()
	fmt.Printf("  Or go to %s and enter: %s\n", dcResp.VerificationURI, dcResp.UserCode)
	fmt.Println("============================================")
	fmt.Println()

	// ── Step 3: Poll the token endpoint until approved, denied, or expired ────
	accessToken, err := pollForToken(dcResp)
	if err != nil {
		log.Fatalf("authorization failed: %v", err)
	}

	fmt.Println()
	fmt.Println("Authorization successful! Calling Transaction API...")

	// ── Step 4: Call the Transaction API using the access token ──────────────
	resp, err := callTransactionAPI(accessToken)
	if err != nil {
		log.Fatalf("API call failed: %v", err)
	}

	fmt.Println()
	fmt.Println("Transaction API Response:")
	fmt.Println(resp)
}

// requestDeviceCode sends a POST to /device/code and returns the parsed response.
// We use net/http directly since we don't need the oauth2 package for this step.
func requestDeviceCode() (*deviceCodeResponse, error) {
	formData := url.Values{
		"client_id": {"cli-tool"},
		"scope":     {"openid profile transactions:read"},
	}

	resp, err := http.PostForm("http://localhost:9000/device/code", formData)
	if err != nil {
		return nil, fmt.Errorf("POST /device/code: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(body))
	}

	var dcResp deviceCodeResponse
	if err := json.NewDecoder(resp.Body).Decode(&dcResp); err != nil {
		return nil, fmt.Errorf("decode device code response: %w", err)
	}

	// Default the interval to 5 seconds if the server didn't specify one.
	if dcResp.Interval == 0 {
		dcResp.Interval = 5
	}

	return &dcResp, nil
}

// pollForToken polls POST /token at the specified interval until the user approves
// (or denies or the code expires). Returns the access token on success.
func pollForToken(dcResp *deviceCodeResponse) (string, error) {
	// Calculate the deadline from expires_in so we don't poll indefinitely.
	deadline := time.Now().Add(time.Duration(dcResp.ExpiresIn) * time.Second)

	for {
		// Check deadline before polling.
		if time.Now().After(deadline) {
			return "", fmt.Errorf("device code expired before user authorized")
		}

		// Wait the specified interval between polls.
		// (On the very first iteration we still wait — this gives the user
		// at least a few seconds to open the browser before we start hammering.)
		fmt.Print("Waiting for approval")
		time.Sleep(time.Duration(dcResp.Interval) * time.Second)
		fmt.Println("... polling")

		// POST to the token endpoint with the device_code grant type.
		// We build the request manually using http.PostForm (no oauth2 package
		// needed for device flow polling).
		formData := url.Values{
			"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
			"device_code": {dcResp.DeviceCode},
			"client_id":   {"cli-tool"},
		}

		resp, err := http.PostForm("http://localhost:9000/token", formData)
		if err != nil {
			return "", fmt.Errorf("POST /token: %w", err)
		}

		body, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()
		if readErr != nil {
			return "", fmt.Errorf("read token response: %w", readErr)
		}

		if resp.StatusCode == http.StatusOK {
			// Success — parse the access token and return it.
			var tr tokenResponse
			if err := json.Unmarshal(body, &tr); err != nil {
				return "", fmt.Errorf("decode token response: %w", err)
			}
			fmt.Println("Token received!")
			return tr.AccessToken, nil
		}

		// Non-200: parse the error code and decide whether to keep polling.
		var errResp tokenErrorResponse
		if err := json.Unmarshal(body, &errResp); err != nil {
			return "", fmt.Errorf("decode error response: %w", err)
		}

		switch errResp.Error {
		case "authorization_pending":
			// User hasn't acted yet — keep polling.
			fmt.Println("Waiting for approval...")
			continue

		case "slow_down":
			// Server asked us to back off — increase the interval by 5 seconds.
			dcResp.Interval += 5
			fmt.Printf("Slowing down — next poll in %d seconds\n", dcResp.Interval)
			continue

		case "access_denied":
			// User explicitly denied access.
			fmt.Println("Access denied by user.")
			return "", fmt.Errorf("access denied")

		case "expired_token":
			// The device_code has expired.
			fmt.Println("Code expired.")
			return "", fmt.Errorf("device code expired")

		default:
			return "", fmt.Errorf("unexpected error from token endpoint: %s", errResp.Error)
		}
	}
}

// callTransactionAPI calls GET /transactions with the given Bearer token and
// returns the pretty-printed JSON response body.
func callTransactionAPI(accessToken string) (string, error) {
	req, err := http.NewRequest(http.MethodGet, "http://localhost:9001/transactions", nil)
	if err != nil {
		return "", fmt.Errorf("create request: %w", err)
	}

	// Attach the access token as a Bearer credential (RFC 6750 §2.1).
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("GET /transactions: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(body))
	}

	// Pretty-print the JSON response.
	var result interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		// Not valid JSON — return raw body.
		return string(body), nil
	}

	pretty, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return string(body), nil
	}

	return string(pretty), nil
}
