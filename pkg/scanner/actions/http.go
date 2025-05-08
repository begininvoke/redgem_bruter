package actions

import (
	"fmt"
	"net/http"
	"strings"
)

// HTTPAction implements HTTP service scanning
type HTTPAction struct {
	BaseAction
}

// NewHTTPAction creates a new HTTP action
func NewHTTPAction() *HTTPAction {
	return &HTTPAction{
		BaseAction: *NewBaseAction(),
	}
}

// CheckAuth checks if HTTP requires authentication
func (h *HTTPAction) CheckAuth() (bool, string, error) {
	// First check if port is open
	open, err := h.CheckPort(h.Host, h.Port)
	if err != nil {
		return false, "", err
	}
	if !open {
		return false, "Port closed", nil
	}

	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: h.Timeout,
	}

	// Try to access a protected resource
	url := fmt.Sprintf("http://%s:%d/admin", h.Host, h.Port)
	resp, err := client.Get(url)
	if err != nil {
		return false, "", err
	}
	defer resp.Body.Close()

	// Check if authentication is required
	requiresAuth := resp.StatusCode == http.StatusUnauthorized ||
		resp.StatusCode == http.StatusForbidden ||
		strings.Contains(resp.Header.Get("WWW-Authenticate"), "Basic") ||
		strings.Contains(resp.Header.Get("WWW-Authenticate"), "Digest")

	return requiresAuth, fmt.Sprintf("HTTP Status: %d", resp.StatusCode), nil
}

// BruteForce attempts to brute force HTTP credentials
func (h *HTTPAction) BruteForce() (bool, string, error) {
	// Try to read from service-specific wordlist first
	credentials, err := h.ReadServiceWordlist("http")
	if err != nil {
		// Fall back to default credentials if wordlist is not available
		credentials = []string{
			"admin:admin",
			"admin:password",
			"admin:123456",
			"root:root",
			"root:password",
			"root:123456",
		}
	}

	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: h.Timeout,
	}

	var success bool
	var successInfo string

	for _, cred := range credentials {
		parts := strings.Split(cred, ":")
		if len(parts) != 2 {
			continue
		}

		username, password := parts[0], parts[1]

		// Create request
		url := fmt.Sprintf("http://%s:%d/admin", h.Host, h.Port)
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			continue
		}

		// Set basic auth
		req.SetBasicAuth(username, password)

		// Send request
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()

		// Check if authentication was successful
		if resp.StatusCode == http.StatusOK {
			success = true
			successInfo = fmt.Sprintf("Successfully authenticated with username: %s, password: %s", username, password)
			break
		}
	}

	if !success {
		return false, "Failed to brute force HTTP with common credentials", nil
	}

	return true, successInfo, nil
}
