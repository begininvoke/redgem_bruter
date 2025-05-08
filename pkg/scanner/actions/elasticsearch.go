package actions

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// ElasticsearchAction implements Elasticsearch service scanning
type ElasticsearchAction struct {
	BaseAction
}

// NewElasticsearchAction creates a new Elasticsearch action
func NewElasticsearchAction() *ElasticsearchAction {
	return &ElasticsearchAction{
		BaseAction: *NewBaseAction(),
	}
}

// CheckAuth checks if Elasticsearch requires authentication
func (e *ElasticsearchAction) CheckAuth() (bool, string, error) {
	// First check if port is open
	open, err := e.CheckPort(e.Host, e.Port)
	if err != nil {
		return false, "", err
	}
	if !open {
		return false, "Port closed", nil
	}

	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: e.Timeout,
	}

	// Try to access Elasticsearch
	url := fmt.Sprintf("http://%s:%d/_cluster/health", e.Host, e.Port)
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

	return requiresAuth, fmt.Sprintf("Elasticsearch Status: %d", resp.StatusCode), nil
}

// BruteForce attempts to brute force Elasticsearch credentials
func (e *ElasticsearchAction) BruteForce() (bool, string, error) {
	// Try to read from service-specific wordlist first
	credentials, err := e.ReadServiceWordlist("elasticsearch")
	if err != nil {
		// Fall back to default credentials if wordlist is not available
		credentials = []string{
			"elastic:elastic",
			"elastic:changeme",
			"elastic:password",
			"elastic:123456",
			"admin:admin",
			"admin:password",
			"admin:123456",
		}
	}

	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: e.Timeout,
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
		url := fmt.Sprintf("http://%s:%d/_cluster/health", e.Host, e.Port)
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
		defer resp.Body.Close()

		// Check if authentication was successful
		if resp.StatusCode == http.StatusOK {
			// Try to parse the response to verify it's valid JSON
			var result map[string]interface{}
			if err := json.NewDecoder(resp.Body).Decode(&result); err == nil {
				success = true
				successInfo = fmt.Sprintf("Successfully authenticated with username: %s, password: %s", username, password)
				break
			}
		}
	}

	if !success {
		return false, "Failed to brute force Elasticsearch with common credentials", nil
	}

	return true, successInfo, nil
}
