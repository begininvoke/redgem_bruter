package actions

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// KibanaAction implements Kibana service scanning
type KibanaAction struct {
	BaseAction
}

// NewKibanaAction creates a new Kibana action
func NewKibanaAction() *KibanaAction {
	return &KibanaAction{
		BaseAction: *NewBaseAction(),
	}
}

// CheckAuth checks if Kibana requires authentication
func (k *KibanaAction) CheckAuth() (bool, string, error) {
	// First check if port is open
	open, err := k.CheckPort(k.Host, k.Port)
	if err != nil {
		return false, "", err
	}
	if !open {
		return false, "Port closed", nil
	}

	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: k.Timeout,
	}

	// Try to access Kibana API endpoints
	endpoints := []string{
		"/api/status",
		"/api/saved_objects/_find",
		"/api/security/v1/me",
	}

	var requiresAuth bool
	var info string

	for _, endpoint := range endpoints {
		url := fmt.Sprintf("http://%s:%d%s", k.Host, k.Port, endpoint)
		resp, err := client.Get(url)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		// Check response status and headers
		if resp.StatusCode == http.StatusUnauthorized ||
			resp.StatusCode == http.StatusForbidden ||
			strings.Contains(resp.Header.Get("WWW-Authenticate"), "Basic") {
			requiresAuth = true
			info = fmt.Sprintf("Kibana requires authentication (Status: %d)", resp.StatusCode)
			break
		}

		// Try to parse response for Kibana-specific indicators
		if resp.StatusCode == http.StatusOK {
			var result map[string]interface{}
			if err := json.NewDecoder(resp.Body).Decode(&result); err == nil {
				if _, ok := result["version"]; ok {
					info = fmt.Sprintf("Kibana version: %v", result["version"])
				}
			}
		}
	}

	// If no specific info was found, use nmap script as fallback
	if info == "" {
		output, err := k.RunNmapScript(k.Host, k.Port, "http-auth-finder")
		if err == nil {
			requiresAuth = strings.Contains(output, "authentication required") ||
				strings.Contains(output, "login required") ||
				strings.Contains(output, "Kibana login")
			info = output
		}
	}

	return requiresAuth, info, nil
}

// BruteForce attempts to brute force Kibana credentials
func (k *KibanaAction) BruteForce() (bool, string, error) {
	// Try to read from service-specific wordlist first
	credentials, err := k.ReadServiceWordlist("kibana")
	if err != nil {
		// Fall back to default credentials if wordlist is not available
		credentials = []string{
			"elastic:elastic",
			"elastic:changeme",
			"kibana:kibana",
			"kibana:changeme",
			"admin:admin",
			"admin:password",
			"admin:123456",
		}
	}

	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: k.Timeout,
	}

	var success bool
	var successInfo string

	for _, cred := range credentials {
		parts := strings.Split(cred, ":")
		if len(parts) != 2 {
			continue
		}

		username, password := parts[0], parts[1]

		// Try different Kibana API endpoints
		endpoints := []string{
			"/api/status",
			"/api/saved_objects/_find",
			"/api/security/v1/me",
		}

		for _, endpoint := range endpoints {
			url := fmt.Sprintf("http://%s:%d%s", k.Host, k.Port, endpoint)
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

		if success {
			break
		}
	}

	if !success {
		// Fall back to nmap script if direct HTTP attempts fail
		output, err := k.RunNmapScript(k.Host, k.Port, "http-brute")
		if err == nil {
			success = strings.Contains(output, "Valid credentials") ||
				strings.Contains(output, "Login successful")
			successInfo = output
		}
	}

	return success, successInfo, nil
}
