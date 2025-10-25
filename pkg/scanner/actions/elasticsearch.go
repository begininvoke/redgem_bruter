package actions

import (
	"fmt"
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

// CheckAuth checks if Elasticsearch requires authentication and potential vulnerabilities
func (e *ElasticsearchAction) CheckAuth() (bool, string, bool, error) {
	// First check if port is open
	open, err := e.CheckPort(e.Host, e.Port)
	if err != nil {
		return false, "", false, err
	}
	if !open {
		return false, "Port closed", false, nil
	}

	// Get banner to check version
	_, version, err := e.GetBanner()
	if err != nil {
		return false, "", false, err
	}

	// Check for known vulnerable versions
	vulnerable := false
	if strings.Contains(version, "1.4") || strings.Contains(version, "1.5") {
		vulnerable = true
	}

	// Run Elasticsearch-specific auth detection
	output, err := e.RunNmapScript(e.Host, e.Port, "elasticsearch-info")
	if err != nil {
		return false, "", false, err
	}

	// Check if authentication is required - Elasticsearch typically requires auth by default
	// unless explicitly configured for anonymous access
	requiresAuth := strings.Contains(output, "authentication required") ||
		strings.Contains(output, "security") ||
		strings.Contains(output, "xpack") ||
		strings.Contains(output, "authentication") ||
		strings.Contains(output, "login") ||
		strings.Contains(output, "credentials")

	// If nmap script doesn't provide clear info, assume auth is required (default Elasticsearch behavior)
	if !strings.Contains(output, "anonymous") && !strings.Contains(output, "no auth") {
		requiresAuth = true
	}

	return requiresAuth, fmt.Sprintf("Elasticsearch %s - %s", version, output), vulnerable, nil
}

// CheckVulnerability checks for Elasticsearch-specific vulnerabilities
func (e *ElasticsearchAction) CheckVulnerability() (bool, string, error) {
	// Get version
	_, version, err := e.GetBanner()
	if err != nil {
		return false, "", err
	}

	vulnerabilities := []string{}

	// Check for known vulnerable versions
	if strings.Contains(version, "1.4") || strings.Contains(version, "1.5") {
		vulnerabilities = append(vulnerabilities, "Known vulnerable version")
	}

	// Check for anonymous access
	output, err := e.RunNmapScript(e.Host, e.Port, "elasticsearch-brute")
	if err == nil && strings.Contains(output, "Anonymous access") {
		vulnerabilities = append(vulnerabilities, "Anonymous access allowed")
	}

	// Check for default credentials
	output, err = e.RunNmapScript(e.Host, e.Port, "elasticsearch-brute")
	if err == nil && strings.Contains(output, "Valid credentials") {
		vulnerabilities = append(vulnerabilities, "Default credentials found")
	}

	if len(vulnerabilities) > 0 {
		return true, fmt.Sprintf("Vulnerabilities found: %s", strings.Join(vulnerabilities, ", ")), nil
	}

	return false, "No obvious vulnerabilities detected", nil
}

// BruteForce attempts to brute force Elasticsearch credentials
func (e *ElasticsearchAction) BruteForce() (bool, string, error) {
	// Run Elasticsearch brute force script
	output, err := e.RunNmapScript(e.Host, e.Port, "elasticsearch-brute")
	if err != nil {
		return false, "", err
	}

	// Check if brute force was successful
	success := strings.Contains(output, "Valid credentials") ||
		strings.Contains(output, "Login successful")

	return success, output, nil
}
