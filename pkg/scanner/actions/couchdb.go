package actions

import (
	"fmt"
	"strings"
)

// CouchDBAction implements CouchDB service scanning
type CouchDBAction struct {
	BaseAction
}

// NewCouchDBAction creates a new CouchDB action
func NewCouchDBAction() *CouchDBAction {
	return &CouchDBAction{
		BaseAction: BaseAction{},
	}
}

// CheckAuth checks if CouchDB requires authentication and potential vulnerabilities
func (c *CouchDBAction) CheckAuth() (bool, string, bool, error) {
	// First check if port is open
	open, err := c.CheckPort(c.Host, c.Port)
	if err != nil {
		return false, "", false, err
	}
	if !open {
		return false, "Port closed", false, nil
	}

	// Get banner to check version
	_, version, err := c.GetBanner()
	if err != nil {
		return false, "", false, err
	}

	// Check for known vulnerable versions
	vulnerable := false
	if strings.Contains(version, "CouchDB 1.6") || strings.Contains(version, "CouchDB 2.0") {
		vulnerable = true
	}

	// Run CouchDB-specific auth detection
	output, err := c.RunNmapScript(c.Host, c.Port, "http-auth")
	if err != nil {
		return false, "", false, err
	}

	// Check if authentication is required
	requiresAuth := strings.Contains(output, "authentication required") ||
		strings.Contains(output, "login required") ||
		strings.Contains(output, "credentials required")

	return requiresAuth, fmt.Sprintf("CouchDB %s - %s", version, output), vulnerable, nil
}

// CheckVulnerability checks for CouchDB-specific vulnerabilities
func (c *CouchDBAction) CheckVulnerability() (bool, string, error) {
	// Get version
	_, version, err := c.GetBanner()
	if err != nil {
		return false, "", err
	}

	vulnerabilities := []string{}

	// Check for known vulnerable versions
	if strings.Contains(version, "CouchDB 1.6") || strings.Contains(version, "CouchDB 2.0") {
		vulnerabilities = append(vulnerabilities, "Known vulnerable version")
	}

	// Check for default credentials
	output, err := c.RunNmapScript(c.Host, c.Port, "http-brute")
	if err == nil && strings.Contains(output, "Valid credentials") {
		vulnerabilities = append(vulnerabilities, "Default credentials found")
	}

	// Check for weak encryption
	output, err = c.RunNmapScript(c.Host, c.Port, "ssl-cert")
	if err == nil && strings.Contains(output, "Weak encryption") {
		vulnerabilities = append(vulnerabilities, "Weak encryption enabled")
	}

	if len(vulnerabilities) > 0 {
		return true, fmt.Sprintf("Vulnerabilities found: %s", strings.Join(vulnerabilities, ", ")), nil
	}

	return false, "No obvious vulnerabilities detected", nil
}

// BruteForce attempts to brute force CouchDB credentials
func (c *CouchDBAction) BruteForce() (bool, string, error) {
	// Run CouchDB brute force script
	output, err := c.RunNmapScript(c.Host, c.Port, "http-brute")
	if err != nil {
		return false, "", err
	}

	// Check if brute force was successful
	success := strings.Contains(output, "Valid credentials") ||
		strings.Contains(output, "Login successful")

	return success, output, nil
}
