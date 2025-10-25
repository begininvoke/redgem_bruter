package actions

import (
	"fmt"
	"strings"
)

// KibanaAction implements Kibana service scanning
type KibanaAction struct {
	BaseAction
}

// NewKibanaAction creates a new Kibana action
func NewKibanaAction() *KibanaAction {
	return &KibanaAction{
		BaseAction: BaseAction{},
	}
}

// CheckAuth checks if Kibana requires authentication and potential vulnerabilities
func (k *KibanaAction) CheckAuth() (bool, string, bool, error) {
	// First check if port is open
	open, err := k.CheckPort(k.Host, k.Port)
	if err != nil {
		return false, "", false, err
	}
	if !open {
		return false, "Port closed", false, nil
	}

	// Get banner to check version
	_, version, err := k.GetBanner()
	if err != nil {
		return false, "", false, err
	}

	// Check for known vulnerable versions
	vulnerable := false
	if strings.Contains(version, "Kibana 6.8") || strings.Contains(version, "Kibana 7.0") {
		vulnerable = true
	}

	// Run Kibana-specific auth detection
	output, err := k.RunNmapScript(k.Host, k.Port, "http-auth")
	if err != nil {
		return false, "", false, err
	}

	// Check if authentication is required - Kibana typically requires auth by default
	requiresAuth := strings.Contains(output, "authentication required") ||
		strings.Contains(output, "login required") ||
		strings.Contains(output, "credentials required") ||
		strings.Contains(output, "WWW-Authenticate") ||
		strings.Contains(output, "Basic realm") ||
		strings.Contains(output, "Digest realm") ||
		strings.Contains(output, "authentication") ||
		strings.Contains(output, "login") ||
		strings.Contains(output, "credentials")

	// If nmap script doesn't provide clear info, assume auth is required (default Kibana behavior)
	if !strings.Contains(output, "anonymous") && !strings.Contains(output, "no auth") {
		requiresAuth = true
	}

	return requiresAuth, fmt.Sprintf("Kibana %s - %s", version, output), vulnerable, nil
}

// CheckVulnerability checks for Kibana-specific vulnerabilities
func (k *KibanaAction) CheckVulnerability() (bool, string, error) {
	// Get version
	_, version, err := k.GetBanner()
	if err != nil {
		return false, "", err
	}

	vulnerabilities := []string{}

	// Check for known vulnerable versions
	if strings.Contains(version, "Kibana 6.8") || strings.Contains(version, "Kibana 7.0") {
		vulnerabilities = append(vulnerabilities, "Known vulnerable version")
	}

	// Check for default credentials
	output, err := k.RunNmapScript(k.Host, k.Port, "http-brute")
	if err == nil && strings.Contains(output, "Valid credentials") {
		vulnerabilities = append(vulnerabilities, "Default credentials found")
	}

	// Check for weak encryption
	output, err = k.RunNmapScript(k.Host, k.Port, "ssl-cert")
	if err == nil && strings.Contains(output, "Weak encryption") {
		vulnerabilities = append(vulnerabilities, "Weak encryption enabled")
	}

	if len(vulnerabilities) > 0 {
		return true, fmt.Sprintf("Vulnerabilities found: %s", strings.Join(vulnerabilities, ", ")), nil
	}

	return false, "No obvious vulnerabilities detected", nil
}

// BruteForce attempts to brute force Kibana credentials
func (k *KibanaAction) BruteForce() (bool, string, error) {
	// Run Kibana brute force script
	output, err := k.RunNmapScript(k.Host, k.Port, "http-brute")
	if err != nil {
		return false, "", err
	}

	// Check if brute force was successful
	success := strings.Contains(output, "Valid credentials") ||
		strings.Contains(output, "Login successful")

	return success, output, nil
}
