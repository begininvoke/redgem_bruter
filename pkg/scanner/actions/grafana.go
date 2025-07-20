package actions

import (
	"fmt"
	"strings"
)

// GrafanaAction implements Grafana service scanning
type GrafanaAction struct {
	BaseAction
}

// NewGrafanaAction creates a new Grafana action
func NewGrafanaAction() *GrafanaAction {
	return &GrafanaAction{
		BaseAction: BaseAction{},
	}
}

// CheckAuth checks if Grafana requires authentication and potential vulnerabilities
func (g *GrafanaAction) CheckAuth() (bool, string, bool, error) {
	// First check if port is open
	open, err := g.CheckPort(g.Host, g.Port)
	if err != nil {
		return false, "", false, err
	}
	if !open {
		return false, "Port closed", false, nil
	}

	// Get banner to check version
	_, version, err := g.GetBanner()
	if err != nil {
		return false, "", false, err
	}

	// Check for known vulnerable versions
	vulnerable := false
	if strings.Contains(version, "Grafana 7.0") || strings.Contains(version, "Grafana 7.1") {
		vulnerable = true
	}

	// Run Grafana-specific auth detection
	output, err := g.RunNmapScript(g.Host, g.Port, "http-auth")
	if err != nil {
		return false, "", false, err
	}

	// Check if authentication is required
	requiresAuth := strings.Contains(output, "authentication required") ||
		strings.Contains(output, "login required") ||
		strings.Contains(output, "credentials required")

	return requiresAuth, fmt.Sprintf("Grafana %s - %s", version, output), vulnerable, nil
}

// CheckVulnerability checks for Grafana-specific vulnerabilities
func (g *GrafanaAction) CheckVulnerability() (bool, string, error) {
	// Get version
	_, version, err := g.GetBanner()
	if err != nil {
		return false, "", err
	}

	vulnerabilities := []string{}

	// Check for known vulnerable versions
	if strings.Contains(version, "Grafana 7.0") || strings.Contains(version, "Grafana 7.1") {
		vulnerabilities = append(vulnerabilities, "Known vulnerable version")
	}

	// Check for default credentials
	output, err := g.RunNmapScript(g.Host, g.Port, "http-brute")
	if err == nil && strings.Contains(output, "Valid credentials") {
		vulnerabilities = append(vulnerabilities, "Default credentials found")
	}

	// Check for weak encryption
	output, err = g.RunNmapScript(g.Host, g.Port, "ssl-cert")
	if err == nil && strings.Contains(output, "Weak encryption") {
		vulnerabilities = append(vulnerabilities, "Weak encryption enabled")
	}

	if len(vulnerabilities) > 0 {
		return true, fmt.Sprintf("Vulnerabilities found: %s", strings.Join(vulnerabilities, ", ")), nil
	}

	return false, "No obvious vulnerabilities detected", nil
}

// BruteForce attempts to brute force Grafana credentials
func (g *GrafanaAction) BruteForce() (bool, string, error) {
	// Run Grafana brute force script
	output, err := g.RunNmapScript(g.Host, g.Port, "http-brute")
	if err != nil {
		return false, "", err
	}

	// Check if brute force was successful
	success := strings.Contains(output, "Valid credentials") ||
		strings.Contains(output, "Login successful")

	return success, output, nil
}
