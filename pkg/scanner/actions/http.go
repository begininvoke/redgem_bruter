package actions

import (
	"fmt"
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

// CheckAuth checks if HTTP requires authentication and potential vulnerabilities
func (h *HTTPAction) CheckAuth() (bool, string, bool, error) {
	// First check if port is open
	open, err := h.CheckPort(h.Host, h.Port)
	if err != nil {
		return false, "", false, err
	}
	if !open {
		return false, "Port closed", false, nil
	}

	// Get banner to check version
	_, version, err := h.GetBanner()
	if err != nil {
		return false, "", false, err
	}

	// Check for known vulnerable versions
	vulnerable := false
	if strings.Contains(version, "Apache/2.4.49") || strings.Contains(version, "Apache/2.4.50") {
		vulnerable = true
	}

	// Run HTTP-specific auth detection
	output, err := h.RunNmapScript(h.Host, h.Port, "http-auth")
	if err != nil {
		return false, "", false, err
	}

	// Check if authentication is required
	requiresAuth := strings.Contains(output, "authentication required") ||
		strings.Contains(output, "WWW-Authenticate") ||
		strings.Contains(output, "Basic realm") ||
		strings.Contains(output, "Digest realm")

	return requiresAuth, fmt.Sprintf("HTTP %s - %s", version, output), vulnerable, nil
}

// CheckVulnerability checks for HTTP-specific vulnerabilities
func (h *HTTPAction) CheckVulnerability() (bool, string, error) {
	// Get version
	_, version, err := h.GetBanner()
	if err != nil {
		return false, "", err
	}

	vulnerabilities := []string{}

	// Check for known vulnerable versions
	if strings.Contains(version, "Apache/2.4.49") || strings.Contains(version, "Apache/2.4.50") {
		vulnerabilities = append(vulnerabilities, "Known vulnerable version (CVE-2021-41773)")
	}

	// Check for common vulnerabilities
	scripts := []string{
		"http-vuln-cve2017-5638", // Struts vulnerability
		"http-vuln-cve2017-8917", // Joomla vulnerability
		"http-vuln-cve2018-7600", // Drupal vulnerability
		"http-vuln-cve2019-2729", // Oracle WebLogic vulnerability
		"http-vuln-cve2020-3452", // Cisco vulnerability
	}

	for _, script := range scripts {
		output, err := h.RunNmapScript(h.Host, h.Port, script)
		if err == nil && strings.Contains(output, "VULNERABLE") {
			vulnerabilities = append(vulnerabilities, fmt.Sprintf("Vulnerable to %s", script))
		}
	}

	// Check for default credentials
	output, err := h.RunNmapScript(h.Host, h.Port, "http-default-accounts")
	if err == nil && strings.Contains(output, "Valid credentials") {
		vulnerabilities = append(vulnerabilities, "Default credentials found")
	}

	if len(vulnerabilities) > 0 {
		return true, fmt.Sprintf("Vulnerabilities found: %s", strings.Join(vulnerabilities, ", ")), nil
	}

	return false, "No obvious vulnerabilities detected", nil
}

// BruteForce attempts to brute force HTTP credentials
func (h *HTTPAction) BruteForce() (bool, string, error) {
	// Run HTTP brute force script
	output, err := h.RunNmapScript(h.Host, h.Port, "http-brute")
	if err != nil {
		return false, "", err
	}

	// Check if brute force was successful
	success := strings.Contains(output, "Valid credentials") ||
		strings.Contains(output, "Login successful")

	return success, output, nil
}
