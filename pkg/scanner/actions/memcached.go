package actions

import (
	"fmt"
	"strings"
)

// MemcachedAction implements Memcached service scanning
type MemcachedAction struct {
	BaseAction
}

// NewMemcachedAction creates a new Memcached action
func NewMemcachedAction() *MemcachedAction {
	return &MemcachedAction{
		BaseAction: BaseAction{},
	}
}

// CheckAuth checks if Memcached requires authentication and potential vulnerabilities
func (m *MemcachedAction) CheckAuth() (bool, string, bool, error) {
	// First check if port is open
	open, err := m.CheckPort(m.Host, m.Port)
	if err != nil {
		return false, "", false, err
	}
	if !open {
		return false, "Port closed", false, nil
	}

	// Get banner to check version
	_, version, err := m.GetBanner()
	if err != nil {
		return false, "", false, err
	}

	// Check for known vulnerable versions
	vulnerable := false
	if strings.Contains(version, "Memcached 1.4") || strings.Contains(version, "Memcached 1.5") {
		vulnerable = true
	}

	// Run Memcached-specific auth detection
	output, err := m.RunNmapScript(m.Host, m.Port, "memcached-info")
	if err != nil {
		return false, "", false, err
	}

	// Check if authentication is required
	requiresAuth := strings.Contains(output, "authentication required") ||
		strings.Contains(output, "login required") ||
		strings.Contains(output, "credentials required")

	return requiresAuth, fmt.Sprintf("Memcached %s - %s", version, output), vulnerable, nil
}

// CheckVulnerability checks for Memcached-specific vulnerabilities
func (m *MemcachedAction) CheckVulnerability() (bool, string, error) {
	// Get version
	_, version, err := m.GetBanner()
	if err != nil {
		return false, "", err
	}

	vulnerabilities := []string{}

	// Check for known vulnerable versions
	if strings.Contains(version, "Memcached 1.4") || strings.Contains(version, "Memcached 1.5") {
		vulnerabilities = append(vulnerabilities, "Known vulnerable version")
	}

	// Check for default credentials
	output, err := m.RunNmapScript(m.Host, m.Port, "memcached-brute")
	if err == nil && strings.Contains(output, "Valid credentials") {
		vulnerabilities = append(vulnerabilities, "Default credentials found")
	}

	// Check for weak encryption
	output, err = m.RunNmapScript(m.Host, m.Port, "memcached-encryption")
	if err == nil && strings.Contains(output, "Weak encryption") {
		vulnerabilities = append(vulnerabilities, "Weak encryption enabled")
	}

	if len(vulnerabilities) > 0 {
		return true, fmt.Sprintf("Vulnerabilities found: %s", strings.Join(vulnerabilities, ", ")), nil
	}

	return false, "No obvious vulnerabilities detected", nil
}

// BruteForce attempts to brute force Memcached credentials
func (m *MemcachedAction) BruteForce() (bool, string, error) {
	// Run Memcached brute force script
	output, err := m.RunNmapScript(m.Host, m.Port, "memcached-brute")
	if err != nil {
		return false, "", err
	}

	// Check if brute force was successful
	success := strings.Contains(output, "Valid credentials") ||
		strings.Contains(output, "Login successful")

	return success, output, nil
}
