package actions

import (
	"fmt"
	"strings"
)

// LDAPAction implements LDAP service scanning
type LDAPAction struct {
	BaseAction
}

// NewLDAPAction creates a new LDAP action
func NewLDAPAction() *LDAPAction {
	return &LDAPAction{
		BaseAction: BaseAction{}, // Initialize without dereferencing
	}
}

// CheckAuth checks if LDAP requires authentication and potential vulnerabilities
func (l *LDAPAction) CheckAuth() (bool, string, bool, error) {
	// First check if port is open
	open, err := l.CheckPort(l.Host, l.Port)
	if err != nil {
		return false, "", false, err
	}
	if !open {
		return false, "Port closed", false, nil
	}

	// Get banner to check version
	_, version, err := l.GetBanner()
	if err != nil {
		return false, "", false, err
	}

	// Check for known vulnerable versions
	vulnerable := false
	if strings.Contains(version, "OpenLDAP 2.2") || strings.Contains(version, "OpenLDAP 2.3") {
		vulnerable = true
	}

	// Run LDAP-specific auth detection
	output, err := l.RunNmapScript(l.Host, l.Port, "ldap-rootdse")
	if err != nil {
		return false, "", false, err
	}

	// Check if authentication is required
	requiresAuth := strings.Contains(output, "authentication required") ||
		strings.Contains(output, "bind failed") ||
		strings.Contains(output, "invalid credentials")

	return requiresAuth, fmt.Sprintf("LDAP %s - %s", version, output), vulnerable, nil
}

// CheckVulnerability checks for LDAP-specific vulnerabilities
func (l *LDAPAction) CheckVulnerability() (bool, string, error) {
	// Get version
	_, version, err := l.GetBanner()
	if err != nil {
		return false, "", err
	}

	vulnerabilities := []string{}

	// Check for known vulnerable versions
	if strings.Contains(version, "OpenLDAP 2.2") || strings.Contains(version, "OpenLDAP 2.3") {
		vulnerabilities = append(vulnerabilities, "Known vulnerable version")
	}

	// Check for anonymous access
	output, err := l.RunNmapScript(l.Host, l.Port, "ldap-anon")
	if err == nil && strings.Contains(output, "Anonymous access") {
		vulnerabilities = append(vulnerabilities, "Anonymous access allowed")
	}

	// Check for default credentials
	output, err = l.RunNmapScript(l.Host, l.Port, "ldap-brute")
	if err == nil && strings.Contains(output, "Valid credentials") {
		vulnerabilities = append(vulnerabilities, "Default credentials found")
	}

	// Check for null bind
	output, err = l.RunNmapScript(l.Host, l.Port, "ldap-null")
	if err == nil && strings.Contains(output, "VULNERABLE") {
		vulnerabilities = append(vulnerabilities, "Null bind allowed")
	}

	if len(vulnerabilities) > 0 {
		return true, fmt.Sprintf("Vulnerabilities found: %s", strings.Join(vulnerabilities, ", ")), nil
	}

	return false, "No obvious vulnerabilities detected", nil
}

// BruteForce attempts to brute force LDAP credentials
func (l *LDAPAction) BruteForce() (bool, string, error) {
	// Run LDAP brute force script
	output, err := l.RunNmapScript(l.Host, l.Port, "ldap-brute")
	if err != nil {
		return false, "", err
	}

	// Check if brute force was successful
	success := strings.Contains(output, "Valid credentials") ||
		strings.Contains(output, "Login successful")

	return success, output, nil
}
