package actions

import (
	"fmt"
	"strings"
)

// KerberosAction implements Kerberos service scanning
type KerberosAction struct {
	BaseAction
}

// NewKerberosAction creates a new Kerberos action
func NewKerberosAction() *KerberosAction {
	return &KerberosAction{
		BaseAction: BaseAction{},
	}
}

// CheckAuth checks if Kerberos requires authentication and potential vulnerabilities
func (k *KerberosAction) CheckAuth() (bool, string, bool, error) {
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
	if strings.Contains(version, "Kerberos 5") {
		vulnerable = true
	}

	// Run Kerberos-specific auth detection
	output, err := k.RunNmapScript(k.Host, k.Port, "krb5-enum-users")
	if err != nil {
		return false, "", false, err
	}

	// Check if authentication is required
	requiresAuth := strings.Contains(output, "authentication required") ||
		strings.Contains(output, "login required") ||
		strings.Contains(output, "credentials required")

	return requiresAuth, fmt.Sprintf("Kerberos %s - %s", version, output), vulnerable, nil
}

// CheckVulnerability checks for Kerberos-specific vulnerabilities
func (k *KerberosAction) CheckVulnerability() (bool, string, error) {
	// Get version
	_, version, err := k.GetBanner()
	if err != nil {
		return false, "", err
	}

	vulnerabilities := []string{}

	// Check for known vulnerable versions
	if strings.Contains(version, "Kerberos 5") {
		vulnerabilities = append(vulnerabilities, "Known vulnerable version")
	}

	// Check for default credentials
	output, err := k.RunNmapScript(k.Host, k.Port, "krb5-brute")
	if err == nil && strings.Contains(output, "Valid credentials") {
		vulnerabilities = append(vulnerabilities, "Default credentials found")
	}

	// Check for weak encryption
	output, err = k.RunNmapScript(k.Host, k.Port, "krb5-encryption")
	if err == nil && strings.Contains(output, "Weak encryption") {
		vulnerabilities = append(vulnerabilities, "Weak encryption enabled")
	}

	if len(vulnerabilities) > 0 {
		return true, fmt.Sprintf("Vulnerabilities found: %s", strings.Join(vulnerabilities, ", ")), nil
	}

	return false, "No obvious vulnerabilities detected", nil
}

// BruteForce attempts to brute force Kerberos credentials
func (k *KerberosAction) BruteForce() (bool, string, error) {
	// Run Kerberos brute force script
	output, err := k.RunNmapScript(k.Host, k.Port, "krb5-brute")
	if err != nil {
		return false, "", err
	}

	// Check if brute force was successful
	success := strings.Contains(output, "Valid credentials") ||
		strings.Contains(output, "Login successful")

	return success, output, nil
}
