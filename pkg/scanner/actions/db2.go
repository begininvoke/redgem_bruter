package actions

import (
	"fmt"
	"strings"
)

// DB2Action implements DB2 service scanning
type DB2Action struct {
	BaseAction
}

// NewDB2Action creates a new DB2 action
func NewDB2Action() *DB2Action {
	return &DB2Action{
		BaseAction: BaseAction{},
	}
}

// CheckAuth checks if DB2 requires authentication and potential vulnerabilities
func (d *DB2Action) CheckAuth() (bool, string, bool, error) {
	// First check if port is open
	open, err := d.CheckPort(d.Host, d.Port)
	if err != nil {
		return false, "", false, err
	}
	if !open {
		return false, "Port closed", false, nil
	}

	// Get banner to check version
	_, version, err := d.GetBanner()
	if err != nil {
		return false, "", false, err
	}

	// Check for known vulnerable versions
	vulnerable := false
	if strings.Contains(version, "DB2 9.7") || strings.Contains(version, "DB2 10.1") {
		vulnerable = true
	}

	// Run DB2-specific auth detection
	output, err := d.RunNmapScript(d.Host, d.Port, "db2-info")
	if err != nil {
		return false, "", false, err
	}

	// Check if authentication is required
	requiresAuth := strings.Contains(output, "authentication required") ||
		strings.Contains(output, "login required") ||
		strings.Contains(output, "credentials required")

	return requiresAuth, fmt.Sprintf("DB2 %s - %s", version, output), vulnerable, nil
}

// CheckVulnerability checks for DB2-specific vulnerabilities
func (d *DB2Action) CheckVulnerability() (bool, string, error) {
	// Get version
	_, version, err := d.GetBanner()
	if err != nil {
		return false, "", err
	}

	vulnerabilities := []string{}

	// Check for known vulnerable versions
	if strings.Contains(version, "DB2 9.7") || strings.Contains(version, "DB2 10.1") {
		vulnerabilities = append(vulnerabilities, "Known vulnerable version")
	}

	// Check for default credentials
	output, err := d.RunNmapScript(d.Host, d.Port, "db2-brute")
	if err == nil && strings.Contains(output, "Valid credentials") {
		vulnerabilities = append(vulnerabilities, "Default credentials found")
	}

	if len(vulnerabilities) > 0 {
		return true, fmt.Sprintf("Vulnerabilities found: %s", strings.Join(vulnerabilities, ", ")), nil
	}

	return false, "No obvious vulnerabilities detected", nil
}

// BruteForce attempts to brute force DB2 credentials
func (d *DB2Action) BruteForce() (bool, string, error) {
	// Run DB2 brute force script
	output, err := d.RunNmapScript(d.Host, d.Port, "db2-brute")
	if err != nil {
		return false, "", err
	}

	// Check if brute force was successful
	success := strings.Contains(output, "Valid credentials") ||
		strings.Contains(output, "Login successful")

	return success, output, nil
}
