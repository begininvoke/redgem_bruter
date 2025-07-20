package actions

import (
	"fmt"
	"strings"

	_ "github.com/go-sql-driver/mysql"
)

// MySQLAction implements MySQL service scanning
type MySQLAction struct {
	BaseAction
}

// NewMySQLAction creates a new MySQL action
func NewMySQLAction() *MySQLAction {
	return &MySQLAction{
		BaseAction: *NewBaseAction(),
	}
}

// CheckAuth checks if MySQL requires authentication and potential vulnerabilities
func (m *MySQLAction) CheckAuth() (bool, string, bool, error) {
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
	if strings.Contains(version, "5.5") || strings.Contains(version, "5.6") {
		vulnerable = true
	}

	// Run MySQL-specific auth detection
	output, err := m.RunNmapScript(m.Host, m.Port, "mysql-info")
	if err != nil {
		return false, "", false, err
	}

	// Check if authentication is required
	requiresAuth := strings.Contains(output, "authentication required") ||
		strings.Contains(output, "Access denied")

	return requiresAuth, fmt.Sprintf("MySQL %s - %s", version, output), vulnerable, nil
}

// CheckVulnerability checks for MySQL-specific vulnerabilities
func (m *MySQLAction) CheckVulnerability() (bool, string, error) {
	// Get version
	_, version, err := m.GetBanner()
	if err != nil {
		return false, "", err
	}

	vulnerabilities := []string{}

	// Check for known vulnerable versions
	if strings.Contains(version, "5.5") || strings.Contains(version, "5.6") {
		vulnerabilities = append(vulnerabilities, "Known vulnerable version")
	}

	// Check for anonymous access
	output, err := m.RunNmapScript(m.Host, m.Port, "mysql-empty-password")
	if err == nil && strings.Contains(output, "Anonymous access") {
		vulnerabilities = append(vulnerabilities, "Anonymous access allowed")
	}

	// Check for default credentials
	output, err = m.RunNmapScript(m.Host, m.Port, "mysql-brute")
	if err == nil && strings.Contains(output, "Valid credentials") {
		vulnerabilities = append(vulnerabilities, "Default credentials found")
	}

	if len(vulnerabilities) > 0 {
		return true, fmt.Sprintf("Vulnerabilities found: %s", strings.Join(vulnerabilities, ", ")), nil
	}

	return false, "No obvious vulnerabilities detected", nil
}

// BruteForce attempts to brute force MySQL credentials
func (m *MySQLAction) BruteForce() (bool, string, error) {
	// Run MySQL brute force script
	output, err := m.RunNmapScript(m.Host, m.Port, "mysql-brute")
	if err != nil {
		return false, "", err
	}

	// Check if brute force was successful
	success := strings.Contains(output, "Valid credentials") ||
		strings.Contains(output, "Login successful")

	return success, output, nil
}
