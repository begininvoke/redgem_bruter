package actions

import (
	"fmt"
	"strings"
)

// MSSQLAction implements MSSQL service scanning
type MSSQLAction struct {
	BaseAction
}

// NewMSSQLAction creates a new MSSQL action
func NewMSSQLAction() *MSSQLAction {
	return &MSSQLAction{
		BaseAction: BaseAction{},
	}
}

// CheckAuth checks if MSSQL requires authentication and potential vulnerabilities
func (m *MSSQLAction) CheckAuth() (bool, string, bool, error) {
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
	if strings.Contains(version, "SQL Server 2000") || strings.Contains(version, "SQL Server 2005") {
		vulnerable = true
	}

	// Run MSSQL-specific auth detection
	output, err := m.RunNmapScript(m.Host, m.Port, "ms-sql-info")
	if err != nil {
		return false, "", false, err
	}

	// Check if authentication is required
	requiresAuth := strings.Contains(output, "authentication required") ||
		strings.Contains(output, "login required") ||
		strings.Contains(output, "credentials required")

	return requiresAuth, fmt.Sprintf("MSSQL %s - %s", version, output), vulnerable, nil
}

// CheckVulnerability checks for MSSQL-specific vulnerabilities
func (m *MSSQLAction) CheckVulnerability() (bool, string, error) {
	// Get version
	_, version, err := m.GetBanner()
	if err != nil {
		return false, "", err
	}

	vulnerabilities := []string{}

	// Check for known vulnerable versions
	if strings.Contains(version, "SQL Server 2000") || strings.Contains(version, "SQL Server 2005") {
		vulnerabilities = append(vulnerabilities, "Known vulnerable version")
	}

	// Check for default credentials
	output, err := m.RunNmapScript(m.Host, m.Port, "ms-sql-brute")
	if err == nil && strings.Contains(output, "Valid credentials") {
		vulnerabilities = append(vulnerabilities, "Default credentials found")
	}

	// Check for weak encryption
	output, err = m.RunNmapScript(m.Host, m.Port, "ms-sql-encryption")
	if err == nil && strings.Contains(output, "Weak encryption") {
		vulnerabilities = append(vulnerabilities, "Weak encryption enabled")
	}

	if len(vulnerabilities) > 0 {
		return true, fmt.Sprintf("Vulnerabilities found: %s", strings.Join(vulnerabilities, ", ")), nil
	}

	return false, "No obvious vulnerabilities detected", nil
}

// BruteForce attempts to brute force MSSQL credentials
func (m *MSSQLAction) BruteForce() (bool, string, error) {
	// Run MSSQL brute force script
	output, err := m.RunNmapScript(m.Host, m.Port, "ms-sql-brute")
	if err != nil {
		return false, "", err
	}

	// Check if brute force was successful
	success := strings.Contains(output, "Valid credentials") ||
		strings.Contains(output, "Login successful")

	return success, output, nil
}
