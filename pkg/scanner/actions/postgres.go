package actions

import (
	"fmt"
	"strings"

	_ "github.com/lib/pq"
)

// PostgresAction implements PostgreSQL service scanning
type PostgresAction struct {
	BaseAction
}

// NewPostgresAction creates a new PostgreSQL action
func NewPostgresAction() *PostgresAction {
	return &PostgresAction{
		BaseAction: *NewBaseAction(),
	}
}

// CheckAuth checks if PostgreSQL requires authentication and potential vulnerabilities
func (p *PostgresAction) CheckAuth() (bool, string, bool, error) {
	// First check if port is open
	open, err := p.CheckPort(p.Host, p.Port)
	if err != nil {
		return false, "", false, err
	}
	if !open {
		return false, "Port closed", false, nil
	}

	// Get banner to check version
	_, version, err := p.GetBanner()
	if err != nil {
		return false, "", false, err
	}

	// Check for known vulnerable versions
	vulnerable := false
	if strings.Contains(version, "9.3") || strings.Contains(version, "9.4") {
		vulnerable = true
	}

	// Run PostgreSQL-specific auth detection
	output, err := p.RunNmapScript(p.Host, p.Port, "pgsql-brute")
	if err != nil {
		return false, "", false, err
	}

	// Check if authentication is required
	requiresAuth := strings.Contains(output, "authentication required") ||
		strings.Contains(output, "password required") ||
		strings.Contains(output, "md5")

	return requiresAuth, fmt.Sprintf("PostgreSQL %s - %s", version, output), vulnerable, nil
}

// CheckVulnerability checks for PostgreSQL-specific vulnerabilities
func (p *PostgresAction) CheckVulnerability() (bool, string, error) {
	// Get version
	_, version, err := p.GetBanner()
	if err != nil {
		return false, "", err
	}

	vulnerabilities := []string{}

	// Check for known vulnerable versions
	if strings.Contains(version, "9.3") || strings.Contains(version, "9.4") {
		vulnerabilities = append(vulnerabilities, "Known vulnerable version")
	}

	// Check for anonymous access
	output, err := p.RunNmapScript(p.Host, p.Port, "pgsql-brute")
	if err == nil && strings.Contains(output, "Anonymous access") {
		vulnerabilities = append(vulnerabilities, "Anonymous access allowed")
	}

	// Check for default credentials
	output, err = p.RunNmapScript(p.Host, p.Port, "pgsql-brute")
	if err == nil && strings.Contains(output, "Valid credentials") {
		vulnerabilities = append(vulnerabilities, "Default credentials found")
	}

	if len(vulnerabilities) > 0 {
		return true, fmt.Sprintf("Vulnerabilities found: %s", strings.Join(vulnerabilities, ", ")), nil
	}

	return false, "No obvious vulnerabilities detected", nil
}

// BruteForce attempts to brute force PostgreSQL credentials
func (p *PostgresAction) BruteForce() (bool, string, error) {
	// Run PostgreSQL brute force script
	output, err := p.RunNmapScript(p.Host, p.Port, "pgsql-brute")
	if err != nil {
		return false, "", err
	}

	// Check if brute force was successful
	success := strings.Contains(output, "Valid credentials") ||
		strings.Contains(output, "Login successful")

	return success, output, nil
}
