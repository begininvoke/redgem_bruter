package actions

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

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
		// If we can't get banner, continue with unknown version
		version = "unknown"
	}

	// Check for known vulnerable versions
	vulnerable := false
	if strings.Contains(version, "5.5") || strings.Contains(version, "5.6") {
		vulnerable = true
	}

	var authInfo []string
	requiresAuth := true // Default to true for security

	// Run multiple MySQL-specific scripts for comprehensive detection
	scripts := []string{"mysql-info", "mysql-empty-password", "mysql-users"}
	var allOutput strings.Builder

	for _, script := range scripts {
		output, err := m.RunNmapScript(m.Host, m.Port, script)
		if err == nil {
			allOutput.WriteString(fmt.Sprintf("[%s] %s\n", script, output))

			// Check for specific authentication indicators
			if strings.Contains(output, "Access denied") {
				authInfo = append(authInfo, "Access denied - authentication required")
				requiresAuth = true
			}

			// Check for anonymous/empty password access
			if strings.Contains(output, "Valid credentials") &&
				(strings.Contains(output, "root:") || strings.Contains(output, "anonymous")) {
				authInfo = append(authInfo, "Anonymous or empty password access detected")
				requiresAuth = false
			}

			// Check for no authentication required
			if strings.Contains(output, "Host is not allowed") {
				authInfo = append(authInfo, "Host restrictions in place")
				requiresAuth = true
			}
		}
	}

	// Try a direct connection test to verify authentication requirement
	authRequired, connInfo := m.testDirectConnection()
	if connInfo != "" {
		authInfo = append(authInfo, connInfo)
		// Direct connection test is more reliable than nmap scripts
		requiresAuth = authRequired
	} else {
		// If direct connection test fails, fall back to conservative approach
		// For MySQL, assume authentication is required unless we have evidence otherwise
		requiresAuth = true
		authInfo = append(authInfo, "Unable to test connection directly - assuming auth required for security")
	}

	infoStr := strings.Join(authInfo, "; ")
	if infoStr == "" {
		infoStr = allOutput.String()
	}

	// If no specific info was gathered, provide a general message
	if infoStr == "" {
		infoStr = "Authentication status determined through comprehensive analysis"
	}

	return requiresAuth, fmt.Sprintf("MySQL %s - %s", version, infoStr), vulnerable, nil
}

// CheckVulnerability checks for MySQL-specific vulnerabilities
func (m *MySQLAction) CheckVulnerability() (bool, string, error) {
	// Get version
	_, version, err := m.GetBanner()
	if err != nil {
		return false, "", err
	}

	vulnerabilities := []string{}

	// Check for known vulnerable versions with more specific checks
	if strings.Contains(version, "5.5") || strings.Contains(version, "5.6") {
		vulnerabilities = append(vulnerabilities, "Known vulnerable version (EOL)")
	}

	// Check for very old versions
	if strings.Contains(version, "5.0") || strings.Contains(version, "5.1") {
		vulnerabilities = append(vulnerabilities, "Very old MySQL version with multiple vulnerabilities")
	}

	// Run comprehensive vulnerability scripts
	scripts := []string{
		"mysql-empty-password",
		"mysql-users",
		"mysql-variables",
		"mysql-audit",
	}

	for _, script := range scripts {
		output, err := m.RunNmapScript(m.Host, m.Port, script)
		if err != nil {
			continue
		}

		switch script {
		case "mysql-empty-password":
			if strings.Contains(output, "Valid credentials") &&
				(strings.Contains(output, "root:") || strings.Contains(output, "anonymous")) {
				vulnerabilities = append(vulnerabilities, "Empty password access detected")
			}
		case "mysql-users":
			if strings.Contains(output, "anonymous") {
				vulnerabilities = append(vulnerabilities, "Anonymous user accounts present")
			}
		case "mysql-variables":
			if strings.Contains(output, "skip-grant-tables") {
				vulnerabilities = append(vulnerabilities, "Grant tables disabled - no authentication")
			}
		case "mysql-audit":
			if strings.Contains(output, "VULNERABLE") {
				vulnerabilities = append(vulnerabilities, "Audit script detected vulnerabilities")
			}
		}
	}

	// Test direct connection for authentication bypass
	authRequired, connInfo := m.testDirectConnection()
	if !authRequired && strings.Contains(connInfo, "no authentication required") {
		vulnerabilities = append(vulnerabilities, "Service does not require authentication (potential security risk)")
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

// testDirectConnection attempts a direct MySQL connection to test authentication requirements
func (m *MySQLAction) testDirectConnection() (bool, string) {
	// Test common scenarios for MySQL authentication
	testCases := []struct {
		dsn         string
		description string
		expectAuth  bool
	}{
		{
			dsn:         fmt.Sprintf("root:@tcp(%s:%d)/", m.Host, m.Port),
			description: "root with empty password",
			expectAuth:  false,
		},
		{
			dsn:         fmt.Sprintf(":@tcp(%s:%d)/", m.Host, m.Port),
			description: "anonymous connection",
			expectAuth:  false,
		},
	}

	for _, testCase := range testCases {
		db, err := sql.Open("mysql", testCase.dsn)
		if err != nil {
			continue
		}

		// Set connection timeout
		db.SetConnMaxLifetime(3 * time.Second)
		db.SetConnMaxIdleTime(3 * time.Second)

		// Try to ping the database with shorter timeout
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		err = db.PingContext(ctx)
		cancel()
		db.Close()

		if err == nil {
			// Connection successful without authentication
			return false, fmt.Sprintf("Connection successful with %s - no authentication required", testCase.description)
		}

		// Check error type to determine if it's an authentication error
		errStr := err.Error()
		if strings.Contains(errStr, "Access denied") {
			return true, fmt.Sprintf("Access denied for %s - authentication required", testCase.description)
		}

		if strings.Contains(errStr, "authentication") {
			return true, fmt.Sprintf("Authentication required for %s", testCase.description)
		}

		// Other errors might indicate network issues, not auth requirements
		if strings.Contains(errStr, "connection refused") ||
			strings.Contains(errStr, "timeout") ||
			strings.Contains(errStr, "network") ||
			strings.Contains(errStr, "i/o timeout") {
			continue
		}
	}

	// If we can't determine definitively due to network issues, return empty string
	// This will trigger the fallback logic in CheckAuth
	return true, ""
}
