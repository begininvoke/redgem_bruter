package actions

import (
	"fmt"
	"strings"
)

// MongoDBAction implements MongoDB service scanning
type MongoDBAction struct {
	BaseAction
}

// NewMongoDBAction creates a new MongoDB action
func NewMongoDBAction() *MongoDBAction {
	return &MongoDBAction{
		BaseAction: *NewBaseAction(),
	}
}

// CheckAuth checks if MongoDB requires authentication and potential vulnerabilities
func (m *MongoDBAction) CheckAuth() (bool, string, bool, error) {
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
	if strings.Contains(version, "3.0") || strings.Contains(version, "3.2") {
		vulnerable = true
	}

	// Run MongoDB-specific auth detection
	output, err := m.RunNmapScript(m.Host, m.Port, "mongodb-info")
	if err != nil {
		return false, "", false, err
	}

	// Check if authentication is required
	requiresAuth := strings.Contains(output, "authentication required") ||
		strings.Contains(output, "auth") ||
		strings.Contains(output, "login")

	return requiresAuth, fmt.Sprintf("MongoDB %s - %s", version, output), vulnerable, nil
}

// CheckVulnerability checks for MongoDB-specific vulnerabilities
func (m *MongoDBAction) CheckVulnerability() (bool, string, error) {
	// Get version
	_, version, err := m.GetBanner()
	if err != nil {
		return false, "", err
	}

	vulnerabilities := []string{}

	// Check for known vulnerable versions
	if strings.Contains(version, "3.0") || strings.Contains(version, "3.2") {
		vulnerabilities = append(vulnerabilities, "Known vulnerable version")
	}

	// Check for anonymous access
	output, err := m.RunNmapScript(m.Host, m.Port, "mongodb-brute")
	if err == nil && strings.Contains(output, "Anonymous access") {
		vulnerabilities = append(vulnerabilities, "Anonymous access allowed")
	}

	// Check for default credentials
	output, err = m.RunNmapScript(m.Host, m.Port, "mongodb-brute")
	if err == nil && strings.Contains(output, "Valid credentials") {
		vulnerabilities = append(vulnerabilities, "Default credentials found")
	}

	if len(vulnerabilities) > 0 {
		return true, fmt.Sprintf("Vulnerabilities found: %s", strings.Join(vulnerabilities, ", ")), nil
	}

	return false, "No obvious vulnerabilities detected", nil
}

// BruteForce attempts to brute force MongoDB credentials
func (m *MongoDBAction) BruteForce() (bool, string, error) {
	// Run MongoDB brute force script
	output, err := m.RunNmapScript(m.Host, m.Port, "mongodb-brute")
	if err != nil {
		return false, "", err
	}

	// Check if brute force was successful
	success := strings.Contains(output, "Valid credentials") ||
		strings.Contains(output, "Login successful")

	return success, output, nil
}
