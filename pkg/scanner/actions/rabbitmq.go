package actions

import (
	"fmt"
	"strings"
)

// RabbitMQAction implements RabbitMQ service scanning
type RabbitMQAction struct {
	BaseAction
}

// NewRabbitMQAction creates a new RabbitMQ action
func NewRabbitMQAction() *RabbitMQAction {
	return &RabbitMQAction{
		BaseAction: BaseAction{},
	}
}

// CheckAuth checks if RabbitMQ requires authentication and potential vulnerabilities
func (r *RabbitMQAction) CheckAuth() (bool, string, bool, error) {
	// First check if port is open
	open, err := r.CheckPort(r.Host, r.Port)
	if err != nil {
		return false, "", false, err
	}
	if !open {
		return false, "Port closed", false, nil
	}

	// Get banner to check version
	_, version, err := r.GetBanner()
	if err != nil {
		return false, "", false, err
	}

	// Check for known vulnerable versions
	vulnerable := false
	if strings.Contains(version, "RabbitMQ 3.6") || strings.Contains(version, "RabbitMQ 3.7") {
		vulnerable = true
	}

	// Run RabbitMQ-specific auth detection
	output, err := r.RunNmapScript(r.Host, r.Port, "amqp-info")
	if err != nil {
		return false, "", false, err
	}

	// Check if authentication is required - RabbitMQ typically requires auth by default
	requiresAuth := strings.Contains(output, "authentication required") ||
		strings.Contains(output, "login required") ||
		strings.Contains(output, "credentials required") ||
		strings.Contains(output, "authentication") ||
		strings.Contains(output, "login") ||
		strings.Contains(output, "credentials")

	// If nmap script doesn't provide clear info, assume auth is required (default RabbitMQ behavior)
	if !strings.Contains(output, "anonymous") && !strings.Contains(output, "no auth") && !strings.Contains(output, "guest") {
		requiresAuth = true
	}

	return requiresAuth, fmt.Sprintf("RabbitMQ %s - %s", version, output), vulnerable, nil
}

// CheckVulnerability checks for RabbitMQ-specific vulnerabilities
func (r *RabbitMQAction) CheckVulnerability() (bool, string, error) {
	// Get version
	_, version, err := r.GetBanner()
	if err != nil {
		return false, "", err
	}

	vulnerabilities := []string{}

	// Check for known vulnerable versions
	if strings.Contains(version, "RabbitMQ 3.6") || strings.Contains(version, "RabbitMQ 3.7") {
		vulnerabilities = append(vulnerabilities, "Known vulnerable version")
	}

	// Check for default credentials
	output, err := r.RunNmapScript(r.Host, r.Port, "amqp-brute")
	if err == nil && strings.Contains(output, "Valid credentials") {
		vulnerabilities = append(vulnerabilities, "Default credentials found")
	}

	// Check for weak encryption
	output, err = r.RunNmapScript(r.Host, r.Port, "ssl-cert")
	if err == nil && strings.Contains(output, "Weak encryption") {
		vulnerabilities = append(vulnerabilities, "Weak encryption enabled")
	}

	if len(vulnerabilities) > 0 {
		return true, fmt.Sprintf("Vulnerabilities found: %s", strings.Join(vulnerabilities, ", ")), nil
	}

	return false, "No obvious vulnerabilities detected", nil
}

// BruteForce attempts to brute force RabbitMQ credentials
func (r *RabbitMQAction) BruteForce() (bool, string, error) {
	// Run RabbitMQ brute force script
	output, err := r.RunNmapScript(r.Host, r.Port, "amqp-brute")
	if err != nil {
		return false, "", err
	}

	// Check if brute force was successful
	success := strings.Contains(output, "Valid credentials") ||
		strings.Contains(output, "Login successful")

	return success, output, nil
}
