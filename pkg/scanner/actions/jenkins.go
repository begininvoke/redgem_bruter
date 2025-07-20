package actions

import (
	"fmt"
	"strings"
)

// JenkinsAction implements Jenkins service scanning
type JenkinsAction struct {
	BaseAction
}

// NewJenkinsAction creates a new Jenkins action
func NewJenkinsAction() *JenkinsAction {
	return &JenkinsAction{
		BaseAction: BaseAction{},
	}
}

// CheckAuth checks if Jenkins requires authentication and potential vulnerabilities
func (j *JenkinsAction) CheckAuth() (bool, string, bool, error) {
	// First check if port is open
	open, err := j.CheckPort(j.Host, j.Port)
	if err != nil {
		return false, "", false, err
	}
	if !open {
		return false, "Port closed", false, nil
	}

	// Get banner to check version
	_, version, err := j.GetBanner()
	if err != nil {
		return false, "", false, err
	}

	// Check for known vulnerable versions
	vulnerable := false
	if strings.Contains(version, "Jenkins 2.0") || strings.Contains(version, "Jenkins 2.1") {
		vulnerable = true
	}

	// Run Jenkins-specific auth detection
	output, err := j.RunNmapScript(j.Host, j.Port, "http-auth")
	if err != nil {
		return false, "", false, err
	}

	// Check if authentication is required
	requiresAuth := strings.Contains(output, "authentication required") ||
		strings.Contains(output, "login required") ||
		strings.Contains(output, "credentials required")

	return requiresAuth, fmt.Sprintf("Jenkins %s - %s", version, output), vulnerable, nil
}

// CheckVulnerability checks for Jenkins-specific vulnerabilities
func (j *JenkinsAction) CheckVulnerability() (bool, string, error) {
	// Get version
	_, version, err := j.GetBanner()
	if err != nil {
		return false, "", err
	}

	vulnerabilities := []string{}

	// Check for known vulnerable versions
	if strings.Contains(version, "Jenkins 2.0") || strings.Contains(version, "Jenkins 2.1") {
		vulnerabilities = append(vulnerabilities, "Known vulnerable version")
	}

	// Check for default credentials
	output, err := j.RunNmapScript(j.Host, j.Port, "http-brute")
	if err == nil && strings.Contains(output, "Valid credentials") {
		vulnerabilities = append(vulnerabilities, "Default credentials found")
	}

	// Check for weak encryption
	output, err = j.RunNmapScript(j.Host, j.Port, "ssl-cert")
	if err == nil && strings.Contains(output, "Weak encryption") {
		vulnerabilities = append(vulnerabilities, "Weak encryption enabled")
	}

	if len(vulnerabilities) > 0 {
		return true, fmt.Sprintf("Vulnerabilities found: %s", strings.Join(vulnerabilities, ", ")), nil
	}

	return false, "No obvious vulnerabilities detected", nil
}

// BruteForce attempts to brute force Jenkins credentials
func (j *JenkinsAction) BruteForce() (bool, string, error) {
	// Run Jenkins brute force script
	output, err := j.RunNmapScript(j.Host, j.Port, "http-brute")
	if err != nil {
		return false, "", err
	}

	// Check if brute force was successful
	success := strings.Contains(output, "Valid credentials") ||
		strings.Contains(output, "Login successful")

	return success, output, nil
}
