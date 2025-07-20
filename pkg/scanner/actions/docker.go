package actions

import (
	"fmt"
	"strings"
)

// DockerAction implements Docker service scanning
type DockerAction struct {
	BaseAction
}

// NewDockerAction creates a new Docker action
func NewDockerAction() *DockerAction {
	return &DockerAction{
		BaseAction: BaseAction{},
	}
}

// CheckAuth checks if Docker requires authentication and potential vulnerabilities
func (d *DockerAction) CheckAuth() (bool, string, bool, error) {
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
	if strings.Contains(version, "Docker 1.12") || strings.Contains(version, "Docker 1.13") {
		vulnerable = true
	}

	// Run Docker-specific auth detection
	output, err := d.RunNmapScript(d.Host, d.Port, "docker-info")
	if err != nil {
		return false, "", false, err
	}

	// Check if authentication is required
	requiresAuth := strings.Contains(output, "authentication required") ||
		strings.Contains(output, "login required") ||
		strings.Contains(output, "credentials required")

	return requiresAuth, fmt.Sprintf("Docker %s - %s", version, output), vulnerable, nil
}

// CheckVulnerability checks for Docker-specific vulnerabilities
func (d *DockerAction) CheckVulnerability() (bool, string, error) {
	// Get version
	_, version, err := d.GetBanner()
	if err != nil {
		return false, "", err
	}

	vulnerabilities := []string{}

	// Check for known vulnerable versions
	if strings.Contains(version, "Docker 1.12") || strings.Contains(version, "Docker 1.13") {
		vulnerabilities = append(vulnerabilities, "Known vulnerable version")
	}

	// Check for default credentials
	output, err := d.RunNmapScript(d.Host, d.Port, "docker-brute")
	if err == nil && strings.Contains(output, "Valid credentials") {
		vulnerabilities = append(vulnerabilities, "Default credentials found")
	}

	// Check for weak encryption
	output, err = d.RunNmapScript(d.Host, d.Port, "ssl-cert")
	if err == nil && strings.Contains(output, "Weak encryption") {
		vulnerabilities = append(vulnerabilities, "Weak encryption enabled")
	}

	if len(vulnerabilities) > 0 {
		return true, fmt.Sprintf("Vulnerabilities found: %s", strings.Join(vulnerabilities, ", ")), nil
	}

	return false, "No obvious vulnerabilities detected", nil
}

// BruteForce attempts to brute force Docker credentials
func (d *DockerAction) BruteForce() (bool, string, error) {
	// Run Docker brute force script
	output, err := d.RunNmapScript(d.Host, d.Port, "docker-brute")
	if err != nil {
		return false, "", err
	}

	// Check if brute force was successful
	success := strings.Contains(output, "Valid credentials") ||
		strings.Contains(output, "Login successful")

	return success, output, nil
}
