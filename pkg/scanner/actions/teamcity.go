package actions

import (
	"fmt"
	"strings"
)

// TeamCityAction implements TeamCity service scanning
type TeamCityAction struct {
	BaseAction
}

// NewTeamCityAction creates a new TeamCity action
func NewTeamCityAction() *TeamCityAction {
	return &TeamCityAction{
		BaseAction: BaseAction{},
	}
}

// CheckAuth checks if TeamCity requires authentication and potential vulnerabilities
func (t *TeamCityAction) CheckAuth() (bool, string, bool, error) {
	// First check if port is open
	open, err := t.CheckPort(t.Host, t.Port)
	if err != nil {
		return false, "", false, err
	}
	if !open {
		return false, "Port closed", false, nil
	}

	// Get banner to check version
	_, version, err := t.GetBanner()
	if err != nil {
		return false, "", false, err
	}

	// Check for known vulnerable versions
	vulnerable := false
	if strings.Contains(version, "TeamCity 2017") || strings.Contains(version, "TeamCity 2018") {
		vulnerable = true
	}

	// Run TeamCity-specific auth detection
	output, err := t.RunNmapScript(t.Host, t.Port, "http-auth")
	if err != nil {
		return false, "", false, err
	}

	// Check if authentication is required
	requiresAuth := strings.Contains(output, "authentication required") ||
		strings.Contains(output, "login required") ||
		strings.Contains(output, "credentials required")

	return requiresAuth, fmt.Sprintf("TeamCity %s - %s", version, output), vulnerable, nil
}

// CheckVulnerability checks for TeamCity-specific vulnerabilities
func (t *TeamCityAction) CheckVulnerability() (bool, string, error) {
	// Get version
	_, version, err := t.GetBanner()
	if err != nil {
		return false, "", err
	}

	vulnerabilities := []string{}

	// Check for known vulnerable versions
	if strings.Contains(version, "TeamCity 2017") || strings.Contains(version, "TeamCity 2018") {
		vulnerabilities = append(vulnerabilities, "Known vulnerable version")
	}

	// Check for default credentials
	output, err := t.RunNmapScript(t.Host, t.Port, "http-brute")
	if err == nil && strings.Contains(output, "Valid credentials") {
		vulnerabilities = append(vulnerabilities, "Default credentials found")
	}

	// Check for weak encryption
	output, err = t.RunNmapScript(t.Host, t.Port, "ssl-cert")
	if err == nil && strings.Contains(output, "Weak encryption") {
		vulnerabilities = append(vulnerabilities, "Weak encryption enabled")
	}

	if len(vulnerabilities) > 0 {
		return true, fmt.Sprintf("Vulnerabilities found: %s", strings.Join(vulnerabilities, ", ")), nil
	}

	return false, "No obvious vulnerabilities detected", nil
}

// BruteForce attempts to brute force TeamCity credentials
func (t *TeamCityAction) BruteForce() (bool, string, error) {
	// Run TeamCity brute force script
	output, err := t.RunNmapScript(t.Host, t.Port, "http-brute")
	if err != nil {
		return false, "", err
	}

	// Check if brute force was successful
	success := strings.Contains(output, "Valid credentials") ||
		strings.Contains(output, "Login successful")

	return success, output, nil
}
