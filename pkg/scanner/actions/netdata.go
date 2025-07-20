package actions

import (
	"fmt"
	"strings"
)

// NetdataAction implements Netdata service scanning
type NetdataAction struct {
	BaseAction
}

// NewNetdataAction creates a new Netdata action
func NewNetdataAction() *NetdataAction {
	return &NetdataAction{
		BaseAction: BaseAction{},
	}
}

// CheckAuth checks if Netdata requires authentication and potential vulnerabilities
func (n *NetdataAction) CheckAuth() (bool, string, bool, error) {
	open, err := n.CheckPort(n.Host, n.Port)
	if err != nil {
		return false, "", false, err
	}
	if !open {
		return false, "Port closed", false, nil
	}

	_, version, err := n.GetBanner()
	if err != nil {
		return false, "", false, err
	}

	vulnerable := false
	if strings.Contains(version, "Netdata 1.0") || strings.Contains(version, "Netdata 1.1") {
		vulnerable = true
	}

	output, err := n.RunNmapScript(n.Host, n.Port, "http-auth")
	if err != nil {
		return false, "", false, err
	}

	requiresAuth := strings.Contains(output, "authentication required") ||
		strings.Contains(output, "login required") ||
		strings.Contains(output, "credentials required")

	return requiresAuth, fmt.Sprintf("Netdata %s - %s", version, output), vulnerable, nil
}

// CheckVulnerability checks for Netdata-specific vulnerabilities
func (n *NetdataAction) CheckVulnerability() (bool, string, error) {
	_, version, err := n.GetBanner()
	if err != nil {
		return false, "", err
	}

	vulnerabilities := []string{}
	if strings.Contains(version, "Netdata 1.0") || strings.Contains(version, "Netdata 1.1") {
		vulnerabilities = append(vulnerabilities, "Known vulnerable version")
	}

	output, err := n.RunNmapScript(n.Host, n.Port, "http-brute")
	if err == nil && strings.Contains(output, "Valid credentials") {
		vulnerabilities = append(vulnerabilities, "Default credentials found")
	}

	output, err = n.RunNmapScript(n.Host, n.Port, "ssl-cert")
	if err == nil && strings.Contains(output, "Weak encryption") {
		vulnerabilities = append(vulnerabilities, "Weak encryption enabled")
	}

	if len(vulnerabilities) > 0 {
		return true, fmt.Sprintf("Vulnerabilities found: %s", strings.Join(vulnerabilities, ", ")), nil
	}

	return false, "No obvious vulnerabilities detected", nil
}

// BruteForce attempts to brute force Netdata credentials
func (n *NetdataAction) BruteForce() (bool, string, error) {
	output, err := n.RunNmapScript(n.Host, n.Port, "http-brute")
	if err != nil {
		return false, "", err
	}

	success := strings.Contains(output, "Valid credentials") ||
		strings.Contains(output, "Login successful")

	return success, output, nil
}
