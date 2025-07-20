package actions

import (
	"fmt"
	"strings"
)

// FTPAction implements FTP service scanning
type FTPAction struct {
	BaseAction
}

// NewFTPAction creates a new FTP action
func NewFTPAction() *FTPAction {
	return &FTPAction{
		BaseAction: *NewBaseAction(),
	}
}

// CheckAuth checks if FTP requires authentication and potential vulnerabilities
func (f *FTPAction) CheckAuth() (bool, string, bool, error) {
	// First check if port is open
	open, err := f.CheckPort(f.Host, f.Port)
	if err != nil {
		return false, "", false, err
	}
	if !open {
		return false, "Port closed", false, nil
	}

	// Get banner to check version
	_, version, err := f.GetBanner()
	if err != nil {
		return false, "", false, err
	}

	// Check for known vulnerable versions
	vulnerable := false
	if strings.Contains(version, "vsFTPd 2.3.2") || strings.Contains(version, "vsFTPd 2.3.4") {
		vulnerable = true
	}

	// Run FTP-specific auth detection
	output, err := f.RunNmapScript(f.Host, f.Port, "ftp-anon")
	if err != nil {
		return false, "", false, err
	}

	// Check if authentication is required
	requiresAuth := strings.Contains(output, "authentication required") ||
		strings.Contains(output, "Login failed") ||
		strings.Contains(output, "530")

	return requiresAuth, fmt.Sprintf("FTP %s - %s", version, output), vulnerable, nil
}

// CheckVulnerability checks for FTP-specific vulnerabilities
func (f *FTPAction) CheckVulnerability() (bool, string, error) {
	// Get version
	_, version, err := f.GetBanner()
	if err != nil {
		return false, "", err
	}

	vulnerabilities := []string{}

	// Check for known vulnerable versions
	if strings.Contains(version, "vsFTPd 2.3.2") || strings.Contains(version, "vsFTPd 2.3.4") {
		vulnerabilities = append(vulnerabilities, "Known vulnerable version (backdoor)")
	}

	// Check for anonymous access
	output, err := f.RunNmapScript(f.Host, f.Port, "ftp-anon")
	if err == nil && strings.Contains(output, "Anonymous access") {
		vulnerabilities = append(vulnerabilities, "Anonymous access allowed")
	}

	// Check for default credentials
	output, err = f.RunNmapScript(f.Host, f.Port, "ftp-brute")
	if err == nil && strings.Contains(output, "Valid credentials") {
		vulnerabilities = append(vulnerabilities, "Default credentials found")
	}

	// Check for bounce attack vulnerability
	output, err = f.RunNmapScript(f.Host, f.Port, "ftp-bounce")
	if err == nil && strings.Contains(output, "VULNERABLE") {
		vulnerabilities = append(vulnerabilities, "FTP bounce attack possible")
	}

	if len(vulnerabilities) > 0 {
		return true, fmt.Sprintf("Vulnerabilities found: %s", strings.Join(vulnerabilities, ", ")), nil
	}

	return false, "No obvious vulnerabilities detected", nil
}

// BruteForce attempts to brute force FTP credentials
func (f *FTPAction) BruteForce() (bool, string, error) {
	// Run FTP brute force script
	output, err := f.RunNmapScript(f.Host, f.Port, "ftp-brute")
	if err != nil {
		return false, "", err
	}

	// Check if brute force was successful
	success := strings.Contains(output, "Valid credentials") ||
		strings.Contains(output, "Login successful")

	return success, output, nil
}
