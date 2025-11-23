package actions

import (
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// SSHAction implements SSH service scanning
type SSHAction struct {
	BaseAction
}

// NewSSHAction creates a new SSH action
func NewSSHAction() *SSHAction {
	return &SSHAction{
		BaseAction: *NewBaseAction(),
	}
}

// CheckAuth checks if SSH requires authentication and potential vulnerabilities
func (s *SSHAction) CheckAuth() (bool, string, bool, error) {
	// First check if port is open
	open, err := s.CheckPort(s.Host, s.Port)
	if err != nil {
		return false, "", false, err
	}
	if !open {
		return false, "Port closed", false, nil
	}

	// Get banner to check version and potential vulnerabilities
	_, version, err := s.GetBanner()
	if err != nil {
		return false, "", false, err
	}

	// Check for known vulnerable versions
	vulnerable := false
	if strings.Contains(version, "7.2") || strings.Contains(version, "7.3") {
		vulnerable = true
	}

	// Run SSH-specific auth detection
	output, err := s.RunNmapScript(s.Host, s.Port, "ssh-auth-methods")
	if err != nil {
		return false, "", false, err
	}

	// Check if authentication is required
	requiresAuth := strings.Contains(output, "publickey") ||
		strings.Contains(output, "password") ||
		strings.Contains(output, "keyboard-interactive")

	return requiresAuth, fmt.Sprintf("SSH %s - %s", version, output), vulnerable, nil
}

// CheckVulnerability checks for SSH-specific vulnerabilities
func (s *SSHAction) CheckVulnerability() (bool, string, error) {
	// Get banner and version
	_, version, err := s.GetBanner()
	if err != nil {
		return false, "", err
	}

	vulnerabilities := []string{}

	// Check for known vulnerable versions
	if strings.Contains(version, "7.2") || strings.Contains(version, "7.3") {
		vulnerabilities = append(vulnerabilities, "Known vulnerable version")
	}

	// Check for weak algorithms
	output, err := s.RunNmapScript(s.Host, s.Port, "ssh2-enum-algos")
	if err == nil {
		if strings.Contains(output, "arcfour") || strings.Contains(output, "blowfish") {
			vulnerabilities = append(vulnerabilities, "Weak encryption algorithms supported")
		}
	}

	// Check for default credentials
	output, err = s.RunNmapScript(s.Host, s.Port, "ssh-default-accounts")
	if err == nil && strings.Contains(output, "Valid credentials") {
		vulnerabilities = append(vulnerabilities, "Default credentials found")
	}

	if len(vulnerabilities) > 0 {
		return true, fmt.Sprintf("Vulnerabilities found: %s", strings.Join(vulnerabilities, ", ")), nil
	}

	return false, "No obvious vulnerabilities detected", nil
}

// BruteForce attempts to brute force SSH credentials
func (s *SSHAction) BruteForce() (bool, string, error) {
	var results []string

	// First, test credentials from SSH wordlist
	wordlistSuccess, wordlistOutput := s.testHardcodedCredentials()
	if wordlistSuccess {
		return true, fmt.Sprintf("SSH login successful with wordlist credentials: %s", wordlistOutput), nil
	}
	if wordlistOutput != "" {
		results = append(results, fmt.Sprintf("SSH wordlist test: %s", wordlistOutput))
	}

	// Then try with nmap brute force script for additional common credentials
	output, err := s.RunNmapScript(s.Host, s.Port, "ssh-brute --script-args ssh-brute.timeout=10s")
	if err != nil {
		// If the full brute force fails, try a quick check for common accounts
		quickOutput, quickErr := s.RunNmapScript(s.Host, s.Port, "ssh-auth-methods")
		if quickErr != nil {
			if len(results) > 0 {
				return false, strings.Join(results, "; "), nil
			}
			return false, "", fmt.Errorf("SSH brute force timed out or was killed - this is normal for well-secured SSH services")
		}

		// Check if we can at least determine authentication methods
		if strings.Contains(quickOutput, "password") {
			results = append(results, fmt.Sprintf("SSH requires password authentication but brute force was limited due to timeout constraints: %s", quickOutput))
			return false, strings.Join(results, "; "), nil
		}

		results = append(results, fmt.Sprintf("SSH brute force could not complete due to timeout, but service appears to require authentication: %s", quickOutput))
		return false, strings.Join(results, "; "), nil
	}

	// Check if nmap brute force was successful
	success := strings.Contains(output, "Valid credentials") ||
		strings.Contains(output, "Login successful") ||
		strings.Contains(output, "Authentication successful")

	if success {
		results = append(results, fmt.Sprintf("SSH brute force successful: %s", output))
		return true, strings.Join(results, "; "), nil
	}

	// Even if not successful, provide useful information
	if strings.Contains(output, "Authentication failed") || strings.Contains(output, "Invalid credentials") {
		results = append(results, fmt.Sprintf("SSH brute force completed - no weak credentials found: %s", output))
	} else {
		results = append(results, fmt.Sprintf("SSH brute force completed with limited results: %s", output))
	}

	return false, strings.Join(results, "; "), nil
}

// testHardcodedCredentials tests credentials from SSH wordlist using direct SSH connection
func (s *SSHAction) testHardcodedCredentials() (bool, string) {
	// Read credentials from SSH wordlist file
	credentials, err := s.ReadServiceWordlist("ssh")
	if err != nil {
		return false, fmt.Sprintf("Failed to read SSH wordlist: %v", err)
	}

	if len(credentials) == 0 {
		return false, "SSH wordlist is empty"
	}

	var results []string
	successCount := 0

	// Limit the number of credentials to test to avoid long delays
	maxCredentials := 10
	if len(credentials) > maxCredentials {
		credentials = credentials[:maxCredentials]
	}

	for _, credLine := range credentials {
		// Parse username:password format
		parts := strings.Split(strings.TrimSpace(credLine), ":")
		if len(parts) != 2 {
			continue // Skip malformed lines
		}

		username, password := parts[0], parts[1]
		success, message := s.testSSHLogin(username, password)

		if success {
			return true, fmt.Sprintf("SSH login successful with %s:%s - %s", username, password, message)
		}

		results = append(results, fmt.Sprintf("%s:%s - %s", username, password, message))
		successCount++
	}

	return false, fmt.Sprintf("SSH wordlist tested (%d credentials): %s", successCount, strings.Join(results, "; "))
}

// testSSHLogin attempts to login to SSH with specific credentials
func (s *SSHAction) testSSHLogin(username, password string) (bool, string) {
	// Create SSH client configuration
	config := &ssh.ClientConfig{
		User: username,
		Auth: []ssh.AuthMethod{
			ssh.Password(password),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // For testing purposes
		Timeout:         5 * time.Second,
	}

	// Attempt to connect
	addr := fmt.Sprintf("%s:%d", s.Host, s.Port)
	client, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		// Check error type to determine what happened
		if strings.Contains(err.Error(), "authentication failed") ||
			strings.Contains(err.Error(), "permission denied") {
			return false, "authentication failed"
		}
		if strings.Contains(err.Error(), "connection refused") {
			return false, "connection refused"
		}
		if strings.Contains(err.Error(), "timeout") {
			return false, "connection timeout"
		}
		return false, fmt.Sprintf("connection error: %v", err)
	}

	// If we got here, authentication was successful
	client.Close()
	return true, "authentication successful"
}
