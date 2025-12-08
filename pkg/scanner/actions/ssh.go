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
	// First check if port is open, but continue even if it appears filtered
	open, err := s.CheckPort(s.Host, s.Port)
	if err != nil {
		// If port check fails, still try to connect directly (might be filtered but accessible)
		return s.checkAuthDirect()
	}
	if !open {
		// Port appears closed/filtered, but try direct connection anyway
		return s.checkAuthDirect()
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

// checkAuthDirect performs direct SSH connection testing when port scanning is unreliable
func (s *SSHAction) checkAuthDirect() (bool, string, bool, error) {
	// Try a direct SSH connection with invalid credentials to test if SSH is running
	config := &ssh.ClientConfig{
		User: "nonexistent_user_test",
		Auth: []ssh.AuthMethod{
			ssh.Password("invalid_password_test"),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}

	addr := fmt.Sprintf("%s:%d", s.Host, s.Port)
	client, err := ssh.Dial("tcp", addr, config)
	if client != nil {
		client.Close()
	}

	if err != nil {
		errStr := err.Error()

		// If we get authentication errors, SSH service is confirmed running
		if strings.Contains(errStr, "authentication failed") ||
			strings.Contains(errStr, "permission denied") ||
			strings.Contains(errStr, "unable to authenticate") {
			return true, fmt.Sprintf("SSH service confirmed via direct connection test - %s", errStr), false, nil
		}

		// Connection timeouts might mean firewall/filtering - assume auth required for security
		if strings.Contains(errStr, "timeout") || strings.Contains(errStr, "i/o timeout") {
			return true, fmt.Sprintf("SSH service likely present but filtered/firewalled - %s", errStr), false, nil
		}

		// Connection refused means service is definitely not running
		if strings.Contains(errStr, "connection refused") ||
			strings.Contains(errStr, "network is unreachable") {
			return false, fmt.Sprintf("SSH service not accessible - %s", errStr), false, nil
		}

		// Other SSH protocol errors still indicate SSH service presence
		if strings.Contains(errStr, "ssh:") {
			return true, fmt.Sprintf("SSH service detected with protocol issues - %s", errStr), false, nil
		}
	}

	// If no error, authentication somehow succeeded (very unlikely with test credentials)
	return true, "SSH service confirmed - test authentication unexpectedly succeeded", false, nil
}

// getHardcodedSSHCredentials returns a hardcoded list of SSH credentials
func (s *SSHAction) getHardcodedSSHCredentials() []string {
	return []string{
		// Most common SSH credentials - PRIORITY ORDER

		"admin:123456",
		"user:123456",
		"root:password",
		"admin:password",
		"root:root",
		"admin:admin",
		"root:toor",
		"root:",
		"admin:",
		"root:123456",
		"user:password",
		"user:user",
		"user:",
		// Distribution-specific defaults
		"ubuntu:ubuntu",
		"ubuntu:123456",
		"centos:centos",
		"debian:debian",
		"fedora:fedora",
		"pi:raspberry",
		"pi:123456",
		// Service accounts
		"oracle:oracle",
		"postgres:postgres",
		"mysql:mysql",
		"redis:redis",
		"mongodb:mongodb",
		"elasticsearch:elasticsearch",
		// Common service users
		"backup:backup",
		"service:service",
		"support:support",
		"operator:operator",
		"manager:manager",
		"developer:developer",
		"webmaster:webmaster",
		"devops:123456",
		"devops:devops",
		// Test accounts
		"test:test",
		"demo:demo",
		"guest:guest",
		"anonymous:",
		// Weak passwords
		"root:qwerty",
		"admin:qwerty",
		"root:12345",
		"admin:12345",
		"root:letmein",
		"admin:letmein",
	}
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

// testHardcodedCredentials tests credentials from SSH wordlist or hardcoded fallback
func (s *SSHAction) testHardcodedCredentials() (bool, string) {
	var credentials []string

	// Try to read credentials from SSH wordlist file
	wordlistCreds, err := s.ReadServiceWordlist("ssh")
	if err != nil {
		// Fallback to hardcoded credentials when wordlist fails
		credentials = s.getHardcodedSSHCredentials()
	} else if len(wordlistCreds) == 0 {
		// Fallback to hardcoded credentials when wordlist is empty
		credentials = s.getHardcodedSSHCredentials()
	} else {
		credentials = wordlistCreds
	}

	var results []string
	successCount := 0

	// Limit the number of credentials to test to avoid long delays
	maxCredentials := 1000
	if len(credentials) > maxCredentials {
		credentials = credentials[:maxCredentials]
	}

	for i, credLine := range credentials {
		// Parse username:password format
		parts := strings.Split(strings.TrimSpace(credLine), ":")
		if len(parts) != 2 {
			continue // Skip malformed lines
		}

		username, password := parts[0], parts[1]

		// Test each credential
		fmt.Printf("Testing SSH %d/%d: %s:%s\n", i+1, len(credentials), username, password)

		// Test each credential with a fresh SSH connection
		success, message := s.testSSHLogin(username, password)

		if success {
			// Found valid credentials!
			return true, fmt.Sprintf("SSH login successful with %s:%s - %s [CREDS:%s:%s]", username, password, message, username, password)
		}

		results = append(results, fmt.Sprintf("%s:%s - %s", username, password, message))
		successCount++

		// Small delay between attempts to avoid overwhelming the target
		time.Sleep(100 * time.Millisecond)
	}

	return false, fmt.Sprintf("SSH wordlist tested (%d credentials from %d total): %s", successCount, len(credentials), strings.Join(results, "; "))
}

// testSSHLogin attempts to login to SSH with specific credentials
func (s *SSHAction) testSSHLogin(username, password string) (bool, string) {
	// Create SSH client configuration with more aggressive settings
	config := &ssh.ClientConfig{
		User: username,
		Auth: []ssh.AuthMethod{
			ssh.Password(password),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // For testing purposes
		Timeout:         10 * time.Second,            // Increased timeout for filtered ports
	}

	// Attempt to connect
	addr := fmt.Sprintf("%s:%d", s.Host, s.Port)
	client, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		// Check error type to determine what happened
		errStr := err.Error()

		// Authentication failed - this means SSH is working but credentials are wrong
		if strings.Contains(errStr, "authentication failed") ||
			strings.Contains(errStr, "permission denied") ||
			strings.Contains(errStr, "unable to authenticate") {
			return false, "authentication failed (SSH service confirmed)"
		}

		// Connection issues
		if strings.Contains(errStr, "connection refused") {
			return false, "connection refused"
		}
		if strings.Contains(errStr, "timeout") || strings.Contains(errStr, "i/o timeout") {
			return false, "connection timeout (firewall/filtered)"
		}
		if strings.Contains(errStr, "network is unreachable") {
			return false, "network unreachable"
		}
		if strings.Contains(errStr, "no route to host") {
			return false, "no route to host"
		}

		// SSH protocol errors (still indicates SSH service is present)
		if strings.Contains(errStr, "ssh:") {
			return false, fmt.Sprintf("SSH protocol error: %v", err)
		}

		return false, fmt.Sprintf("connection error: %v", err)
	}

	// If we got here, authentication was successful
	client.Close()
	return true, "authentication successful"
}
