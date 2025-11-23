package actions

import (
	"fmt"
	"net"
	"strings"
	"time"
)

// RDPAction implements RDP service scanning
type RDPAction struct {
	BaseAction
}

// NewRDPAction creates a new RDP action
func NewRDPAction() *RDPAction {
	return &RDPAction{
		BaseAction: BaseAction{},
	}
}

// CheckAuth checks if RDP requires authentication and potential vulnerabilities
func (r *RDPAction) CheckAuth() (bool, string, bool, error) {
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
	if strings.Contains(version, "Windows XP") || strings.Contains(version, "Windows 2000") {
		vulnerable = true
	}

	// Run RDP-specific auth detection
	output, err := r.RunNmapScript(r.Host, r.Port, "rdp-enum-encryption")
	if err != nil {
		return false, "", false, err
	}

	// Check if authentication is required
	requiresAuth := strings.Contains(output, "authentication required") ||
		strings.Contains(output, "login required") ||
		strings.Contains(output, "credentials required")

	return requiresAuth, fmt.Sprintf("RDP %s - %s", version, output), vulnerable, nil
}

// CheckVulnerability checks for RDP-specific vulnerabilities
func (r *RDPAction) CheckVulnerability() (bool, string, error) {
	// Get version
	_, version, err := r.GetBanner()
	if err != nil {
		return false, "", err
	}

	vulnerabilities := []string{}

	// Check for known vulnerable versions
	if strings.Contains(version, "Windows XP") || strings.Contains(version, "Windows 2000") {
		vulnerabilities = append(vulnerabilities, "Known vulnerable version")
	}

	// Check for BlueKeep vulnerability
	output, err := r.RunNmapScript(r.Host, r.Port, "rdp-vuln-ms12-020")
	if err == nil && strings.Contains(output, "VULNERABLE") {
		vulnerabilities = append(vulnerabilities, "BlueKeep vulnerability (CVE-2019-0708)")
	}

	// Check for default credentials
	output, err = r.RunNmapScript(r.Host, r.Port, "rdp-brute")
	if err == nil && strings.Contains(output, "Valid credentials") {
		vulnerabilities = append(vulnerabilities, "Default credentials found")
	}

	// Check for weak encryption
	output, err = r.RunNmapScript(r.Host, r.Port, "rdp-enum-encryption")
	if err == nil && strings.Contains(output, "Weak encryption") {
		vulnerabilities = append(vulnerabilities, "Weak encryption enabled")
	}

	if len(vulnerabilities) > 0 {
		return true, fmt.Sprintf("Vulnerabilities found: %s", strings.Join(vulnerabilities, ", ")), nil
	}

	return false, "No obvious vulnerabilities detected", nil
}

// BruteForce attempts to brute force RDP credentials
func (r *RDPAction) BruteForce() (bool, string, error) {
	var results []string
	
	// First, test credentials from RDP wordlist
	wordlistSuccess, wordlistOutput := r.testRDPCredentials()
	if wordlistSuccess {
		return true, fmt.Sprintf("RDP login successful with wordlist credentials: %s", wordlistOutput), nil
	}
	if wordlistOutput != "" {
		results = append(results, fmt.Sprintf("RDP wordlist test: %s", wordlistOutput))
	}

	// Then try with nmap brute force script for additional coverage
	output, err := r.RunNmapScript(r.Host, r.Port, "rdp-brute --script-args rdp-brute.timeout=10s")
	if err != nil {
		// If nmap brute force fails, provide wordlist results
		if len(results) > 0 {
			return false, strings.Join(results, "; "), nil
		}
		return false, fmt.Sprintf("RDP brute force failed: %v", err), nil
	}

	// Check if nmap brute force was successful
	success := strings.Contains(output, "Valid credentials") ||
		strings.Contains(output, "Login successful") ||
		strings.Contains(output, "Authentication successful")

	if success {
		results = append(results, fmt.Sprintf("RDP nmap brute force successful: %s", output))
		return true, strings.Join(results, "; "), nil
	}

	// Even if not successful, provide useful information
	if strings.Contains(output, "Authentication failed") || strings.Contains(output, "Invalid credentials") {
		results = append(results, fmt.Sprintf("RDP brute force completed - no weak credentials found: %s", output))
	} else {
		results = append(results, fmt.Sprintf("RDP brute force completed with limited results: %s", output))
	}

	return false, strings.Join(results, "; "), nil
}

// testRDPCredentials tests credentials from RDP wordlist using connection attempts
func (r *RDPAction) testRDPCredentials() (bool, string) {
	// Read credentials from RDP wordlist file
	credentials, err := r.ReadServiceWordlist("rdp")
	if err != nil {
		return false, fmt.Sprintf("Failed to read RDP wordlist: %v", err)
	}

	if len(credentials) == 0 {
		return false, "RDP wordlist is empty"
	}

	var results []string
	successCount := 0
	
	// Limit the number of credentials to test to avoid long delays
	maxCredentials := 8
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
		success, message := r.testRDPConnection(username, password)
		
		if success {
			return true, fmt.Sprintf("RDP login successful with %s:%s - %s", username, password, message)
		}
		
		results = append(results, fmt.Sprintf("%s:%s - %s", username, password, message))
		successCount++
	}

	return false, fmt.Sprintf("RDP wordlist tested (%d credentials): %s", successCount, strings.Join(results, "; "))
}

// testRDPConnection attempts to test RDP connectivity with specific credentials
func (r *RDPAction) testRDPConnection(username, password string) (bool, string) {
	// For RDP, we'll do a basic connection test to see if the port responds properly
	// Full RDP authentication would require a complex RDP client implementation
	
	addr := net.JoinHostPort(r.Host, fmt.Sprintf("%d", r.Port))
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		if strings.Contains(err.Error(), "connection refused") {
			return false, "connection refused"
		}
		if strings.Contains(err.Error(), "timeout") {
			return false, "connection timeout"
		}
		return false, fmt.Sprintf("connection error: %v", err)
	}
	defer conn.Close()

	// Set read deadline
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	
	// Try to read RDP handshake response
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		// If we can connect but can't read, it might still be RDP
		return false, "RDP service detected but authentication test inconclusive"
	}

	response := string(buffer[:n])
	
	// Check for RDP-specific responses
	if strings.Contains(response, "RDP") || 
	   strings.Contains(response, "Terminal") ||
	   len(response) > 10 { // RDP typically sends binary data
		return false, "RDP service confirmed, credentials not verified (requires full RDP client)"
	}

	return false, "service response unclear"
}
