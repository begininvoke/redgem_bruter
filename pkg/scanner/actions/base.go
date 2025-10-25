package actions

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"redgem_bruter/pkg/nmap"
)

// ServiceAction defines the interface for service-specific actions
type ServiceAction interface {
	CheckAuth() (bool, string, bool, error)
	CheckVulnerability() (bool, string, error)
	BruteForce() (bool, string, error)
	GetBanner() (string, string, error)
	SetHost(host string)
	SetPort(port int)
}

// BaseAction provides common functionality for all service actions
type BaseAction struct {
	Timeout     time.Duration
	nmapScanner *nmap.NmapScanner
	Host        string
	Port        int
}

// NewBaseAction creates a new BaseAction with default timeout
func NewBaseAction() *BaseAction {
	return &BaseAction{
		Timeout:     5 * time.Second,
		nmapScanner: nmap.NewNmapScanner(5 * time.Second),
	}
}

// SetHost sets the host for the action
func (b *BaseAction) SetHost(host string) {
	b.Host = host
}

// SetPort sets the port for the action
func (b *BaseAction) SetPort(port int) {
	b.Port = port
}

// CheckPort checks if a port is open on the specified host
func (b *BaseAction) CheckPort(host string, port int) (bool, error) {
	openPorts, err := b.nmapScanner.ScanPorts(host, []int{port})
	if err != nil {
		return false, fmt.Errorf("failed to scan port: %v", err)
	}

	return len(openPorts) > 0, nil
}

// RunNmapScript runs an Nmap script and returns the output
func (b *BaseAction) RunNmapScript(host string, port int, script string) (string, error) {
	// Use the NmapScanner to run the script
	scriptResults, err := b.nmapScanner.RunNmapScript(host, port, script)
	if err != nil {
		return "", fmt.Errorf("failed to run nmap script: %v", err)
	}

	// Combine all script outputs into a single string
	var output string
	for scriptName, scriptOutput := range scriptResults {
		output += fmt.Sprintf("Script %s output:\n%s\n", scriptName, scriptOutput)
	}

	return output, nil
}

// GetBanner attempts to get the service banner and version
func (b *BaseAction) GetBanner() (string, string, error) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", b.Host, b.Port), 5*time.Second)
	if err != nil {
		return "", "", err
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	reader := bufio.NewReader(conn)
	banner, err := reader.ReadString('\n')
	if err != nil {
		return "", "", err
	}

	// Try to extract version based on service type
	version := extractVersion(banner)
	return strings.TrimSpace(banner), version, nil
}

// ReadServiceWordlist reads credentials from a service-specific wordlist
func (b *BaseAction) ReadServiceWordlist(service string) ([]string, error) {
	wordlistPath := filepath.Join("pkg", "scanner", "wordlists", service+".txt")
	file, err := os.Open(wordlistPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open wordlist file: %v", err)
	}
	defer file.Close()

	var credentials []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			credentials = append(credentials, line)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading wordlist: %v", err)
	}

	return credentials, nil
}

// extractVersion attempts to extract version information from a banner
func extractVersion(banner string) string {
	// Common version patterns
	patterns := []struct {
		service string
		pattern string
	}{
		{"SSH", "SSH-\\d+\\.\\d+"},
		{"FTP", "vsFTPd \\d+\\.\\d+"},
		{"HTTP", "Server: [^\\r\\n]+"},
		{"MySQL", "\\d+\\.\\d+\\.\\d+"},
		{"PostgreSQL", "\\d+\\.\\d+"},
		{"Redis", "redis_version:\\d+\\.\\d+"},
		{"MongoDB", "\\d+\\.\\d+\\.\\d+"},
	}

	for _, p := range patterns {
		if strings.Contains(banner, p.service) {
			// Extract version using pattern
			// This is a simplified version - you might want to use regex for more precise matching
			parts := strings.Split(banner, p.service)
			if len(parts) > 1 {
				return strings.TrimSpace(parts[1])
			}
		}
	}

	return ""
}

// CheckAuth is the default implementation for checking authentication
func (b *BaseAction) CheckAuth() (bool, string, bool, error) {
	// First check if port is open
	open, err := b.CheckPort(b.Host, b.Port)
	if err != nil {
		return false, "", false, err
	}
	if !open {
		return false, "Port closed", false, nil
	}

	// Try to get banner first to see if it indicates authentication
	banner, _, err := b.GetBanner()
	if err == nil && banner != "" {
		// Check banner for authentication indicators
		if strings.Contains(strings.ToLower(banner), "authentication") ||
			strings.Contains(strings.ToLower(banner), "login") ||
			strings.Contains(strings.ToLower(banner), "password") ||
			strings.Contains(strings.ToLower(banner), "credentials") {
			return true, fmt.Sprintf("Authentication indicated in banner: %s", banner), false, nil
		}
	}

	// Run a generic auth detection script
	output, err := b.RunNmapScript(b.Host, b.Port, "auth-finder")
	if err != nil {
		// If nmap script fails, try alternative approach
		output, err = b.RunNmapScript(b.Host, b.Port, "banner")
		if err != nil {
			return false, "", false, err
		}
	}

	// Check if authentication is required
	requiresAuth := strings.Contains(output, "authentication required") ||
		strings.Contains(output, "auth") ||
		strings.Contains(output, "login") ||
		strings.Contains(output, "password") ||
		strings.Contains(output, "credentials") ||
		strings.Contains(output, "WWW-Authenticate") ||
		strings.Contains(output, "Basic realm") ||
		strings.Contains(output, "Digest realm")

	// If nmap script doesn't provide clear info, assume auth might be required
	// This is a conservative approach for security-focused scanning
	if !strings.Contains(output, "anonymous") && !strings.Contains(output, "no auth") && !strings.Contains(output, "public") {
		requiresAuth = true
	}

	return requiresAuth, output, false, nil
}

// CheckVulnerability is the default implementation for vulnerability checking
func (b *BaseAction) CheckVulnerability() (bool, string, error) {
	// Run a generic vulnerability scan
	output, err := b.RunNmapScript(b.Host, b.Port, "vuln")
	if err != nil {
		return false, "", err
	}

	// Check for common vulnerability indicators
	vulnerable := strings.Contains(output, "VULNERABLE") ||
		strings.Contains(output, "vulnerable") ||
		strings.Contains(output, "CVE") ||
		strings.Contains(output, "exploit")

	if vulnerable {
		return true, output, nil
	}

	return false, "No obvious vulnerabilities detected", nil
}

// BruteForce is the default implementation for brute force attempts
func (b *BaseAction) BruteForce() (bool, string, error) {
	return false, "Brute force not implemented for this service", nil
}
