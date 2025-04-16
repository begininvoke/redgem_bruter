package actions

import (
	"fmt"
	"strings"
	"time"

	"redgem_bruter/pkg/nmap"
)

// ServiceAction defines the interface for service-specific actions
type ServiceAction interface {
	CheckAuth(host string, port int) (bool, string, error)
	BruteForce(host string, port int, wordlist string) (bool, string, error)
}

// BaseAction provides common functionality for all service actions
type BaseAction struct {
	Timeout     time.Duration
	nmapScanner *nmap.NmapScanner
}

// NewBaseAction creates a new BaseAction with default timeout
func NewBaseAction() *BaseAction {
	return &BaseAction{
		Timeout:     5 * time.Second,
		nmapScanner: nmap.NewNmapScanner(5 * time.Second),
	}
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

// CheckAuth is the default implementation for checking authentication
func (b *BaseAction) CheckAuth(host string, port int) (bool, string, error) {
	// First check if port is open
	open, err := b.CheckPort(host, port)
	if err != nil {
		return false, "", err
	}
	if !open {
		return false, "Port closed", nil
	}

	// Run a generic auth detection script
	output, err := b.RunNmapScript(host, port, "auth-finder")
	if err != nil {
		return false, "", err
	}

	// Check if authentication is required
	requiresAuth := strings.Contains(output, "authentication required") ||
		strings.Contains(output, "auth") ||
		strings.Contains(output, "login") ||
		strings.Contains(output, "password")

	return requiresAuth, output, nil
}

// BruteForce is the default implementation for brute force attempts
func (b *BaseAction) BruteForce(host string, port int, wordlist string) (bool, string, error) {
	return false, "Brute force not implemented for this service", nil
}
