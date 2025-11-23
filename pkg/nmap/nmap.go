package nmap

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Ullaakut/nmap/v3"
)

// NmapScanner provides functionality for running Nmap scans
type NmapScanner struct {
	Timeout time.Duration
}

// NewNmapScanner creates a new NmapScanner with the specified timeout
func NewNmapScanner(timeout time.Duration) *NmapScanner {
	return &NmapScanner{
		Timeout: timeout,
	}
}

// ScanPorts scans the specified ports on a host
func (n *NmapScanner) ScanPorts(host string, ports []int) ([]int, error) {
	// Convert ports to strings for nmap
	portStrings := make([]string, len(ports))
	for i, port := range ports {
		portStrings[i] = fmt.Sprintf("%d", port)
	}

	ctx, cancel := context.WithTimeout(context.Background(), n.Timeout)
	defer cancel()

	// Create nmap scanner
	scanner, err := nmap.NewScanner(
		ctx,
		nmap.WithTargets(host),
		nmap.WithPorts(portStrings...),
		nmap.WithTimingTemplate(nmap.TimingAggressive),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create nmap scanner: %v", err)
	}

	// Run scan
	result, _, err := scanner.Run()
	if err != nil {
		return nil, fmt.Errorf("failed to run nmap scan: %v", err)
	}

	// Extract open ports
	var openPorts []int
	for _, host := range result.Hosts {
		for _, port := range host.Ports {
			if port.State.State == "open" {
				openPorts = append(openPorts, int(port.ID))
			}
		}
	}

	return openPorts, nil
}

// RunNmapScript runs an Nmap script and returns the output
func (n *NmapScanner) RunNmapScript(host string, port int, script string) (map[string]string, error) {
	// Use a longer timeout for brute force scripts
	timeout := n.Timeout
	if strings.Contains(script, "brute") {
		timeout = timeout * 3 // Triple the timeout for brute force operations
	}
	
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Create nmap scanner with appropriate timing
	timingTemplate := nmap.TimingAggressive
	if strings.Contains(script, "brute") {
		timingTemplate = nmap.TimingNormal // Use normal timing for brute force to avoid being too aggressive
	}

	scanner, err := nmap.NewScanner(
		ctx,
		nmap.WithTargets(host),
		nmap.WithPorts(fmt.Sprintf("%d", port)),
		nmap.WithScripts(script),
		nmap.WithTimingTemplate(timingTemplate),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create nmap scanner: %v", err)
	}

	// Run scan
	result, _, err := scanner.Run()
	if err != nil {
		return nil, fmt.Errorf("failed to run nmap scan: %v", err)
	}

	// Extract script output
	scriptOutput := make(map[string]string)
	for _, host := range result.Hosts {
		for _, port := range host.Ports {
			for _, script := range port.Scripts {
				scriptOutput[script.ID] = script.Output
			}
		}
	}

	return scriptOutput, nil
}

// RunVulnScan runs a vulnerability scan using Nmap scripts
func (n *NmapScanner) RunVulnScan(host string, port int) (map[string]string, error) {
	return n.RunNmapScript(host, port, "vuln")
}

// RunSSHScan runs SSH-specific Nmap scripts
func (n *NmapScanner) RunSSHScan(host string, port int) (map[string]string, error) {
	return n.RunNmapScript(host, port, "ssh-auth-methods,ssh2-enum-algos")
}

// RunMySQLScan runs MySQL-specific Nmap scripts
func (n *NmapScanner) RunMySQLScan(host string, port int) (map[string]string, error) {
	return n.RunNmapScript(host, port, "mysql-info,mysql-enum")
}

// RunFTPScan runs FTP-specific Nmap scripts
func (n *NmapScanner) RunFTPScan(host string, port int) (map[string]string, error) {
	return n.RunNmapScript(host, port, "ftp-anon,ftp-bounce")
}

// RunHTTPScan runs HTTP-specific Nmap scripts
func (n *NmapScanner) RunHTTPScan(host string, port int) (map[string]string, error) {
	return n.RunNmapScript(host, port, "http-auth-finder,http-title")
}
