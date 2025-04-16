package scanner

import (
	"context"
	"fmt"
	"time"

	"github.com/Ullaakut/nmap/v3"
)

// NmapScanner provides functionality to scan hosts using nmap
type NmapScanner struct {
	timeout time.Duration
}

// NewNmapScanner creates a new NmapScanner with the specified timeout
func NewNmapScanner(timeout time.Duration) *NmapScanner {
	return &NmapScanner{
		timeout: timeout,
	}
}

// ScanPorts scans the specified host for open ports
func (n *NmapScanner) ScanPorts(host string, ports []int) ([]int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), n.timeout)
	defer cancel()

	// Convert ports slice to string format for nmap
	portsStr := ""
	for i, port := range ports {
		if i > 0 {
			portsStr += ","
		}
		portsStr += fmt.Sprintf("%d", port)
	}

	// Create nmap scanner
	scanner, err := nmap.NewScanner(
		ctx,
		nmap.WithTargets(host),
		nmap.WithPorts(portsStr),
		nmap.WithServiceInfo(),
	)
	if err != nil {
		return nil, fmt.Errorf("unable to create nmap scanner: %v", err)
	}

	// Run the scan
	result, warnings, err := scanner.Run()
	if len(*warnings) > 0 {
		// Log warnings but continue
		fmt.Printf("Scan warnings: %s\n", *warnings)
	}
	if err != nil {
		return nil, fmt.Errorf("unable to run nmap scan: %v", err)
	}

	// Extract open ports from results
	var openPorts []int
	for _, host := range result.Hosts {
		if len(host.Ports) == 0 || len(host.Addresses) == 0 {
			continue
		}

		for _, port := range host.Ports {
			if port.State.State == "open" {
				openPorts = append(openPorts, int(port.ID))
			}
		}
	}

	return openPorts, nil
}

// ScanServiceVersion scans the specified host and port for service version information
func (n *NmapScanner) ScanServiceVersion(host string, port int) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), n.timeout)
	defer cancel()

	// Create nmap scanner with version detection
	scanner, err := nmap.NewScanner(
		ctx,
		nmap.WithTargets(host),
		nmap.WithPorts(fmt.Sprintf("%d", port)),
		nmap.WithServiceInfo(),
		nmap.WithVersionIntensity(5),
	)
	if err != nil {
		return "", fmt.Errorf("unable to create nmap scanner: %v", err)
	}

	// Run the scan
	result, warnings, err := scanner.Run()
	if len(*warnings) > 0 {
		// Log warnings but continue
		fmt.Printf("Scan warnings: %s\n", *warnings)
	}
	if err != nil {
		return "", fmt.Errorf("unable to run nmap scan: %v", err)
	}

	// Extract service version from results
	for _, host := range result.Hosts {
		if len(host.Ports) == 0 || len(host.Addresses) == 0 {
			continue
		}

		for _, port := range host.Ports {
			if port.Service.Version != "" {
				return port.Service.Version, nil
			}
		}
	}

	return "", nil
}

// RunNmapScript runs a custom NSE script against the specified host and port
func (n *NmapScanner) RunNmapScript(host string, port int, scriptName string) (map[string]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), n.timeout)
	defer cancel()

	// Create nmap scanner with script scanning
	scanner, err := nmap.NewScanner(
		ctx,
		nmap.WithTargets(host),
		nmap.WithPorts(fmt.Sprintf("%d", port)),
		nmap.WithScripts(scriptName),
	)
	if err != nil {
		return nil, fmt.Errorf("unable to create nmap scanner: %v", err)
	}

	// Run the scan
	result, warnings, err := scanner.Run()
	if len(*warnings) > 0 {
		// Log warnings but continue
		fmt.Printf("Scan warnings: %s\n", *warnings)
	}
	if err != nil {
		return nil, fmt.Errorf("unable to run nmap scan: %v", err)
	}

	// Extract script output from results
	scriptOutput := make(map[string]string)
	for _, host := range result.Hosts {
		if len(host.Ports) == 0 || len(host.Addresses) == 0 {
			continue
		}

		for _, port := range host.Ports {
			for _, script := range port.Scripts {
				scriptOutput[script.ID] = script.Output
			}
		}
	}

	return scriptOutput, nil
}

// RunVulnScan performs a vulnerability scan on the specified host and port
func (n *NmapScanner) RunVulnScan(host string, port int) (map[string]string, error) {
	return n.RunNmapScript(host, port, "vuln")
}

// RunSSHScan performs an SSH scan on the specified host and port
func (n *NmapScanner) RunSSHScan(host string, port int) (map[string]string, error) {
	return n.RunNmapScript(host, port, "ssh2-enum-algos,ssh-auth-methods")
}

// RunMySQLScan performs a MySQL scan on the specified host and port
func (n *NmapScanner) RunMySQLScan(host string, port int) (map[string]string, error) {
	return n.RunNmapScript(host, port, "mysql-info,mysql-variables")
}

// RunFTPScan performs an FTP scan on the specified host and port
func (n *NmapScanner) RunFTPScan(host string, port int) (map[string]string, error) {
	return n.RunNmapScript(host, port, "ftp-anon,ftp-syst")
}

// RunHTTPScan performs an HTTP scan on the specified host and port
func (n *NmapScanner) RunHTTPScan(host string, port int) (map[string]string, error) {
	return n.RunNmapScript(host, port, "http-title,http-server-header,http-headers")
}
