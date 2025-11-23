package scanner

import (
	"context"
	"fmt"
	"net"
	"redgem_bruter/pkg/scanner/actions"
	"redgem_bruter/pkg/services"
	"strings"
	"time"

	"github.com/Ullaakut/nmap/v3"
)

// ScanResult represents the result of a service scan
type ScanResult struct {
	IP              string
	Service         string
	Port            int
	Protocol        string
	Open            bool
	Auth            bool
	Error           error
	Info            string
	Version         string
	Banner          string
	Vulnerable      bool
	VulnDescription string
	DefaultCreds    bool
	DefaultUser     string
	DefaultPass     string
	GuestAccess     bool
	LastChecked     time.Time
}

// Scanner represents the main scanner structure
type Scanner struct {
	Target     string
	Ports      []int
	Services   map[string]services.Service
	Attack     bool
	OutputFile string
	Format     string
	IP         string
	Timeout    time.Duration
}

// SetTimeout sets the timeout for service checks
func (s *Scanner) SetTimeout(timeout time.Duration) {
	s.Timeout = timeout
}

// NewScanner creates a new scanner instance
func NewScanner(target string, ports []int, attack bool, outputFile, format string) *Scanner {
	// Resolve IP address
	ip, err := net.ResolveIPAddr("ip", target)
	ipStr := ""
	if err == nil {
		ipStr = ip.String()
	}

	return &Scanner{
		Target:     target,
		Ports:      ports,
		Services:   services.GetAllServices(),
		Attack:     attack,
		OutputFile: outputFile,
		Format:     format,
		IP:         ipStr,
		Timeout:    30 * time.Second,
	}
}

// detectService attempts to detect the service running on a port using nmap
func (s *Scanner) detectService(port int) (string, string, error) {
	// Create nmap scanner with service detection
	nmapScanner := NewNmapScanner(30 * time.Second)

	// Try to get service version first
	version, err := nmapScanner.ScanServiceVersion(s.Target, port)
	if err != nil {
		return "", "", fmt.Errorf("service version detection failed: %v", err)
	}

	// Run a basic service detection scan
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	scanner, err := nmap.NewScanner(
		ctx,
		nmap.WithTargets(s.Target),
		nmap.WithPorts(fmt.Sprintf("%d", port)),
		nmap.WithServiceInfo(),
	)
	if err != nil {
		return "", version, fmt.Errorf("unable to create nmap scanner: %v", err)
	}

	result, warnings, err := scanner.Run()
	if len(*warnings) > 0 {
		fmt.Printf("Scan warnings: %s\n", *warnings)
	}
	if err != nil {
		return "", version, fmt.Errorf("unable to run nmap scan: %v", err)
	}

	// Extract service name from results
	for _, host := range result.Hosts {
		if len(host.Ports) == 0 || len(host.Addresses) == 0 {
			continue
		}

		for _, port := range host.Ports {
			if port.Service.Name != "" {
				return port.Service.Name, version, nil
			}
		}
	}

	return "", version, nil
}

// ScanPort performs a port scan on the specified port
func (s *Scanner) ScanPort(service services.Service) (*ScanResult, error) {
	result := &ScanResult{
		IP:          s.IP,
		Port:        service.Ports[0],
		Protocol:    "tcp",
		Open:        false,
		Auth:        false,
		LastChecked: time.Now(),
	}

	// Create nmap scanner
	nmapScanner := actions.NewBaseAction()
	open, err := nmapScanner.CheckPort(s.Target, service.Ports[0])
	if err != nil {
		result.Error = err
		return result, nil
	}

	if !open {
		return result, nil
	}

	result.Open = true

	// Try to detect service using nmap
	detectedService, version, err := s.detectService(service.Ports[0])
	if err == nil && detectedService != "" {
		result.Service = detectedService
		result.Version = version
	} else {
		// If nmap detection fails, try to get the banner
		banner, version, err := nmapScanner.GetBanner()
		if err == nil && banner != "" {
			result.Banner = banner
			result.Version = version

			// Try to identify service from banner
			for serviceName, service := range s.Services {
				if strings.Contains(strings.ToLower(banner), strings.ToLower(service.Name)) {
					result.Service = serviceName
					break
				}
			}
		}

		// If service still not identified, use default port mapping
		if result.Service == "" {
			result.Service = service.Name
		} else {
			// If service was detected but doesn't match our expected service name,
			// try to map it to the correct service based on port
			if service.Name != "" && result.Service != service.Name {
				// For specific services, prefer the expected service name
				if service.Name == "elasticsearch" && result.Port == 9200 {
					result.Service = "elasticsearch"
				} else if service.Name == "kibana" && result.Port == 5601 {
					result.Service = "kibana"
				} else if service.Name == "rabbitmq" && result.Port == 5672 {
					result.Service = "rabbitmq"
				}
			}
		}
	}

	// If we have identified a service, perform service-specific checks
	if result.Service != "" {
		// Get the appropriate service action
		serviceAction := actions.GetServiceAction(result.Service)

		// Set host and port
		serviceAction.SetHost(s.Target)
		serviceAction.SetPort(result.Port)

		// Check authentication
		requiresAuth, info, _, err := serviceAction.CheckAuth()
		if err != nil {
			result.Error = err
		}
		result.Auth = requiresAuth
		result.Info = info

		// Check for vulnerabilities - more sophisticated approach
		if !requiresAuth {
			// Check if this is a service that should typically require authentication
			servicesThatShouldHaveAuth := map[string]bool{
				"ssh": true, "mysql": true, "postgres": true, "redis": true,
				"mongodb": true, "mssql": true, "ftp": true, "telnet": true,
				"rdp": true, "vnc": true, "winrm": true, "elasticsearch": true,
			}

			if servicesThatShouldHaveAuth[result.Service] {
				result.Vulnerable = true
				result.VulnDescription = "Service does not require authentication (potential security risk)"
			}
		}
	} else {
		// If we couldn't identify the service, mark it as unknown
		result.Service = "unknown"
		result.Info = "Service could not be identified"
	}

	return result, nil
}

// AttackService attempts to brute force a service
func (s *Scanner) AttackService(result *ScanResult) error {
	// Only attack services that are open AND require authentication
	if !result.Open || !result.Auth {
		return nil
	}

	// Get the appropriate service action
	serviceAction := actions.GetServiceAction(result.Service)
	if serviceAction == nil {
		return fmt.Errorf("no action handler available for service: %s", result.Service)
	}

	serviceAction.SetHost(s.Target)
	serviceAction.SetPort(result.Port)

	success, bruteInfo, err := serviceAction.BruteForce()
	if err != nil {
		return fmt.Errorf("brute force failed for %s on port %d: %v", result.Service, result.Port, err)
	}

	// Add brute force information regardless of success
	if bruteInfo != "" {
		if success {
			result.Info += "\nBrute force successful: " + bruteInfo
			result.Vulnerable = true
			if result.VulnDescription == "" {
				result.VulnDescription = "Brute force attack successful"
			} else {
				result.VulnDescription += "; Brute force attack successful"
			}
		} else {
			result.Info += "\nBrute force attempted: " + bruteInfo
		}
	}

	return nil
}

// Scan performs a scan of all specified ports
func (s *Scanner) Scan() ([]*ScanResult, error) {
	var results []*ScanResult

	// If no specific ports are provided, scan all known service ports
	if len(s.Ports) == 0 {
		for _, service := range s.Services {
			s.Ports = append(s.Ports, service.Ports...)
		}
	}

	// Remove duplicate ports
	portMap := make(map[int]bool)
	var uniquePorts []int
	for _, port := range s.Ports {
		if !portMap[port] {
			portMap[port] = true
			uniquePorts = append(uniquePorts, port)
		}
	}
	s.Ports = uniquePorts

	fmt.Printf("Scanning %d \n", len(s.Ports))

	// Create a map of ports to scan for quick lookup
	portsToScan := make(map[int]bool)
	for _, port := range s.Ports {
		portsToScan[port] = true
	}

	// Only scan services that have ports in our target list
	var servicesToScan []services.Service
	for _, service := range s.Services {
		for _, servicePort := range service.Ports {
			if portsToScan[servicePort] {
				// Create a service with only the matching port
				serviceToScan := service
				serviceToScan.Ports = []int{servicePort}
				servicesToScan = append(servicesToScan, serviceToScan)
				break
			}
		}
	}

	// If no services match the specified ports, scan the ports directly
	if len(servicesToScan) == 0 {
		fmt.Println("No known services match specified ports. Scanning ports directly...")
		for _, port := range s.Ports {
			// Create a generic service for unknown ports
			genericService := services.Service{
				Name:        "unknown",
				Ports:       []int{port},
				Protocol:    "tcp",
				Description: "Unknown service",
			}
			servicesToScan = append(servicesToScan, genericService)
		}
	}

	// Scan only the relevant services
	//طسserviceCount := len(servicesToScan)
	currentService := 0
	for _, service := range servicesToScan {
		currentService++
		// fmt.Printf("Scanning service %d/%d: %s (port: %d)\n", currentService, serviceCount, service.Name, service.Ports[0])

		result, err := s.ScanPort(service)
		if err != nil {
			fmt.Printf("Warning: Error scanning %s on port %d: %v\n", service.Name, service.Ports[0], err)
			continue
		}
		results = append(results, result)
	}

	// Then, if attack mode is enabled, attempt brute force on services that require auth
	if s.Attack {
		fmt.Println("Attack mode enabled. Starting brute force attempts...")
		attackCount := 0
		for _, result := range results {
			if result.Open && result.Auth {
				attackCount++
				fmt.Printf("Attempting brute force on %s (port %d)...\n", result.Service, result.Port)
				if err := s.AttackService(result); err != nil {
					fmt.Printf("Error attacking %s on port %d: %v\n", result.Service, result.Port, err)
				}
			}
		}
		if attackCount == 0 {
			fmt.Println("No services requiring authentication found for brute force attempts.")
		}
	}

	return results, nil
}

// FormatResult formats a scan result according to the specified format
func (s *Scanner) FormatResult(result *ScanResult) string {
	switch s.Format {
	case "json":
		return fmt.Sprintf(`{"ip":"%s","service":"%s","port":%d,"protocol":"%s","open":%v,"auth":%v,"vulnerable":%v,"vuln_description":"%s","default_creds":%v,"default_user":"%s","default_pass":"%s","guest_access":%v,"version":"%s","banner":"%s","info":"%s","last_checked":"%s"}`,
			result.IP, result.Service, result.Port, result.Protocol, result.Open, result.Auth, result.Vulnerable, result.VulnDescription, result.DefaultCreds, result.DefaultUser, result.DefaultPass, result.GuestAccess, result.Version, result.Banner, result.Info, result.LastChecked.Format(time.RFC3339))
	case "csv":
		// Helper function to escape CSV fields
		escapeCSV := func(s string) string {
			if strings.ContainsAny(s, ",\"\n\r") {
				return "\"" + strings.ReplaceAll(s, "\"", "\"\"") + "\""
			}
			return s
		}

		fields := []string{
			escapeCSV(result.IP),
			escapeCSV(result.Service),
			fmt.Sprintf("%d", result.Port),
			escapeCSV(result.Protocol),
			fmt.Sprintf("%v", result.Open),
			fmt.Sprintf("%v", result.Auth),
			fmt.Sprintf("%v", result.Vulnerable),
			escapeCSV(result.VulnDescription),
			fmt.Sprintf("%v", result.DefaultCreds),
			escapeCSV(result.DefaultUser),
			escapeCSV(result.DefaultPass),
			fmt.Sprintf("%v", result.GuestAccess),
			escapeCSV(result.Version),
			escapeCSV(result.Banner),
			escapeCSV(result.Info),
			result.LastChecked.Format(time.RFC3339),
		}
		return strings.Join(fields, ",")
	default:
		output := fmt.Sprintf("IP: %s\n", result.IP)
		output += fmt.Sprintf("Service: %s\n", result.Service)
		output += fmt.Sprintf("Port: %d\n", result.Port)
		output += fmt.Sprintf("Protocol: %s\n", result.Protocol)
		output += fmt.Sprintf("Status: %v\n", result.Open)
		output += fmt.Sprintf("Auth Required: %v\n", result.Auth)

		if result.Vulnerable {
			output += fmt.Sprintf("VULNERABLE: %s\n", result.VulnDescription)
		}

		if result.DefaultCreds {
			output += fmt.Sprintf("Default Credentials Found:\n")
			output += fmt.Sprintf("  Username: %s\n", result.DefaultUser)
			output += fmt.Sprintf("  Password: %s\n", result.DefaultPass)
		}

		if result.GuestAccess {
			output += fmt.Sprintf("Guest Access Available\n")
		}

		if result.Version != "" {
			output += fmt.Sprintf("Version: %s\n", result.Version)
		}

		if result.Banner != "" {
			output += fmt.Sprintf("Banner: %s\n", result.Banner)
		}

		if result.Info != "" {
			output += fmt.Sprintf("Additional Info: %s\n", result.Info)
		}

		output += fmt.Sprintf("Last Checked: %s\n", result.LastChecked.Format(time.RFC3339))

		return output
	}
}
