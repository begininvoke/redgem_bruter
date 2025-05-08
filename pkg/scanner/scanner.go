package scanner

import (
	"fmt"
	"net"
	"redgem_bruter/pkg/scanner/actions"
	"redgem_bruter/pkg/services"
	"strings"
	"time"
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
	}
}

// ScanPort performs a port scan on the specified port
func (s *Scanner) ScanPort(port int) (*ScanResult, error) {
	result := &ScanResult{
		IP:          s.IP,
		Port:        port,
		Protocol:    "tcp",
		Open:        false,
		Auth:        false,
		LastChecked: time.Now(),
	}

	// Create nmap scanner
	nmapScanner := actions.NewBaseAction()
	open, err := nmapScanner.CheckPort(s.Target, port)
	if err != nil {
		result.Error = err
		return result, nil
	}

	if !open {
		return result, nil
	}

	result.Open = true

	// First try to get the banner to identify the service
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

	// If service not identified from banner, try default port mapping
	if result.Service == "" {
		for serviceName, service := range s.Services {
			for _, servicePort := range service.Ports {
				if port == servicePort {
					result.Service = serviceName
					break
				}
			}
			if result.Service != "" {
				break
			}
		}
	}

	// If we have identified a service, perform service-specific checks
	if result.Service != "" {
		// Get the appropriate service action
		serviceAction := actions.GetServiceAction(result.Service)

		// Set host and port
		serviceAction.SetHost(s.Target)
		serviceAction.SetPort(port)

		// Check authentication
		requiresAuth, info, err := serviceAction.CheckAuth()
		if err != nil {
			result.Error = err
		}
		result.Auth = requiresAuth
		result.Info = info

		// Check for vulnerabilities
		if !requiresAuth {
			result.Vulnerable = true
			result.VulnDescription = "Service does not require authentication"
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
	if !result.Open || !result.Auth {
		return nil
	}

	serviceAction := actions.GetServiceAction(result.Service)
	serviceAction.SetHost(s.Target)
	serviceAction.SetPort(result.Port)

	success, bruteInfo, err := serviceAction.BruteForce()
	if err != nil {
		return err
	}
	if success {
		result.Info += "\nBrute force successful: " + bruteInfo
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

	// First, scan all ports
	for _, port := range s.Ports {
		result, err := s.ScanPort(port)
		if err != nil {
			return nil, err
		}
		results = append(results, result)
	}

	// Then, if attack mode is enabled, attempt brute force on services that require auth
	if s.Attack {
		for _, result := range results {
			if err := s.AttackService(result); err != nil {
				fmt.Printf("Error attacking %s on port %d: %v\n", result.Service, result.Port, err)
			}
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
