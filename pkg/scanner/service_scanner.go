package scanner

import (
	"fmt"
	"sync"
	"time"

	"redgem_bruter/pkg/scanner/actions"
)

// ServiceResult represents the result of a service scan
type ServiceResult struct {
	ServiceName       string
	Port              int
	Protocol          string
	IsOpen            bool
	RequiresAuth      bool
	BruteForceSuccess bool
	ServiceInfo       string
	BruteForceInfo    string
	Version           string
	Banner            string
	LastChecked       time.Time
}

// ServiceScanner handles scanning multiple services
type ServiceScanner struct {
	services map[string]actions.ServiceAction
	timeout  time.Duration
}

// NewServiceScanner creates a new service scanner
func NewServiceScanner() *ServiceScanner {
	return &ServiceScanner{
		services: map[string]actions.ServiceAction{
			"ssh":           actions.NewSSHAction(),
			"mysql":         actions.NewMySQLAction(),
			"postgres":      actions.NewPostgresAction(),
			"redis":         actions.NewRedisAction(),
			"mongodb":       actions.NewMongoDBAction(),
			"ftp":           actions.NewFTPAction(),
			"http":          actions.NewHTTPAction(),
			"elasticsearch": actions.NewElasticsearchAction(),
			"telnet":        actions.NewTelnetAction(),
			"smtp":          actions.NewSMTPAction(),
			"ldap":          actions.NewLDAPAction(),
			"rdp":           actions.NewRDPAction(),
		},
		timeout: 5 * time.Second,
	}
}

// ScanService scans a specific service
func (s *ServiceScanner) ScanService(serviceName, host string, port int, wordlist string) (*ServiceResult, error) {
	service, ok := s.services[serviceName]
	if !ok {
		return nil, fmt.Errorf("unsupported service: %s", serviceName)
	}

	// Set host and port
	service.SetHost(host)
	service.SetPort(port)

	result := &ServiceResult{
		ServiceName: serviceName,
		Port:        port,
		Protocol:    getProtocol(serviceName),
		LastChecked: time.Now(),
	}

	// Check if port is open and get service info
	requiresAuth, info, err := service.CheckAuth()
	if err != nil {
		return nil, fmt.Errorf("failed to check auth: %v", err)
	}
	result.IsOpen = true
	result.RequiresAuth = requiresAuth
	result.ServiceInfo = info

	if !result.IsOpen {
		return result, nil
	}

	// Get banner and version
	if baseAction, ok := service.(*actions.BaseAction); ok {
		banner, version, err := baseAction.GetBanner()
		if err == nil {
			result.Banner = banner
			result.Version = version
		}
	}

	// Attempt brute force if authentication is required
	if requiresAuth {
		success, bruteInfo, err := service.BruteForce()
		if err != nil {
			return nil, fmt.Errorf("failed to brute force: %v", err)
		}
		result.BruteForceSuccess = success
		result.BruteForceInfo = bruteInfo
	}

	return result, nil
}

// ScanAllServices scans all supported services
func (s *ServiceScanner) ScanAllServices(host string, ports []int, wordlist string) (map[string]*ServiceResult, error) {
	results := make(map[string]*ServiceResult)
	var wg sync.WaitGroup
	var mu sync.Mutex
	sem := make(chan struct{}, 10) // Limit concurrent scans

	for serviceName := range s.services {
		for _, port := range ports {
			wg.Add(1)
			go func(service string, p int) {
				defer wg.Done()
				sem <- struct{}{}        // Acquire semaphore
				defer func() { <-sem }() // Release semaphore

				result, err := s.ScanService(service, host, p, wordlist)
				if err != nil {
					fmt.Printf("Error scanning %s on port %d: %v\n", service, p, err)
					return
				}

				mu.Lock()
				results[fmt.Sprintf("%s:%d", service, p)] = result
				mu.Unlock()
			}(serviceName, port)
		}
	}

	wg.Wait()
	return results, nil
}

// FormatResult formats a service result for display
func (s *ServiceScanner) FormatResult(result *ServiceResult) string {
	status := "CLOSED"
	if result.IsOpen {
		status = "OPEN"
		if result.RequiresAuth {
			status += " (Auth Required)"
			if result.BruteForceSuccess {
				status += " - Brute Force Successful"
			}
		}
	}

	output := fmt.Sprintf("Service: %s\n", result.ServiceName)
	output += fmt.Sprintf("Port: %d\n", result.Port)
	output += fmt.Sprintf("Protocol: %s\n", result.Protocol)
	output += fmt.Sprintf("Status: %s\n", status)

	if result.IsOpen {
		if result.Version != "" {
			output += fmt.Sprintf("Version: %s\n", result.Version)
		}
		if result.Banner != "" {
			output += fmt.Sprintf("Banner: %s\n", result.Banner)
		}
		if result.ServiceInfo != "" {
			output += fmt.Sprintf("Service Info: %s\n", result.ServiceInfo)
		}
		if result.RequiresAuth && result.BruteForceInfo != "" {
			output += fmt.Sprintf("Brute Force Info: %s\n", result.BruteForceInfo)
		}
	}
	output += fmt.Sprintf("Last Checked: %s\n", result.LastChecked.Format(time.RFC3339))

	return output
}

// getProtocol returns the protocol for a given service
func getProtocol(service string) string {
	switch service {
	case "http", "https":
		return "HTTP"
	case "ssh":
		return "SSH"
	case "mysql":
		return "MySQL"
	case "postgres":
		return "PostgreSQL"
	case "redis":
		return "Redis"
	case "mongodb":
		return "MongoDB"
	case "ftp":
		return "FTP"
	case "elasticsearch":
		return "HTTP"
	case "telnet":
		return "Telnet"
	case "smtp":
		return "SMTP"
	case "ldap":
		return "LDAP"
	case "rdp":
		return "RDP"
	default:
		return "Unknown"
	}
}
