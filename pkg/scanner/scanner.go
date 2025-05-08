package scanner

import (
	"fmt"
	"net"
	"redgem_bruter/pkg/scanner/actions"
	"redgem_bruter/pkg/services"
	"time"
)

// ScanResult represents the result of a service scan
type ScanResult struct {
	IP       string
	Service  string
	Port     int
	Protocol string
	Open     bool
	Auth     bool
	Error    error
	Info     string
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
	address := fmt.Sprintf("%s:%d", s.Target, port)
	conn, err := net.DialTimeout("tcp", address, 5*time.Second)

	result := &ScanResult{
		IP:       s.IP,
		Port:     port,
		Protocol: "tcp",
		Open:     false,
		Auth:     false,
	}

	if err != nil {
		result.Error = err
		return result, nil
	}
	defer conn.Close()

	result.Open = true

	// Try to identify the service
	for serviceName, service := range s.Services {
		for _, servicePort := range service.Ports {
			if port == servicePort {
				result.Service = serviceName

				// Get the appropriate service action
				serviceAction := actions.GetServiceAction(serviceName)

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

				break
			}
		}
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
		return fmt.Sprintf(`{"ip":"%s","service":"%s","port":%d,"protocol":"%s","open":%v,"auth":%v,"info":"%s"}`,
			result.IP, result.Service, result.Port, result.Protocol, result.Open, result.Auth, result.Info)
	case "csv":
		return fmt.Sprintf("%s,%s,%d,%s,%v,%v,%s",
			result.IP, result.Service, result.Port, result.Protocol, result.Open, result.Auth, result.Info)
	default:
		return fmt.Sprintf("IP: %s, Service: %s, Port: %d, Protocol: %s, Open: %v, Auth: %v, Info: %s",
			result.IP, result.Service, result.Port, result.Protocol, result.Open, result.Auth, result.Info)
	}
}
