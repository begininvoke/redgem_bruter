package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"redgem_bruter/pkg/scanner"

	"strings"
)

func main() {
	// Define command line flags
	target := flag.String("target", "", "Target host to scan (required)")
	ports := flag.String("port", "", "Comma-separated list of ports to scan (optional)")
	outputFile := flag.String("o", "", "Output file for results (optional)")
	format := flag.String("f", "text", "Output format (text, json, or csv)")
	attack := flag.Bool("a", false, "Enable brute force attack mode")

	flag.Parse()

	// Validate required flags
	if *target == "" {
		fmt.Println("Error: -target flag is required")
		flag.Usage()
		os.Exit(1)
	}

	var portList []int

	// First check for port in target (IP:PORT format)
	if strings.Contains(*target, ":") {
		parts := strings.Split(*target, ":")
		if len(parts) > 1 {
			*target = parts[0]
			var port int
			fmt.Sscanf(parts[1], "%d", &port)
			if port > 0 && port < 65536 {
				portList = append(portList, port)
			}
		}
	}

	// Then check -port flag
	if *ports != "" {
		// Parse comma-separated ports
		portStrings := strings.Split(*ports, ",")
		for _, portStr := range portStrings {
			var port int
			fmt.Sscanf(strings.TrimSpace(portStr), "%d", &port)
			if port > 0 && port < 65536 {
				portList = append(portList, port)
			}
		}
	}

	// Remove duplicate ports
	portMap := make(map[int]bool)
	var uniquePortList []int
	for _, port := range portList {
		if !portMap[port] {
			portMap[port] = true
			uniquePortList = append(uniquePortList, port)
		}
	}
	portList = uniquePortList
	// Check if wordlist files are available
	wordlistPath := filepath.Join("pkg", "scanner", "wordlists")
	if _, err := os.Stat(wordlistPath); os.IsNotExist(err) {
		fmt.Println("Warning: Wordlist directory not found. Using hardcoded credentials.")
	} else {
		// Check for specific service wordlists
		services := []string{"http", "ssh"}
		for _, service := range services {
			serviceWordlist := filepath.Join(wordlistPath, service+".txt")
			if _, err := os.Stat(serviceWordlist); os.IsNotExist(err) {
				fmt.Printf("Warning: Wordlist for %s service not found. Using hardcoded credentials.\n", service)
			}
		}
	}
	// Create scanner instance
	s := scanner.NewScanner(*target, portList, *attack, *outputFile, *format)

	// Print scan information
	fmt.Printf("Starting scan of %s (%s)\n", *target, s.IP)
	if len(portList) > 0 {
		fmt.Printf("Scanning ports: %v\n", portList)
	} else {
		fmt.Println("No specific ports provided. Scanning all known service ports:")
		for serviceName, service := range s.Services {
			fmt.Printf("- %s (%s): %v\n", serviceName, service.Description, service.Ports)
		}
	}

	// Perform scan
	results, err := s.Scan()
	if err != nil {
		fmt.Printf("Error during scan: %v\n", err)
		os.Exit(1)
	}

	// Output results
	var output *os.File
	if *outputFile != "" {
		var err error
		output, err = os.Create(*outputFile)
		if err != nil {
			fmt.Printf("Error creating output file: %v\n", err)
			os.Exit(1)
		}
		defer output.Close()
	} else {
		output = os.Stdout
	}

	// Write header for CSV format
	if *format == "csv" {
		fmt.Fprintln(output, "IP,Service,Port,Protocol,Open,Auth,Vulnerable,VulnDescription,DefaultCreds,DefaultUser,DefaultPass,GuestAccess,Version,Banner,Info,LastChecked")
	}

	// Write results
	openCount := 0
	authCount := 0
	for _, result := range results {
		if result.Open {
			openCount++
			if result.Auth {
				authCount++
			}
			fmt.Fprintln(output, s.FormatResult(result))
		}
	}

	// Print summary
	if *outputFile == "" {
		fmt.Printf("\nScan completed. Found %d open ports, %d requiring authentication.\n",
			openCount, authCount)
	}
}
