package main

import (
	"fmt"
	"log"
	"time"

	"redgem_bruter/pkg/scanner"
)

func main() {
	// Create a new NmapScanner with a 30-second timeout
	nmapScanner := scanner.NewNmapScanner(30 * time.Second)

	// Example host and port to scan
	host := "example.com"
	port := 22

	// 1. Basic port scan
	fmt.Println("1. Basic port scan:")
	openPorts, err := nmapScanner.ScanPorts(host, []int{port})
	if err != nil {
		log.Fatalf("Failed to scan ports: %v", err)
	}
	if len(openPorts) > 0 {
		fmt.Printf("Port %d is open\n", port)
	} else {
		fmt.Printf("Port %d is closed\n", port)
	}

	// 2. Service version detection
	fmt.Println("\n2. Service version detection:")
	version, err := nmapScanner.ScanServiceVersion(host, port)
	if err != nil {
		log.Fatalf("Failed to detect service version: %v", err)
	}
	if version != "" {
		fmt.Printf("Service version: %s\n", version)
	} else {
		fmt.Println("No version information found")
	}

	// 3. Run a custom NSE script
	fmt.Println("\n3. Run a custom NSE script:")
	scriptResults, err := nmapScanner.RunNmapScript(host, port, "ssh2-enum-algos")
	if err != nil {
		log.Fatalf("Failed to run NSE script: %v", err)
	}
	for scriptName, output := range scriptResults {
		fmt.Printf("Script %s output:\n%s\n", scriptName, output)
	}

	// 4. Run a vulnerability scan
	fmt.Println("\n4. Run a vulnerability scan:")
	vulnResults, err := nmapScanner.RunVulnScan(host, port)
	if err != nil {
		log.Fatalf("Failed to run vulnerability scan: %v", err)
	}
	for scriptName, output := range vulnResults {
		fmt.Printf("Vulnerability scan %s output:\n%s\n", scriptName, output)
	}

	// 5. Run service-specific scans
	fmt.Println("\n5. Run service-specific scans:")

	// SSH scan
	sshResults, err := nmapScanner.RunSSHScan(host, port)
	if err != nil {
		log.Printf("Failed to run SSH scan: %v", err)
	} else {
		for scriptName, output := range sshResults {
			fmt.Printf("SSH scan %s output:\n%s\n", scriptName, output)
		}
	}

	// HTTP scan (on port 80)
	httpResults, err := nmapScanner.RunHTTPScan(host, 80)
	if err != nil {
		log.Printf("Failed to run HTTP scan: %v", err)
	} else {
		for scriptName, output := range httpResults {
			fmt.Printf("HTTP scan %s output:\n%s\n", scriptName, output)
		}
	}
}
