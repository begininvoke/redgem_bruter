package nmap_script_example

import (
	"fmt"
	"log"

	"redgem_bruter/pkg/scanner/actions"
)

// RunExample demonstrates how to use the RunNmapScript method
func RunExample() {
	// Create a new BaseAction with default timeout
	baseAction := actions.NewBaseAction()

	// Example host and port to scan
	host := "example.com"
	port := 22

	// Run a simple SSH script
	fmt.Println("Running SSH script scan:")
	output, err := baseAction.RunNmapScript(host, port, "ssh2-enum-algos")
	if err != nil {
		log.Fatalf("Failed to run SSH script: %v", err)
	}
	fmt.Println(output)

	// Run a vulnerability scan
	fmt.Println("\nRunning vulnerability scan:")
	output, err = baseAction.RunNmapScript(host, port, "vuln")
	if err != nil {
		log.Fatalf("Failed to run vulnerability scan: %v", err)
	}
	fmt.Println(output)

	// Run a custom script with arguments
	fmt.Println("\nRunning custom script with arguments:")
	output, err = baseAction.RunNmapScript(host, port, "http-title --script-args http-title.url=/admin")
	if err != nil {
		log.Fatalf("Failed to run custom script: %v", err)
	}
	fmt.Println(output)

	// Run multiple scripts at once
	fmt.Println("\nRunning multiple scripts:")
	output, err = baseAction.RunNmapScript(host, port, "ssh2-enum-algos,ssh-auth-methods")
	if err != nil {
		log.Fatalf("Failed to run multiple scripts: %v", err)
	}
	fmt.Println(output)
}
