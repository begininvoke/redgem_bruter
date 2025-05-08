package actions

import (
	"strings"
)

// VNCAction implements VNC service scanning
type VNCAction struct {
	BaseAction
}

// NewVNCAction creates a new VNC action
func NewVNCAction() *VNCAction {
	return &VNCAction{
		BaseAction: *NewBaseAction(),
	}
}

// CheckAuth checks if VNC requires authentication
func (v *VNCAction) CheckAuth() (bool, string, error) {
	// First check if port is open
	open, err := v.CheckPort(v.Host, v.Port)
	if err != nil {
		return false, "", err
	}
	if !open {
		return false, "Port closed", nil
	}

	// Run VNC auth script
	output, err := v.RunNmapScript(v.Host, v.Port, "vnc-info")
	if err != nil {
		return false, "", err
	}

	// Check if authentication is required
	requiresAuth := strings.Contains(output, "authentication required") ||
		strings.Contains(output, "VNC authentication") ||
		strings.Contains(output, "password required")

	return requiresAuth, output, nil
}

// BruteForce attempts to brute force VNC credentials
func (v *VNCAction) BruteForce() (bool, string, error) {
	// Run VNC brute force script
	output, err := v.RunNmapScript(v.Host, v.Port, "vnc-brute")
	if err != nil {
		return false, "", err
	}

	// Check if brute force was successful
	success := strings.Contains(output, "Valid credentials") ||
		strings.Contains(output, "Login successful")

	return success, output, nil
}
