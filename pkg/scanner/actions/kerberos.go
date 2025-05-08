package actions

import (
	"strings"
)

// KerberosAction implements Kerberos service scanning
type KerberosAction struct {
	BaseAction
}

// NewKerberosAction creates a new Kerberos action
func NewKerberosAction() *KerberosAction {
	return &KerberosAction{
		BaseAction: *NewBaseAction(),
	}
}

// CheckAuth checks if Kerberos requires authentication
func (k *KerberosAction) CheckAuth() (bool, string, error) {
	// First check if port is open
	open, err := k.CheckPort(k.Host, k.Port)
	if err != nil {
		return false, "", err
	}
	if !open {
		return false, "Port closed", nil
	}

	// Run Kerberos auth script
	output, err := k.RunNmapScript(k.Host, k.Port, "krb5-enum-users")
	if err != nil {
		return false, "", err
	}

	// Kerberos always requires authentication
	return true, output, nil
}

// BruteForce attempts to brute force Kerberos credentials
func (k *KerberosAction) BruteForce() (bool, string, error) {
	// Run Kerberos brute force script
	output, err := k.RunNmapScript(k.Host, k.Port, "krb5-brute")
	if err != nil {
		return false, "", err
	}

	// Check if brute force was successful
	success := strings.Contains(output, "Valid credentials") ||
		strings.Contains(output, "Login successful")

	return success, output, nil
}
