package actions

// SSHAction implements SSH-specific actions
type SSHAction struct {
	*BaseAction
}

// NewSSHAction creates a new SSH action
func NewSSHAction() *SSHAction {
	return &SSHAction{
		BaseAction: NewBaseAction(),
	}
}

// CheckAuth checks if SSH requires authentication
func (s *SSHAction) CheckAuth(host string, port int) (bool, string, error) {
	// First check if port is open
	open, err := s.CheckPort(host, port)
	if err != nil {
		return false, "", err
	}
	if !open {
		return false, "Port closed", nil
	}

	// Run SSH auth methods script
	output, err := s.RunNmapScript(host, port, "ssh-auth-methods")
	if err != nil {
		return false, "", err
	}

	// SSH always requires authentication
	return true, output, nil
}

// BruteForce attempts to brute force SSH
func (s *SSHAction) BruteForce(host string, port int, wordlist string) (bool, string, error) {
	// Implementation for SSH brute force
	return false, "Brute force not implemented for SSH", nil
}
