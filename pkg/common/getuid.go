package common

import (
	"github.com/Coalfire-Research/Slackor/pkg/command"
)

// GetUID is an alias for whoami
type GetUID struct{}

// Name is the name of the command
func (g GetUID) Name() string {
	return "getuid"
}

// Run is an alias for whoami
func (g GetUID) Run(clientID string, jobID string, args []string) (string, error) {
	return command.GetCommand("whoami").Run(clientID, jobID, args)
}

func init() {
	command.RegisterCommand(GetUID{})
}
