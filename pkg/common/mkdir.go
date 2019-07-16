package common

import (
	"errors"
	"os"

	"github.com/Coalfire-Research/Slackor/pkg/command"
)

// MkDir creates the given directory
type MkDir struct{}

// Name is the name of the command
func (m MkDir) Name() string {
	return "mkdir"
}

// Run creates the given directory
func (m MkDir) Run(clientID string, jobID string, args []string) (string, error) {
	if len(args) != 1 {
		return "", errors.New("mkdir takes 1 argument")
	}
	path := args[0]
	var err = os.Mkdir(path, os.FileMode(0522))
	if err != nil {
		return "", err
	}
	return path + " has been created.", nil
}

func init() {
	command.RegisterCommand(MkDir{})
}
