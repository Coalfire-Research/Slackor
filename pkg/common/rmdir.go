package common

import (
	"errors"
	"os"

	"github.com/Coalfire-Research/Slackor/pkg/command"
)

// RMDir removes the given empty directory
type RMDir struct{}

// Name is the name of the command
func (p RMDir) Name() string {
	return "rmdir"
}

// Run removes the given empty directory
func (p RMDir) Run(clientID string, jobID string, args []string) (string, error) {
	if len(args) != 1 {
		return "", errors.New("rm takes 1 argument")
	}
	path := args[0]
	st, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if !st.Mode().IsDir() {
		return "", errors.New("rmdir can only remove empty directories")
	}
	err = os.Remove(path)
	if err != nil {
		return "", err
	}
	return path + " has been removed.", nil
}

func init() {
	command.RegisterCommand(RMDir{})
}
