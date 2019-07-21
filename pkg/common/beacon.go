package common

import (
	"errors"
	"fmt"
	"strconv"

	"github.com/Coalfire-Research/Slackor/internal/config"
	"github.com/Coalfire-Research/Slackor/pkg/command"
)

// Beacon changes the polling frequency
type Beacon struct{}

// Name is the name of the command
func (b Beacon) Name() string {
	return "beacon"
}

// Run changes the polling frequency
func (b Beacon) Run(clientID string, jobID string, args []string) (string, error) {
	if len(args) != 1 {
		return "", errors.New("beacon takes 1 argument")
	}
	config.Beacon, _ = strconv.Atoi(args[0])
	return fmt.Sprintf("Implant will now poll every %d second(s).", config.Beacon), nil
}

func init() {
	command.RegisterCommand(Beacon{})
}
