// +build windows

package windows

import (
	"fmt"
	"syscall"

	"github.com/Coalfire-Research/Slackor/internal/config"
	"github.com/Coalfire-Research/Slackor/pkg/command"
)

// Version gets the OS version
type Version struct{}

// Name is the name of the command
func (v Version) Name() string {
	return "version"
}

// Run gets the OS version
func (v Version) Run(clientID string, jobID string, args []string) (string, error) {
	if config.OSVersion != "" {
		return config.OSVersion, nil
	}
	dll := syscall.MustLoadDLL("kernel32.dll")
	p := dll.MustFindProc("GetVersion")
	v, _, _ := p.Call()
	version := fmt.Sprintf("Windows version %d.%d (Build %d)\n", byte(v), uint8(v>>8), uint16(v>>16))
	config.OSVersion = version
	return config.OSVersion, nil
}

func init() {
	command.RegisterCommand(Version{})
}
