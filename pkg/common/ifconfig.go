package common

import (
	"net"
	"strings"

	"github.com/Coalfire-Research/Slackor/pkg/command"
)

// IFConfig dumps interface and network information
type IFConfig struct{}

// Name is the name of the command
func (i IFConfig) Name() string {
	return "ifconfig"
}

// Run dumps interface and network information
func (i IFConfig) Run(clientID string, jobID string, args []string) (string, error) {
	returnString := "=== interfaces ===\n"
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	for _, iface := range ifaces {
		returnString += iface.Name + ":\n"
		addrs, err := iface.Addrs()
		if err != nil {
			return "", err
		}
		for _, addr := range addrs {
			addrStr := addr.String()
			split := strings.Split(addrStr, "/")
			addrStr0 := split[0]
			mask := split[1]
			ip := net.ParseIP(addrStr0)
			if ip.To4() != nil {
				returnString += "    IPv4 Address: " + addrStr0 + "/" + mask + "\n"
			} else {
				returnString += "    IPv6 Address: " + addrStr0 + "/" + mask + "\n"
			}
		}
		returnString += "\n"
	}
	return returnString, nil
}

func init() {
	command.RegisterCommand(IFConfig{})
}
