// +build windows

package windows

import "os"

func checkForAdmin() bool { //attempts to get a file handle on MBR, only Admin can
	_, err := os.Open("\\\\.\\PHYSICALDRIVE0")
	if err != nil {
		return false
	}
	return true
}
