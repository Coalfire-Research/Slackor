package common

import (
	"errors"
	"strings"

	"github.com/Coalfire-Research/Slackor/pkg/command"

	"github.com/miekg/dns"
)

// GetIP gets the external WAN outbound ip of this machine
type GetIP struct{}

// Name is the name of the command
func (g GetIP) Name() string {
	return "getip"
}

// Run gets the external WAN outbound ip of this machine
func (g GetIP) Run(clientID string, jobID string, args []string) (string, error) {
	// high speed response, won't look that weird in DNS logs
	target := "o-o.myaddr.l.google.com"
	server := "ns1.google.com"

	c := dns.Client{}
	m := dns.Msg{}
	m.SetQuestion(target+".", dns.TypeTXT)
	r, _, err := c.Exchange(&m, server+":53")
	if err != nil {
		return "", err
	}
	for _, ans := range r.Answer {
		TXTrecord := ans.(*dns.TXT)
		// shouldn't ever be multiple, but provide the full answer if we ever do
		return strings.Join(TXTrecord.Txt, ","), nil
	}
	return "", errors.New("no answer")
}

func init() {
	command.RegisterCommand(GetIP{})
}
