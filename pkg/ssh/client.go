package ssh

import (
	"fmt"
	"strings"
	"sync"

	"github.com/sirupsen/logrus"
)

type Client struct {
	Hosts []Host   `yaml:"hosts" json:"hosts,omitempty"`
	Cmd   []string `yaml:"cmd" json:"cmd,omitempty"`
}

func NewClientFromYAML(config string) (*Client, error) {
	client := &Client{}
	err := YAMLToInterface(config, client)
	if err != nil {
		return nil, err
	}
	return client, client.validate()
}

func (c *Client) validate() error {
	if c.Cmd == nil || len(c.Cmd) == 0 {
		return fmt.Errorf("Validating client: cmd should be provided")
	}
	if c.Hosts == nil || len(c.Hosts) == 0 {
		return fmt.Errorf("Validating client: hosts should be provided")
	}
	errStrings := []string{}
	hostIDS := make(map[string]int, len(c.Hosts))
	for i := range c.Hosts {
		err := c.Hosts[i].validate()
		hostID := c.Hosts[i].Address + ":" + c.Hosts[i].Port
		if err != nil || hostIDS[hostID] > 0 {
			errLine := "[" + hostID + "] Validating client: duplicated host"
			if err != nil {
				errLine = "[" + hostID + "]" + err.Error()
			}
			errStrings = append(errStrings, errLine)
		}
		hostIDS[hostID]++
	}
	if len(errStrings) > 0 {
		return fmt.Errorf("%s", strings.Join(errStrings, "\n"))
	}
	logrus.Debugf("Client validated")
	return nil
}

func (c *Client) Run() error {
	var wg sync.WaitGroup
	wgErrors := make(chan error)
	for _, host := range c.Hosts {
		wg.Add(1)
		go func(h Host) {
			defer wg.Done()
			err := h.Dial()
			if err != nil {
				wgErrors <- err
				return
			}
			defer h.Close()
			out, err := h.CombinedOutput(c.Cmd)
			fmt.Printf("%s\n", out)
			if err != nil {
				wgErrors <- err
			}
		}(host)
	}

	go func() {
		wg.Wait()
		close(wgErrors)
	}()

	errStrings := []string{}
	select {
	case err := <-wgErrors:
		if err == nil {
			break
		}
		errStrings = append(errStrings, err.Error())
	}

	if len(errStrings) > 0 {
		return fmt.Errorf("%s", strings.Join(errStrings, "\n"))
	}

	return nil
}
