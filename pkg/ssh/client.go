package ssh

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync"

	"github.com/sirupsen/logrus"
)

// Client struct
type Client struct {
	Hosts []Host   `yaml:"hosts" json:"hosts,omitempty"`
	Cmd   []string `yaml:"cmd" json:"cmd,omitempty"`
}

// NewClientFromYAML func
func NewClientFromYAML(config string) (*Client, error) {
	logrus.Debugf("Client creating...")
	client := &Client{}
	if err := YAMLToInterface(config, client); err != nil {
		return nil, err
	}
	if err := client.validate(); err != nil {
		return nil, err
	}
	logrus.Debugf("Client created")
	return client, nil
}

func (c *Client) validate() error {
	logrus.Debugf("Client validating...")
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

// Run func
func (c *Client) Run() error {
	logrus.Debugf("Client running...")
	var wg sync.WaitGroup

	exit := make(chan os.Signal, 1)
	signal.Notify(exit, os.Interrupt, os.Kill)

	wgErrors, errStrings := newErrorByChan()
	ctx := context.Background()
	ctx, cancel := context.WithCancel(context.Background())
	for _, host := range c.Hosts {
		wg.Add(1)
		go func(h Host) {
			defer wg.Done()
			_, err := h.Run(ctx, c.Cmd)
			if err != nil {
				message := err.Error()
				if len(message) > 0 {
					logrus.Debugf("%s[%s:%s] client run: %s", hostDebugIndent, h.Address, h.Port, message)
					wgErrors <- &message
				}
			}
		}(host)
	}

	go func() {
		wg.Wait()
		close(wgErrors)
	}()

	select {
	case errStr := <-wgErrors:
		if errStr == nil {
			break
		}
		errStrings = append(errStrings, *errStr)
	case <-exit:
		logrus.Info("Exit signal detected....trying to close properly...")
		cancel()
		<-wgErrors
		fmt.Printf("killed\n")
		return fmt.Errorf("Client run killed by user request")
	}

	if len(errStrings) > 0 {
		fmt.Printf("error\n")
		return fmt.Errorf("Client run failed:\n%s", strings.Join(errStrings, "\n"))
	}
	fmt.Printf("ok\n")
	logrus.Debugf("Client runned")
	return nil
}

// Close func
func (c *Client) Close() error {
	logrus.Debugf("Client closing...")
	for _, host := range c.Hosts {
		host.Close()
	}
	logrus.Debugf("Client closed")
	return nil
}
