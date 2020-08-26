package ssh

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"os/signal"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// DefaultTimeout const
const DefaultTimeout = "300s"

// Client struct
type Client struct {
	Hosts   []Host   `yaml:"hosts" json:"hosts,omitempty"`
	Cmd     []string `yaml:"cmd" json:"cmd,omitempty"`
	CmdFile []string `yaml:"cmd_file,omitempty" json:"cmd_file,omitempty"`
	Timeout string   `yaml:"timeout,omitempty" json:"timeout,omitempty"`
	timeout time.Duration
}

// NewClientFromYAML func
func NewClientFromYAML(config string) (*Client, error) {
	logrus.Debugf("New client creating...")
	client := &Client{
		Timeout: DefaultTimeout,
	}
	if err := YAMLToInterface(config, client); err != nil {
		return nil, err
	}
	if err := client.validate(); err != nil {
		return nil, err
	}
	logrus.Debugf("New client created")
	return client, nil
}

func (c *Client) parseTimeout() error {
	duration, err := time.ParseDuration(c.Timeout)
	if err != nil {
		return fmt.Errorf("parsing timeout: %v", err)
	}
	c.timeout = duration
	return nil
}
func (c *Client) validate() error {
	logrus.Debugf("Client validating...")
	for _, cmdFile := range c.CmdFile {
		cmdBytes, err := ioutil.ReadFile(cmdFile)
		if err != nil {
			return fmt.Errorf("Validating client: Reading config file: %v", err)
		}
		c.Cmd = append(c.Cmd, string(cmdBytes))
	}
	if c.Cmd == nil || len(c.Cmd) == 0 {
		return fmt.Errorf("Validating client: cmd should be provided")
	}
	if c.Hosts == nil || len(c.Hosts) == 0 {
		return fmt.Errorf("Validating client: hosts should be provided")
	}
	if err := c.parseTimeout(); err != nil {
		return fmt.Errorf("Validating client: %v", err)
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

// RunCmd func
func (c *Client) RunCmd(cmd []string) error {
	logrus.Debugf("Client running cmd...")
	c.Cmd = cmd
	err := c.Run()
	if err != nil {
		return err
	}
	logrus.Debugf("Client cmd runned")
	return nil
}

// Run func
func (c *Client) Run() error {
	logrus.Debugf("Client running...")
	var wg sync.WaitGroup

	cmd := c.Cmd
	exit := make(chan os.Signal, 1)
	signal.Notify(exit, os.Interrupt, os.Kill)

	wgErrors, errStrings := newErrorByChan()
	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()
	for _, host := range c.Hosts {
		wg.Add(1)
		go func(h Host) {
			defer wg.Done()
			_, err := h.Run(ctx, cmd, dialerRunKindCombined)
			if err != nil {
				message := err.Error()
				if len(message) > 0 {
					logrus.Debugf("%s%s", hostDebugIndent, message)
					wgErrors <- &message
				}
			}
		}(host)
	}

	go func() {
		wg.Wait()
		close(wgErrors)
	}()

running:
	for {
		select {
		case errStr := <-wgErrors:
			if errStr == nil {
				break running
			}
			errStrings = append(errStrings, *errStr)
		case <-exit:
			logrus.Info("Exit signal detected....trying to close properly...")
			cancel()
			<-wgErrors
			fmt.Printf("killed\n")
			return fmt.Errorf("Client killed by user request: %v", ctx.Err())
		case <-ctx.Done():
			logrus.Errorf("Client run context timeout: %s", c.Timeout)
			<-wgErrors
			fmt.Printf("killed\n")
			return fmt.Errorf("Client run context cancelled: %v", ctx.Err())
		}
	}

	if len(errStrings) > 0 {
		fmt.Printf("error\n")
		return fmt.Errorf("Client run failed:\n%s", stringsToLines(errStrings))
	}
	fmt.Printf("ok\n")
	logrus.Debugf("Client runned")
	return nil
}

// Close func
func (c *Client) Close() error {
	logrus.Debugf("Client closing...")
	errStrings := []string{}
	for _, host := range c.Hosts {
		if err := host.Close(); err != nil {
			errStrings = append(errStrings, err.Error())
		}
	}
	if len(errStrings) > 0 {
		fmt.Printf("error\n")
		return fmt.Errorf("Client close failed:\n%s", stringsToLines(errStrings))
	}
	logrus.Debugf("Client closed")
	return nil
}
