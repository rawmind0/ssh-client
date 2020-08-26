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

// ClientConfig struct
type ClientConfig struct {
	Hosts   []Host   `yaml:"hosts" json:"hosts,omitempty"`
	Cmd     []string `yaml:"cmd" json:"cmd,omitempty"`
	CmdFile []string `yaml:"cmd_file,omitempty" json:"cmd_file,omitempty"`
	Timeout string   `yaml:"timeout,omitempty" json:"timeout,omitempty"`
}

// NewClientConfigFromYAML func
func NewClientConfigFromYAML(config string) (*ClientConfig, error) {
	logrus.Debugf("New client config creating...")
	clientConfig := &ClientConfig{
		Timeout: DefaultTimeout,
	}
	if err := YAMLToInterface(config, clientConfig); err != nil {
		return nil, err
	}
	return clientConfig, nil
}

func (c *ClientConfig) setCmd(config []string) {
	c.Cmd = config
}

func (c *ClientConfig) getHosts() []Host {
	return c.Hosts
}

func (c *ClientConfig) getCmd() []string {
	return c.Cmd
}

func (c *ClientConfig) getHCmdFile() []string {
	return c.CmdFile
}

func (c *ClientConfig) getTimeout() string {
	return c.Timeout
}

func (c *ClientConfig) validate() error {
	logrus.Debugf("Config validating...")
	for _, cmdFile := range c.getHCmdFile() {
		cmdBytes, err := ioutil.ReadFile(cmdFile)
		if err != nil {
			return fmt.Errorf("Reading config file: %v", err)
		}
		c.Cmd = append(c.Cmd, string(cmdBytes))
	}
	if c.Cmd == nil || len(c.getCmd()) == 0 {
		return fmt.Errorf("cmd should be provided")
	}
	hostList := c.getHosts()
	if c.Hosts == nil || len(hostList) == 0 {
		return fmt.Errorf("hosts should be provided")
	}
	if _, err := time.ParseDuration(c.Timeout); err != nil {
		return fmt.Errorf("parinsg timeout %v", err)
	}

	errStrings := []string{}
	hostIDS := make(map[string]int, len(hostList))
	for i := range hostList {
		err := hostList[i].validate()
		hostID := hostList[i].Address + ":" + hostList[i].Port
		if err != nil || hostIDS[hostID] > 0 {
			errLine := "[" + hostID + "] Validating config: duplicated host"
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
	logrus.Debugf("Config validated")
	return nil
}

type Client struct {
	config  *ClientConfig
	timeout time.Duration
	runSync *sync.Mutex
}

// NewClientFromYAML func
func NewClientFromYAML(config string) (*Client, error) {
	logrus.Debugf("New client creating...")
	clientConfig, err := NewClientConfigFromYAML(config)
	if err != nil {
		return nil, err
	}
	client := &Client{
		config:  clientConfig,
		runSync: &sync.Mutex{},
	}
	if err := client.validate(); err != nil {
		return nil, err
	}
	logrus.Debugf("New client created")
	return client, nil
}

func (c *Client) SetCmd(config string) error {
	logrus.Debugf("Cmd setting...")
	clientConfig, err := NewClientConfigFromYAML(config)
	if err != nil {
		return err
	}
	clientConfig = c.config
	err = c.config.validate()
	if err != nil {
		return fmt.Errorf("Setting cmd: %v", err)
	}

	logrus.Debugf("Setting cmd locking...")
	c.runSync.Lock()
	c.config.setCmd(clientConfig.Cmd)
	c.runSync.Unlock()
	logrus.Debugf("Setting cmd unlocked")

	logrus.Debugf("Cmd set")
	return nil
}

func (c *Client) validate() error {
	err := c.config.validate()
	if err != nil {
		return fmt.Errorf("Validating config: %v", err)
	}
	duration, err := time.ParseDuration(c.config.getTimeout())
	if err != nil {
		return fmt.Errorf("Validating client: parsing timeout: %v", err)
	}
	c.timeout = duration
	return nil
}

// RunCmd func
func (c *Client) RunCmd(cmd []string) error {
	logrus.Debugf("Client running cmd...")
	return c.run(cmd)
}

// Run func
func (c *Client) Run() error {
	logrus.Debugf("Client run locking...")
	c.runSync.Lock()
	defer logrus.Debugf("Client run unlocked")
	defer c.runSync.Unlock()
	logrus.Debugf("Client running...")
	return c.run(c.config.getCmd())
}

func (c *Client) run(cmd []string) error {
	if cmd == nil || len(cmd) == 0 {
		return fmt.Errorf("Client run: cmd should be provided")
	}
	var wg sync.WaitGroup
	exit := make(chan os.Signal, 1)
	signal.Notify(exit, os.Interrupt, os.Kill)

	wgErrors, errStrings := newErrorByChan()
	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()
	for _, host := range c.config.getHosts() {
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
			logrus.Errorf("Client run context timeout: %s", c.config.getTimeout())
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
	for _, host := range c.config.getHosts() {
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
