package ssh

import (
	"fmt"
	"io/ioutil"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

// DefaultPoolTimeout const
const DefaultPoolTimeout = "300s"

// PoolConfig struct
type PoolConfig struct {
	Hosts   []Host   `yaml:"hosts" json:"hosts,omitempty"`
	Cmd     []string `yaml:"cmd" json:"cmd,omitempty"`
	CmdFile []string `yaml:"cmd_file,omitempty" json:"cmd_file,omitempty"`
	Timeout string   `yaml:"timeout,omitempty" json:"timeout,omitempty"`
}

// NewPoolConfigFromYAML func
func NewPoolConfigFromYAML(config string) (*PoolConfig, error) {
	logrus.Debugf("New pool config creating...")
	poolConfig := &PoolConfig{}
	if err := YAMLToInterface(config, poolConfig); err != nil {
		return nil, err
	}
	return poolConfig, poolConfig.validate()
}

func (c *PoolConfig) setCmd(config []string) {
	c.Cmd = config
}

func (c *PoolConfig) getHosts() []Host {
	return c.Hosts
}

func (c *PoolConfig) getCmd() []string {
	return c.Cmd
}

func (c *PoolConfig) getHCmdFile() []string {
	return c.CmdFile
}

func (c *PoolConfig) getTimeout() string {
	return c.Timeout
}

func (c *PoolConfig) validate() error {
	logrus.Debugf("Pool config validating...")
	for _, cmdFile := range c.getHCmdFile() {
		cmdBytes, err := ioutil.ReadFile(cmdFile)
		if err != nil {
			return fmt.Errorf("Reading config file: %v", err)
		}
		c.Cmd = append(c.Cmd, "sh -c '"+string(cmdBytes)+"'")
	}
	if c.Cmd == nil || len(c.getCmd()) == 0 {
		return fmt.Errorf("cmd should be provided")
	}
	hostList := c.getHosts()
	if c.Hosts == nil || len(hostList) == 0 {
		return fmt.Errorf("hosts should be provided")
	}
	if len(c.Timeout) == 0 {
		c.Timeout = DefaultPoolTimeout
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
