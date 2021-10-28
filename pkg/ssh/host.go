package ssh

import (
	"context"
	"fmt"
	"io/ioutil"
	"net"
	"time"

	"github.com/sirupsen/logrus"
)

const (
	// DefaultPort const
	DefaultPort = "22"
	// DefaultHostTimeout const
	DefaultHostTimeout = "30s"
	// DefaultHostKeepAlive const
	DefaultHostKeepAlive = "30s"
	defaultHostKeyfile   = "/.ssh/id_rsa"
	hostDebugIndent      = "  "
)

// DefaultKeyPath var
var DefaultKeyPath string

// Host struct
type Host struct {
	Address      string `yaml:"address" json:"address,omitempty"`
	Port         string `yaml:"port" json:"port,omitempty"`
	User         string `yaml:"user" json:"user,omitempty"`
	Pass         string `yaml:"password" json:"password,omitempty"`
	SSHAgentAuth bool   `yaml:"ssh_agent_auth,omitempty" json:"sshAgentAuth,omitempty"`
	SSHKey       string `yaml:"ssh_key" json:"sshKey,omitempty"`
	SSHKeyPass   string `yaml:"ssh_key_pass" json:"sshKeyPass,omitempty"`
	SSHKeyPath   string `yaml:"ssh_key_path" json:"sshKeyPath,omitempty"`
	SSHCert      string `yaml:"ssh_cert" json:"sshCert,omitempty"`
	SSHCertPath  string `yaml:"ssh_cert_path" json:"sshCertPath,omitempty"`
	SSHTimeout   string `yaml:"ssh_timeout" json:"sshTimeout,omitempty"`
	SSHKeepAlive string `yaml:"ssh_keep_alive" json:"sshKeepAlive,omitempty"`
	dialer       *Dialer
}

func init() {
	DefaultKeyPath = GetUserHome() + defaultHostKeyfile
}

// NewHostFromYAML func
func NewHostFromYAML(config string) (*Host, error) {
	logrus.Debugf("New host creating...")
	host := &Host{}
	if err := YAMLToInterface(config, host); err != nil {
		return nil, err
	}
	if err := host.validate(); err != nil {
		return nil, err
	}
	logrus.Debugf("New host created")
	return host, nil
}

func (h *Host) validate() error {
	logrus.Debugf("%s[%s:%s] host validating...", hostDebugIndent, h.Address, h.Port)
	if len(h.Address) == 0 {
		return fmt.Errorf("host validating: no address provided")
	}
	if len(h.SSHTimeout) == 0 {
		h.SSHTimeout = DefaultHostTimeout
	}
	if _, err := time.ParseDuration(h.SSHTimeout); err != nil {
		return fmt.Errorf("parinsg timeout %v", err)
	}
	if len(h.SSHKeepAlive) == 0 {
		h.SSHKeepAlive = DefaultHostKeepAlive
	}
	if _, err := time.ParseDuration(h.SSHKeepAlive); err != nil {
		return fmt.Errorf("parinsg timeout %v", err)
	}
	if len(h.Port) == 0 {
		h.Port = DefaultPort
	}
	if len(h.User) == 0 {
		return fmt.Errorf("[%s:%s] host validating: no user provided", h.Address, h.Port)
	}
	if len(h.Pass) == 0 && len(h.SSHKey) == 0 && !h.SSHAgentAuth {
		if len(h.SSHKeyPath) == 0 {
			h.SSHKeyPath = DefaultKeyPath
		}
		keyByte, err := ioutil.ReadFile(h.SSHKeyPath)
		if err != nil {
			return fmt.Errorf("[%s:%s] host validating: Reading user ssh key file: %s", h.Address, h.Port, err)
		}
		h.SSHKey = string(keyByte)
	}
	logrus.Debugf("%s[%s:%s] host validated", hostDebugIndent, h.Address, h.Port)
	return nil
}

// TunnelUp func
func (h *Host) TunnelUp(ctx context.Context) error {
	if h.dialer != nil {
		err := h.dialer.tunnelUp(ctx)
		if err != nil {
			return fmt.Errorf("[%s:%s] host tunnelling: %v", h.Address, h.Port, err)
		}
		return nil
	}
	logrus.Debugf("%s[%s:%s] host tunnelling", hostDebugIndent, h.Address, h.Port)
	if len(h.User) == 0 {
		return fmt.Errorf("[%s:%s] host tunnelling: user is nil", h.Address, h.Port)
	}

	dialer, err := NewDialer(ctx, h.Address+":"+h.Port, h.User, h.Pass, h.SSHKey, h.SSHKeyPass, h.SSHAgentAuth, h.SSHTimeout, h.SSHKeepAlive)
	if err != nil {
		return fmt.Errorf("[%s:%s] host tunnelling: %v", h.Address, h.Port, err)
	}
	h.dialer = dialer
	logrus.Debugf("%s[%s:%s] host tunnelled", hostDebugIndent, h.Address, h.Port)
	return nil
}

// Close func
func (h *Host) Close() error {
	logrus.Debugf("%s[%s:%s] host closing...", hostDebugIndent, h.Address, h.Port)
	if h.dialer != nil {
		err := h.dialer.Close()
		if err != nil {
			logrus.Errorf("%sDialer close failed", dialerDebugIndent)
			return fmt.Errorf("[%s:%s] host closing: %v", h.Address, h.Port, err)
		}
	}
	logrus.Debugf("%s[%s:%s] host closed", hostDebugIndent, h.Address, h.Port)
	return nil
}

// Dial func
func (h *Host) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	logrus.Debugf("%s[%s:%s] host dialing...", hostDebugIndent, h.Address, h.Port)
	err := h.TunnelUp(ctx)
	if err != nil {
		return nil, err
	}
	conn, err := h.dialer.Dial(ctx, network, addr)
	if err != nil {
		return nil, fmt.Errorf("[%s:%s] host dialing: %v", h.Address, h.Port, err)
	}
	return conn, nil
}

// Run func
func (h *Host) Run(ctx context.Context, cmds []string, kind string) ([]byte, error) {
	logrus.Debugf("%s[%s:%s] host running...", hostDebugIndent, h.Address, h.Port)
	err := h.TunnelUp(ctx)
	if err != nil {
		return nil, err
	}
	cmd := stringsToCmd(cmds)
	if len(cmd) == 0 {
		return nil, fmt.Errorf("[%s:%s] run: Command is nil", h.Address, h.Port)
	}
	data, err := h.dialer.run(ctx, cmd, kind)
	if err != nil {
		return data, fmt.Errorf("[%s:%s] host run failed:\n%s", h.Address, h.Port, err)
	}

	logrus.Debugf("%s[%s:%s] host runned", hostDebugIndent, h.Address, h.Port)
	return data, nil
}
