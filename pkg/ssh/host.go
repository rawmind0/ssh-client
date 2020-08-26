package ssh

import (
	"context"
	"fmt"
	"io/ioutil"
	"os/user"

	"github.com/sirupsen/logrus"
)

const (
	// DefaultPort const
	DefaultPort     = "22"
	hostDebugIndent = "  "
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
	dialer       *Dialer
}

// InitKeyPath func
func InitKeyPath() string {
	user, err := user.Current()
	if err != nil {
		panic(err)
	}
	DefaultKeyPath = user.HomeDir + "/.ssh/id_rsa"
	return DefaultKeyPath
}

// Dial func
func (h *Host) Dial(ctx context.Context) error {
	logrus.Debugf("%s[%s:%s] host dialing", hostDebugIndent, h.Address, h.Port)
	if len(h.User) == 0 {
		return fmt.Errorf("[%s:%s] host dialing: user is nil", h.Address, h.Port)
	}

	dialer, err := NewDialer(h.Address+":"+h.Port, h.User, h.Pass, h.SSHKey, h.SSHKeyPass, h.SSHAgentAuth)
	if err != nil {
		return fmt.Errorf("[%s:%s] host dialing: %v", h.Address, h.Port, err)
	}
	h.dialer = dialer
	logrus.Debugf("%s[%s:%s] host dialed", hostDebugIndent, h.Address, h.Port)
	return nil
}

func (h *Host) validate() error {
	logrus.Debugf("%s[%s:%s] host validating...", hostDebugIndent, h.Address, h.Port)
	if len(h.Address) == 0 {
		return fmt.Errorf("host validating: no address provided")
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
			return fmt.Errorf("[%s:%s] host validating: Reading user ssh key file: %v", h.Address, h.Port, err)
		}
		h.SSHKey = string(keyByte)
	}
	logrus.Debugf("%s[%s:%s] host validated", hostDebugIndent, h.Address, h.Port)
	return nil
}

// Close func
func (h *Host) Close() error {
	logrus.Debugf("%s[%s:%s] host closing...", hostDebugIndent, h.Address, h.Port)
	if h.dialer != nil {
		err := h.dialer.Close()
		if err != nil {
			logrus.Errorf("%sDialer close failed", dialerDebugIndent)
			return nil
		}
	}
	logrus.Debugf("%s[%s:%s] host closed", hostDebugIndent, h.Address, h.Port)
	return nil
}

// Run func
func (h *Host) Run(ctx context.Context, cmds []string, kind string) ([]byte, error) {
	logrus.Debugf("%s[%s:%s] host running...", hostDebugIndent, h.Address, h.Port)
	err := h.Dial(ctx)
	if err != nil {
		return nil, err
	}
	cmd := stringsToCmd(cmds)
	if len(cmd) == 0 {
		return nil, fmt.Errorf("[%s:%s] run: Command is nil", h.Address, h.Port)
	}
	data, err := h.dialer.Run(ctx, cmd, kind)
	if err != nil {
		return data, fmt.Errorf("[%s:%s] host run failed:\n%s", h.Address, h.Port, err)
	}

	logrus.Debugf("%s[%s:%s] host runned", hostDebugIndent, h.Address, h.Port)
	return data, nil
}
