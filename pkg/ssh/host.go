package ssh

import (
	"fmt"
	"io/ioutil"
	"os/user"

	"github.com/sirupsen/logrus"
)

const DefaultPort = "22"

var DefaultKeyPath string

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

func InitKeyPath() string {
	user, err := user.Current()
    if err != nil {
        panic(err)
    }
    DefaultKeyPath = user.HomeDir+"/.ssh/id_rsa"
    return DefaultKeyPath
}

func (h *Host) Dial() error {
	if len(h.User) == 0 {
		return fmt.Errorf("[%s:%s] Dialing host: user is nil", h.Address, h.Port)
	}

	dialer, err := NewDialer(h.Address+":"+h.Port, h.User, h.Pass, h.SSHKey, h.SSHKeyPass, h.SSHAgentAuth)
	if err != nil {
		return fmt.Errorf("[%s:%s] Dialing host: %v", h.Address, h.Port, err)
	}
	h.dialer = dialer
	logrus.Debugf("[%s:%s] host dialed", h.Address, h.Port)
	return nil
}

func (h *Host) validate() error {
	if len(h.Address) == 0 {
		return fmt.Errorf("Validating host: no address provided")
	}
	if len(h.Port) == 0 {
		h.Port = DefaultPort
	}
	if len(h.User) == 0 {
		return fmt.Errorf("[%s:%s] Validating host: no user provided", h.Address, h.Port)
	}
	if len(h.Pass) == 0 && len(h.SSHKey) == 0 && !h.SSHAgentAuth {
		if len(h.SSHKeyPath) == 0 {
			h.SSHKeyPath = DefaultKeyPath
		}
		keyByte, err := ioutil.ReadFile(h.SSHKeyPath)
		if err != nil {
			return fmt.Errorf("[%s:%s] Validating host: Reading user ssh key file: %v", h.Address, h.Port, err)
		}
		h.SSHKey = string(keyByte)
	}
	logrus.Debugf("[%s:%s] host validated", h.Address, h.Port)
	return nil
}

func (h *Host) Close() error {
	if h.dialer == nil {
		return nil
	}
	logrus.Debugf("[%s:%s] host closed", h.Address, h.Port)
	return h.dialer.Close()
}

func (h *Host) Cmd(cmds []string) error {
	cmd := ""
	for i := range cmds {
		cmd = cmd + cmds[i] + "\n"
	}
	if len(cmd) == 0 {
		return fmt.Errorf("[%s:%s] cmd: Command is nil", h.Address, h.Port)
	}
	err := h.dialer.Cmd(cmd)
	if err != nil {
		return fmt.Errorf("[%s:%s] cmd: %v", h.Address, h.Port, err)
	}
	logrus.Debugf("[%s:%s] cmd executed", h.Address, h.Port)
	return nil
}

func (h *Host) Output(cmds []string) ([]byte, error) {
	cmd := ""
	for i := range cmds {
		cmd = cmd + cmds[i] + "\n"
	}
	if len(cmd) == 0 {
		return nil, fmt.Errorf("[%s:%s] output: Command is nil", h.Address, h.Port)
	}
	out, err := h.dialer.Output(cmd)
	if err != nil {
		return nil, fmt.Errorf("[%s:%s] output: %v", h.Address, h.Port, err)
	}
	logrus.Debugf("[%s:%s] output executed", h.Address, h.Port)
	return out, nil
}

func (h *Host) CombinedOutput(cmds []string) ([]byte, error) {
	cmd := ""
	for i := range cmds {
		cmd = cmd + cmds[i] + "\n"
	}
	if len(cmd) == 0 {
		return nil, fmt.Errorf("[%s:%s] output: Command is nil", h.Address, h.Port)
	}
	out, err := h.dialer.CombinedOutput(cmd)
	if err != nil {
		return nil, fmt.Errorf("[%s:%s] output: \n%s", h.Address, h.Port, string(out))
	}
	logrus.Debugf("[%s:%s] combined output executed", h.Address, h.Port)
	return out, nil
}
