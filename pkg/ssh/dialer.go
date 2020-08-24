package ssh

import (
	"fmt"
	"io"
	"net"
	"os"

	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

type Dialer struct {
	client *ssh.Client
	err    error
	stdout io.Writer
	stderr io.Writer
}

func NewDialerWithPasswd(addr, user, pass string) (*Dialer, error) {
	return NewDialer(addr, user, pass, "", "", false)
}

func NewDialerWithKey(addr, user, key, keypass string) (*Dialer, error) {
	return NewDialer(addr, user, "", key, keypass, false)
}

func NewDialerWithKeyAgent(addr, user string) (*Dialer, error) {
	return NewDialer(addr, user, "", "", "", true)
}

func NewDialer(addr, user, pass, key, keyPass string, keyAgent bool) (*Dialer, error) {
	if len(addr) == 0 {
		return nil, fmt.Errorf("New dialer: host address should be provided")
	}
	kind, config, err := newDialerConfig(user, pass, key, keyPass, keyAgent)
	if err != nil {
		return nil, fmt.Errorf("New dialer: %v", err)
	}
	dialer := &Dialer{}
	dialer, err = dialer.Dial("tcp", addr, config)
	if err != nil {
		return nil, fmt.Errorf("New dialer: %v", err)
	}
	logrus.Debugf("[%s] New dialer created: %s auth", addr, kind)
	return dialer, nil
}

func newDialerConfig(user, pass, key, keyPass string, keyAgent bool) (string, *ssh.ClientConfig, error) {
	if len(user) == 0 {
		return "", nil, fmt.Errorf("New dialer config: user should be provided")
	}

	config := &ssh.ClientConfig{
		User:            user,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	if len(key) > 0 {
		var signer ssh.Signer
		var err error
		if len(keyPass) > 0 {
			signer, err = ssh.ParsePrivateKeyWithPassphrase([]byte(key), []byte(keyPass))
		} else {
			signer, err = ssh.ParsePrivateKey([]byte(key))
		}
		if err != nil {
			return "", nil, fmt.Errorf("New dialer config: publickey auth: %v", err)
		}
		config.Auth = append(config.Auth, ssh.PublicKeys(signer))
		logrus.Tracef("New dialer config: ssh key auth")
		return "ssh key", config, nil
	}

	if sshAgentSock := os.Getenv("SSH_AUTH_SOCK"); len(sshAgentSock) > 0 && keyAgent {
		sshAgent, err := net.Dial("unix", sshAgentSock)
		if err != nil {
			return "", nil, fmt.Errorf("New dialer config: Cannot connect to SSH Auth socket %q: %s", sshAgentSock, err)
		}
		config.Auth = append(config.Auth, ssh.PublicKeysCallback(agent.NewClient(sshAgent).Signers))
		logrus.Tracef("New dialer config: ssh key agent auth")
		return "ssh key agent", config, nil
	}

	if len(pass) > 0 {
		config.Auth = append(config.Auth, ssh.Password(pass))
		logrus.Tracef("New dialer config: password auth")
		return "password", config, nil
	}

	return "", nil, fmt.Errorf("New dialer config: auth method not found")
}

func (c *Dialer) Dial(network, addr string, config *ssh.ClientConfig) (*Dialer, error) {
	connClient, err := ssh.Dial(network, addr, config)
	if err != nil {
		return nil, fmt.Errorf("[%s] Dialing host: %v", addr, err)
	}
	c.client = connClient
	logrus.Tracef("Dialer opened")
	return c, nil
}

func (c *Dialer) Close() error {
	logrus.Tracef("Dialer closed")
	if c.client == nil {
		return nil
	}
	return c.client.Close()
}

func (c *Dialer) Cmd(cmd string) error {
	session, err := c.client.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()
	logrus.Tracef("Dialer cmd executed")
	return session.Run(cmd)
}

func (c *Dialer) Output(cmd string) ([]byte, error) {
	session, err := c.client.NewSession()
	if err != nil {
		return nil, err
	}
	defer session.Close()
	logrus.Tracef("Dialer output executed")
	return session.Output(cmd)
}

func (c *Dialer) CombinedOutput(cmd string) ([]byte, error) {
	session, err := c.client.NewSession()
	if err != nil {
		return nil, err
	}
	defer session.Close()
	logrus.Tracef("Dialer combined output executed")
	return session.CombinedOutput(cmd)
}

func (c *Dialer) runScript(cmd string) error {
	session, err := c.client.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()

	//session.Stdin = cmd
	session.Stdout = c.stdout
	session.Stderr = c.stderr

	if err := session.Shell(); err != nil {
		return err
	}
	logrus.Tracef("Dialer run script executed")
	return session.Wait()
}
