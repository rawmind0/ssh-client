package ssh

import (
	"context"
	"fmt"
	"net"
	"os"

	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

const (
	dialerDebugIndent     = "    "
	dialerRunKindCmd      = "cmd"
	dialerRunKindOutput   = "output"
	dialerRunKindCombined = "combined"
)

// Dialer struct
type Dialer struct {
	client *ssh.Client
}

// NewDialerWithPasswd func
func NewDialerWithPasswd(addr, user, pass string) (*Dialer, error) {
	return NewDialer(addr, user, pass, "", "", false)
}

// NewDialerWithKey func
func NewDialerWithKey(addr, user, key, keypass string) (*Dialer, error) {
	return NewDialer(addr, user, "", key, keypass, false)
}

// NewDialerWithKeyAgent func
func NewDialerWithKeyAgent(addr, user string) (*Dialer, error) {
	return NewDialer(addr, user, "", "", "", true)
}

// NewDialer func
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
	logrus.Debugf("%sNew dialer created: %s auth", dialerDebugIndent, kind)
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
		logrus.Debugf("%sNew dialer config: ssh key auth", dialerDebugIndent)
		return "ssh key", config, nil
	}

	if sshAgentSock := os.Getenv("SSH_AUTH_SOCK"); len(sshAgentSock) > 0 && keyAgent {
		sshAgent, err := net.Dial("unix", sshAgentSock)
		if err != nil {
			return "", nil, fmt.Errorf("New dialer config: Cannot connect to SSH Auth socket %q: %s", sshAgentSock, err)
		}
		config.Auth = append(config.Auth, ssh.PublicKeysCallback(agent.NewClient(sshAgent).Signers))
		logrus.Debugf("%sNew dialer config: ssh key agent auth", dialerDebugIndent)
		return "ssh key agent", config, nil
	}

	if len(pass) > 0 {
		config.Auth = append(config.Auth, ssh.Password(pass))
		logrus.Debugf("%sNew dialer config: password auth", dialerDebugIndent)
		return "password", config, nil
	}

	return "", nil, fmt.Errorf("New dialer config: auth method not found")
}

// Dial func
func (c *Dialer) Dial(network, addr string, config *ssh.ClientConfig) (*Dialer, error) {
	logrus.Debugf("%sDialer openning...", dialerDebugIndent)
	connClient, err := ssh.Dial(network, addr, config)
	if err != nil {
		return nil, fmt.Errorf("[%s] Dialing host: %v", addr, err)
	}
	c.client = connClient
	logrus.Debugf("%sDialer opened", dialerDebugIndent)
	return c, nil
}

// Close func
func (c *Dialer) Close() error {
	logrus.Debugf("%sDialer closing...", dialerDebugIndent)
	if c.client != nil {
		if err := c.client.Close(); err != nil {
			return err
		}
	}
	logrus.Debugf("%sDialer closed", dialerDebugIndent)
	return nil
}

// Run func
func (c *Dialer) Run(ctx context.Context, cmd, kind string) ([]byte, error) {
	logrus.Debugf("%sDialer run executing...", dialerDebugIndent)
	if len(cmd) == 0 {
		return nil, fmt.Errorf("Dialer run failed: Command is nil")
	}
	session, err := c.client.NewSession()
	if err != nil {
		return nil, err
	}
	defer session.Close()
	var data []byte
	wgErrors, errStrings := newErrorByChan()
	go func() {
		var err error
		switch kind {
		case dialerRunKindCmd:
			err = session.Run(cmd)
		case dialerRunKindOutput:
			data, err = session.Output(cmd)
		default:
			data, err = session.CombinedOutput(cmd)
			if err != nil {
				err = fmt.Errorf("%s", string(data))
			}
		}

		if err != nil {
			message := err.Error()
			if len(message) > 0 {
				wgErrors <- &message
			}
		}
		close(wgErrors)
	}()

	select {
	case <-ctx.Done():
		session.Signal(ssh.SIGKILL)
		logrus.Debugf("%sDialer run killed by user request", dialerDebugIndent)
		return nil, fmt.Errorf("Dialer run execution killed by user request%s")
	case errStr := <-wgErrors:
		if errStr == nil {
			break
		}
		errStrings = append(errStrings, *errStr)
	}
	if len(errStrings) > 0 {
		return data, fmt.Errorf("Dialer run execution failed:\n%s", stringsToLines(errStrings))
	}
	logrus.Debugf("%sDialer run executed", dialerDebugIndent)
	return data, nil
}
