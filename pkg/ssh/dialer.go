package ssh

import (
	"context"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

const (
	dialerDebugIndent     = "    "
	dialerRunKindCmd      = "cmd"
	dialerRunKindOutput   = "output"
	dialerRunKindCombined = "combined"
	dialerSSHTimeout      = "60s"
	dialerSSHKeepAlive    = "120s"
)

type dialerConfig struct {
	network      string
	addr         string
	SSHconfig    *ssh.ClientConfig
	SSHTimeout   time.Duration
	SSHKeepAlive time.Duration
}

// Dialer struct
type Dialer struct {
	client     *ssh.Client
	connConfig *dialerConfig
}

// NewDialer func
func NewDialer(ctx context.Context, addr, user, pass, key, keyPass string, keyAgent bool) (*Dialer, error) {
	if len(addr) == 0 {
		return nil, fmt.Errorf("New dialer: host address should be provided")
	}
	timeout, err := time.ParseDuration(dialerSSHTimeout)
	if err != nil {
		return nil, fmt.Errorf("New dialer: setting timeout: %v", err)
	}
	keepAlive, err := time.ParseDuration(dialerSSHKeepAlive)
	if err != nil {
		return nil, fmt.Errorf("New dialer: setting keep alive: %v", err)
	}
	dialer := &Dialer{
		connConfig: &dialerConfig{
			network:      "tcp",
			addr:         addr,
			SSHTimeout:   timeout,
			SSHKeepAlive: keepAlive,
		},
	}
	kind, err := dialer.getConnConfig(user, pass, key, keyPass, keyAgent)
	if err != nil {
		return nil, fmt.Errorf("New dialer %v", err)
	}
	err = dialer.dial(ctx)
	if err != nil {
		return nil, fmt.Errorf("New dialer %v", err)
	}
	logrus.Debugf("%s[%s] New dialer created: %s auth", dialerDebugIndent, dialer.connConfig.addr, kind)
	return dialer, nil
}

func (c *Dialer) getConnConfig(user, pass, key, keyPass string, keyAgent bool) (string, error) {
	if len(user) == 0 {
		return "", fmt.Errorf("config: user should be provided")
	}

	config := &ssh.ClientConfig{
		User:            user,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         c.connConfig.SSHTimeout,
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
			return "", fmt.Errorf("config: publickey auth: %v", err)
		}
		config.Auth = append(config.Auth, ssh.PublicKeys(signer))
		logrus.Debugf("%s[%s] New dialer config: ssh key auth", dialerDebugIndent, c.connConfig.addr)
		c.connConfig.SSHconfig = config
		return "ssh key", nil
	}

	if sshAgentSock := os.Getenv("SSH_AUTH_SOCK"); len(sshAgentSock) > 0 && keyAgent {
		sshAgent, err := net.Dial("unix", sshAgentSock)
		if err != nil {
			return "", fmt.Errorf("config: Cannot connect to SSH Auth socket %q: %s", sshAgentSock, err)
		}
		config.Auth = append(config.Auth, ssh.PublicKeysCallback(agent.NewClient(sshAgent).Signers))
		logrus.Debugf("%s[%s] New dialer config: ssh key agent auth", dialerDebugIndent, c.connConfig.addr)
		c.connConfig.SSHconfig = config
		return "ssh key agent", nil
	}

	if len(pass) > 0 {
		config.Auth = append(config.Auth, ssh.Password(pass))
		logrus.Debugf("%s[%s] New dialer config: password auth", dialerDebugIndent, c.connConfig.addr)
		c.connConfig.SSHconfig = config
		return "password", nil
	}

	return "", fmt.Errorf("New dialer config: auth method not found")
}

func (c *Dialer) dial(ctx context.Context) error {
	if c.client != nil {
		return nil
	}
	logrus.Debugf("%s[%s] Dialer openning...", dialerDebugIndent, c.connConfig.addr)
	wgErrors, errStrings := newErrorByChan()
	go func() {
		connClient, err := ssh.Dial(c.connConfig.network, c.connConfig.addr, c.connConfig.SSHconfig)
		if err != nil {
			message := err.Error()
			if len(message) > 0 {
				wgErrors <- &message
			}
		}
		c.client = connClient
		close(wgErrors)
	}()
	select {
	case <-ctx.Done():
		logrus.Debugf("%s[%s] Dialer open cancelled: %s", dialerDebugIndent, c.connConfig.addr, ctx.Err())
		return fmt.Errorf("Dialer open killed by user request")
	case errStr := <-wgErrors:
		if errStr == nil {
			break
		}
		errStrings = append(errStrings, *errStr)
	}
	if len(errStrings) > 0 {
		return fmt.Errorf("Dialer open failed:\n%s", stringsToLines(errStrings))
	}
	logrus.Debugf("%s[%s] Dialer opened", dialerDebugIndent, c.connConfig.addr)
	return nil
}

func (c *Dialer) keepAlive(ctx context.Context) {
	t := time.NewTicker(c.connConfig.SSHKeepAlive)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			_, _, err := c.client.SendRequest("keepalive@golang.org", true, nil)
			if err != nil {
				logrus.Warnf("%s[%s] Dialer keepalive failed: %s", dialerDebugIndent, c.connConfig.addr, err)
			}
		case <-ctx.Done():
			logrus.Debugf("%s[%s] Dialer keepalive done", dialerDebugIndent, c.connConfig.addr)
			return
		}
	}
}

// Close func
func (c *Dialer) Close() error {
	logrus.Debugf("%s[%s] Dialer closing...", dialerDebugIndent, c.connConfig.addr)
	if c.client != nil {
		if err := c.client.Close(); err != nil {
			return err
		}
	}
	logrus.Debugf("%sDialer closed", dialerDebugIndent)
	return nil
}

func (c *Dialer) run(ctx context.Context, cmd, kind string) ([]byte, error) {
	logrus.Debugf("%s[%s] Dialer run executing...", dialerDebugIndent, c.connConfig.addr)
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
		logrus.Debugf("%s[%s] Dialer run cancelled: %s", dialerDebugIndent, c.connConfig.addr, ctx.Err())
		return nil, fmt.Errorf("Dialer run cancelled: %s", ctx.Err())
	case errStr := <-wgErrors:
		if errStr == nil {
			break
		}
		errStrings = append(errStrings, *errStr)
	}
	if len(errStrings) > 0 {
		return data, fmt.Errorf("Dialer run failed:\n%s", stringsToLines(errStrings))
	}
	logrus.Debugf("%s[%s] Dialer run executed", dialerDebugIndent, c.connConfig.addr)
	return data, nil
}
