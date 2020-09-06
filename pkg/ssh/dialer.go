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
	dialerTimeout         = "60s"
	dialerKeepAlive       = "60s"
	dialerLocal           = "local"
	dialerTunnelDial      = "tunnel"
)

type dialerConfig struct {
	network   string
	addr      string
	SSHconfig *ssh.ClientConfig
	timeout   time.Duration
	keepAlive time.Duration
}

// Dialer struct
type Dialer struct {
	tunnel  *ssh.Client
	config  *dialerConfig
	conns   map[string]net.Conn
	isLocal bool
}

// NewDialer func
func NewDialer(ctx context.Context, addr, user, pass, key, keyPass string, keyAgent bool, timeout, keepAlive string) (*Dialer, error) {
	if len(addr) == 0 {
		return nil, fmt.Errorf("New dialer: host address should be provided")
	}
	if addr == dialerLocal {

	}
	if len(timeout) == 0 {
		timeout = dialerTimeout
	}
	timeoutDuration, err := time.ParseDuration(timeout)
	if err != nil {
		return nil, fmt.Errorf("New dialer: setting timeout: %v", err)
	}
	if len(keepAlive) == 0 {
		keepAlive = dialerKeepAlive
	}
	keepAliveDuration, err := time.ParseDuration(keepAlive)
	if err != nil {
		return nil, fmt.Errorf("New dialer: setting keep alive: %v", err)
	}
	dialer := &Dialer{
		config: &dialerConfig{
			network:   "tcp",
			addr:      addr,
			timeout:   timeoutDuration,
			keepAlive: keepAliveDuration,
		},
	}
	kind, err := dialer.setConfig(user, pass, key, keyPass, keyAgent)
	if err != nil {
		return nil, fmt.Errorf("New dialer %v", err)
	}
	err = dialer.tunnelUp(ctx)
	if err != nil {
		return nil, fmt.Errorf("New dialer %v", err)
	}
	logrus.Debugf("%s[%s] New dialer created: %s", dialerDebugIndent, dialer.config.addr, kind)
	return dialer, nil
}

func (c *Dialer) setConfig(user, pass, key, keyPass string, keyAgent bool) (string, error) {
	if len(user) == 0 {
		return "", fmt.Errorf("config: user should be provided")
	}
	if c.config.addr == "local" {
		c.isLocal = true
		return "local", nil
	}
	config := &ssh.ClientConfig{
		User:            user,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         c.config.timeout,
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
		logrus.Debugf("%s[%s] New dialer config: ssh key auth", dialerDebugIndent, c.config.addr)
		c.config.SSHconfig = config
		return "ssh key", nil
	}

	if sshAgentSock := os.Getenv("SSH_AUTH_SOCK"); len(sshAgentSock) > 0 && keyAgent {
		sshAgent, err := net.Dial("unix", sshAgentSock)
		if err != nil {
			return "", fmt.Errorf("config: Cannot connect to SSH Auth socket %q: %s", sshAgentSock, err)
		}
		defer sshAgent.Close()
		config.Auth = append(config.Auth, ssh.PublicKeysCallback(agent.NewClient(sshAgent).Signers))
		logrus.Debugf("%s[%s] New dialer config: ssh key agent auth", dialerDebugIndent, c.config.addr)
		c.config.SSHconfig = config
		return "ssh key agent", nil
	}

	if len(pass) > 0 {
		config.Auth = append(config.Auth, ssh.Password(pass))
		logrus.Debugf("%s[%s] New dialer config: password auth", dialerDebugIndent, c.config.addr)
		c.config.SSHconfig = config
		return "password", nil
	}

	return "", fmt.Errorf("New dialer config: auth method not found")
}

func (c *Dialer) newDialer() net.Dialer {
	return net.Dialer{
		Timeout:   c.config.timeout,
		KeepAlive: c.config.keepAlive,
	}
}

// Dial funct
func (c *Dialer) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	if network == dialerTunnelDial && (c.tunnel != nil || c.isLocal) {
		return nil, nil
	}
	connKey := network + "_" + addr
	if c.conns[connKey] != nil {
		return c.conns[connKey], nil
	}
	logrus.Debugf("%s[%s]->%s Dial openning ...", dialerDebugIndent, c.config.addr, connKey)
	if c.isLocal {
		dialer := c.newDialer()
		conn, err := dialer.DialContext(ctx, network, addr)
		if err != nil {
			return nil, fmt.Errorf("Dialer open failed: %v", err)
		}
		c.conns[connKey] = conn
		logrus.Debugf("%s[local]->%s Dialer opened", c.config.addr, connKey)
		return conn, nil
	}
	wgErrors, errStrings := newErrorByChan()
	go func() {
		defer close(wgErrors)
		if c.tunnel == nil {
			err := c.dialTunnel()
			if err != nil {
				message := err.Error()
				if len(message) > 0 {
					wgErrors <- &message
					return
				}
			}
			if network == dialerTunnelDial {
				logrus.Debugf("%s[%s]->%s Dialer opened", dialerDebugIndent, c.config.addr, connKey)
				return
			}
		}
		conn, err := c.tunnel.Dial(network, addr)
		c.conns[connKey] = conn
		if err != nil {
			message := err.Error()
			if len(message) > 0 {
				wgErrors <- &message
				return
			}

		}
	}()
	select {
	case <-ctx.Done():
		logrus.Debugf("%s[%s]->%s Dialer open cancelled: %s", dialerDebugIndent, c.config.addr, connKey, ctx.Err())
		return nil, fmt.Errorf("Dialer open killed by user request: %s", connKey)
	case errStr := <-wgErrors:
		if errStr == nil {
			break
		}
		errStrings = append(errStrings, *errStr)
	}
	if len(errStrings) > 0 {
		return nil, fmt.Errorf("Dialer open failed: %s\n%s", connKey, stringsToLines(errStrings))
	}
	logrus.Debugf("%s[%s]->%s Dialer opened", dialerDebugIndent, c.config.addr, connKey)
	return c.conns[connKey], nil
}

func (c *Dialer) dialTunnel() error {
	logrus.Debugf("%s[%s] Dialer tunneling..", dialerDebugIndent, c.config.addr)
	dialer := c.newDialer()
	conn, err := dialer.Dial(c.config.network, c.config.addr)
	if err != nil {
		return fmt.Errorf("Tunnel up failed: %v", err)
	}
	sshConn, sshChans, sshReqs, err := ssh.NewClientConn(conn, c.config.addr, c.config.SSHconfig)
	if err != nil {
		return fmt.Errorf("Tunnel up failed: %v", err)
	}
	c.tunnel = ssh.NewClient(sshConn, sshChans, sshReqs)
	logrus.Debugf("%s[%s] Dialer tunneled", dialerDebugIndent, c.config.addr)
	return nil
}

func (c *Dialer) tunnelUp(ctx context.Context) error {
	_, err := c.Dial(ctx, dialerTunnelDial, c.config.addr)
	return err
}

// Close funct
func (c *Dialer) Close() error {
	logrus.Debugf("%s[%s] Dialer closing...", dialerDebugIndent, c.config.addr)
	for _, t := range c.conns {
		t.Close()
	}
	if c.tunnel != nil {
		if err := c.tunnel.Close(); err != nil {
			return err
		}
	}
	logrus.Debugf("%sDialer closed", dialerDebugIndent)
	return nil
}

func (c *Dialer) run(ctx context.Context, cmd, kind string) ([]byte, error) {
	logrus.Debugf("%s[%s] Dialer run executing...", dialerDebugIndent, c.config.addr)
	if len(cmd) == 0 {
		return nil, fmt.Errorf("Dialer run failed: Command is nil")
	}
	err := c.tunnelUp(ctx)
	if err != nil {
		return nil, err
	}
	session, err := c.tunnel.NewSession()
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
		logrus.Debugf("%s[%s] Dialer run cancelled: %s", dialerDebugIndent, c.config.addr, ctx.Err())
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
	logrus.Debugf("%s[%s] Dialer run executed", dialerDebugIndent, c.config.addr)
	return data, nil
}
