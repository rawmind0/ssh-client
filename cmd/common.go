package cmd

import (
	"github.com/rancher/spur/cli"
	"github.com/rawmind0/ssh-client/pkg/ssh"
)

func commonFlags() []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{
			Name:    "config",
			Aliases: []string{"c"},
			Usage:   "Specify config YAML file",
			EnvVars: []string{"SSH_CLIENT_CONFIG"},
		},
		&cli.StringFlag{
			Name:  "hosts",
			Usage: "Comma separated host ip to connect",
		},
		&cli.StringFlag{
			Name:    "port",
			Aliases: []string{"p"},
			Usage:   "Host port to connect",
			Value:   ssh.DefaultPort,
		},
		&cli.StringFlag{
			Name:    "user",
			Aliases: []string{"u"},
			Usage:   "Username to auth",
			Value:   "rancher",
		},
		&cli.StringFlag{
			Name:  "password",
			Usage: "Password to auth",
		},
		&cli.BoolFlag{
			Name:  "ssh_agent_auth",
			Usage: "Use SSH agent auth",
			Value: false,
		},
		&cli.StringFlag{
			Name:  "ssh_key",
			Usage: "SSH key to auth",
		},
		&cli.StringFlag{
			Name:  "ssh_key_pass",
			Usage: "SSH key passphrase to auth. Optional",
		},
		&cli.StringFlag{
			Name:  "ssh_key_path",
			Usage: "SSH key path to auth",
			Value: ssh.DefaultKeyPath,
		},
		&cli.StringFlag{
			Name:  "ssh_keep_alive",
			Usage: "SSH connection keep alive interval",
			Value: ssh.DefaultHostKeepAlive,
		},
		&cli.StringFlag{
			Name:  "ssh_timeout",
			Usage: "SSH connection timeout interval. Set 0 to disable",
			Value: ssh.DefaultHostTimeout,
		},
	}
}
