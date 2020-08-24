package cmd

import (
	"fmt"
	"io/ioutil"

	"github.com/rancher/spur/cli"
	"github.com/rawmind0/ssh-client/pkg/ssh"
	"github.com/sirupsen/logrus"
)

// RunCommand func
func RunCommand() *cli.Command {
	runFlags := []cli.Flag{
		&cli.StringFlag{
			Name:    "config",
			Aliases: []string{"c"},
			Usage:   "Specify config YAML file",
			EnvVars: []string{"SSH_CLIENT_NODES"},
		},
		&cli.StringFlag{
			Name:  "cmd",
			Usage: "Command to run. Multiple entry allowed sepparated by ,",
		},
		&cli.StringFlag{
			Name:  "host",
			Usage: "Host ip to connect. Multiple entry allowed sepparated by ,",
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
			Value: ssh.InitKeyPath(),
		},
	}

	return &cli.Command{
		Name:   "run",
		Usage:  "Run commnads on nodes",
		Action: RunFromCli,
		Flags:  runFlags,
	}
}

// RunFromCli func
func RunFromCli(ctx *cli.Context) error {
	logrus.Infof("Running ssh-client version: %v", ctx.App.Version)
	return fmt.Errorf("%s", ctx.String("ssh_key_path"))
	output := map[string]interface{}{}
	configFile := ctx.String("config")
	if len(configFile) > 0 {
		configByte, err := ioutil.ReadFile(configFile)
		if err != nil {
			return fmt.Errorf("Reading config file: %v", err)
		}
		output, err = ssh.GhodssYAMLToMapInterface(string(configByte))
		if err != nil {
			return fmt.Errorf("Reading config file: %v", err)
		}
	}
	host := ctx.String("host")
	hosts := ssh.SplitBySep(host)
	params := map[string]interface{}{}
	params["port"] = ctx.String("port")
	params["user"] = ctx.String("user")
	params["password"] = ctx.String("password")
	params["ssh_agent_auth"] = ctx.Bool("ssh_agent_auth")
	params["ssh_key"] = ctx.String("ssh_key")
	params["ssh_key_pass"] = ctx.String("ssh_key_pass")
	params["ssh_key_path"] = ctx.String("ssh_key_path")

	if output["hosts"] == nil {
		output["hosts"] = make([]interface{}, len(hosts))
	}
	if cmd := ctx.String("cmd"); len(cmd) > 0 {
		output["cmd"] = ssh.SplitBySep(cmd)
	}
	for i := range hosts {
		params["address"] = hosts[i]
		output["hosts"].([]interface{})[i] = params
	}
	return Run(output)
}

// Run func
func Run(params map[string]interface{}) error {
	config, err := ssh.InterfaceToYAML(params)
	if err != nil {
		return err
	}
	client, err := ssh.NewClientFromYAML(config)
	if err != nil {
		return err
	}
	return client.Run()
}
