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
			Name:  "cmds",
			Usage: "Comma separated commands to run",
		},
		&cli.StringFlag{
			Name:  "cmd_files",
			Usage: "Comma separated script files to run",
		},
		&cli.StringFlag{
			Name:  "timeout",
			Usage: "Command execution timeout interval. Set 0 to disable",
			Value: ssh.DefaultPoolTimeout,
		},
	}

	runFlags = append(runFlags, commonFlags()...)

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
	output := map[string]interface{}{
		"timeout": ctx.String("timeout"),
	}
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
	host := ctx.String("hosts")
	hosts := ssh.SplitBySep(host)
	params := map[string]interface{}{}
	params["port"] = ctx.String("port")
	params["user"] = ctx.String("user")
	params["password"] = ctx.String("password")
	params["ssh_agent_auth"] = ctx.Bool("ssh_agent_auth")
	params["ssh_key"] = ctx.String("ssh_key")
	params["ssh_key_pass"] = ctx.String("ssh_key_pass")
	params["ssh_key_path"] = ctx.String("ssh_key_path")
	params["ssh_keep_alive"] = ctx.String("ssh_keep_alive")
	params["ssh_timeout"] = ctx.String("ssh_timeout")

	if output["hosts"] == nil {
		output["hosts"] = make([]interface{}, len(hosts))
	}
	if cmds := ctx.String("cmds"); len(cmds) > 0 {
		output["cmds"] = ssh.SplitBySep(cmds)
	}
	if cmdFiles := ctx.String("cmd_files"); len(cmdFiles) > 0 {
		output["cmd_files"] = ssh.SplitBySep(cmdFiles)
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
	client, err := ssh.NewPoolFromYAML(config)
	if err != nil {
		return err
	}
	defer client.Close()
	return client.Run()
}
