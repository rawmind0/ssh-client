package main

import (
	"io/ioutil"
	"os"
	"regexp"

	"github.com/mattn/go-colorable"
	"github.com/rancher/spur/cli"
	"github.com/rawmind0/ssh-client/cmd"
	"github.com/sirupsen/logrus"
)

// VERSION gets overridden at build time using -X main.VERSION=$VERSION
var VERSION = "dev"
var released = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)

func main() {
	logrus.SetOutput(colorable.NewColorableStdout())

	if err := mainErr(); err != nil {
		logrus.Fatal(err)
	}
}

func mainErr() error {
	app := cli.NewApp()
	app.Name = "ssh-client"
	app.Version = VERSION
	app.Usage = "ssh client to multiple nodes"
	app.Before = func(ctx *cli.Context) error {
		if ctx.Bool("quiet") {
			logrus.SetOutput(ioutil.Discard)
		} else {
			if ctx.Bool("debug") {
				logrus.SetLevel(logrus.DebugLevel)
				logrus.Debugf("Loglevel set to [%v]", logrus.DebugLevel)
			}
		}
		if !released.MatchString(app.Version) {
			logrus.Warnf("This is not an officially released version (%s) of %s. Latest official release at https://github.com/rawmind0/ssh-client/releases/latest", app.Version, app.Name)
		}
		return nil
	}
	author := &cli.Author{Name: "Rancher Labs, Inc."}
	app.Authors = []*cli.Author{author}
	app.Commands = []*cli.Command{
		cmd.RunCommand(),
	}
	app.Flags = []cli.Flag{
		&cli.BoolFlag{
			Name:  "debug,d",
			Usage: "Debug logging",
		},
		&cli.BoolFlag{
			Name:  "quiet,q",
			Usage: "Quiet mode, disables logging and only critical output will be printed",
		},
	}
	return app.Run(os.Args)
}
