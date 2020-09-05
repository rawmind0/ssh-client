ssh-client
========

[![Go Report Card](https://goreportcard.com/badge/github.com/rawmind0/ssh-client)](https://goreportcard.com/report/github.com/rawmind0/ssh-client)

ssh-client is a tool to execute commands concurrently on multiple hosts by ssh. It can be used as go module in your app or executing it from the binary.

## Building

* To build the provider

`make`

## Running

* ssh-cli tool

```
$ ./ssh-client -h
NAME:
   ssh-client - ssh client to multiple nodes

USAGE:
   ssh-client [global options] command [command options] [arguments...]

VERSION:
   dev

AUTHOR:
   Rancher Labs, Inc.

COMMANDS:
   run      Run commnads on nodes
   help, h  Shows a list of commands or help for one command

GLOBAL OPTIONS:
   --debug, -d    Debug logging (default: false)
   --quiet, -q    Quiet mode, disables logging and only critical output will be printed (default: false)
   --help, -h     show help (default: false)
   --version, -v  print the version (default: false)
```

* ssh-cli run command

```
./ssh-client run -h
NAME:
   ssh-client run - Run commnads on nodes

USAGE:
   ssh-client run [command options] [arguments...]

OPTIONS:
  --config value, -c value  Specify config YAML file [$SSH_CLIENT_NODES]
   --cmd value               Command to run. Multiple entry allowed sepparated by ,
   --cmd_file value          Script files to run. Multiple entry allowed sepparated by ,
   --host value              Host ip to connect. Multiple entry allowed sepparated by ,
   --port value, -p value    Host port to connect (default: "22")
   --user value, -u value    Username to auth (default: "rancher")
   --password value          Password to auth
   --ssh_agent_auth          Use SSH agent auth (default: false)
   --ssh_key value           SSH key to auth
   --ssh_key_pass value      SSH key passphrase to auth. Optional
   --ssh_key_path value      SSH key path to auth (default: "/Users/rsanchez/.ssh/id_rsa")
   --ssh_keep_alive value    SSH connection keep alive interval (default: "60s")
   --ssh_timeout value       SSH connection timeout interval (default: "60s")
   --timeout value           Command execution timeout interval (default: "300s")
   --help, -h                show help (default: false)
```

## Configuring

The tool can be configured in different ways:

* using run arguments:
```
   --config value, -c value  Specify config YAML file [$SSH_CLIENT_NODES]
   --cmd value               Command to run. Multiple entry allowed sepparated by ,
   --cmd_file value          Script files to run. Multiple entry allowed sepparated by ,
   --host value              Host ip to connect. Multiple entry allowed sepparated by ,
   --port value, -p value    Host port to connect (default: "22")
   --user value, -u value    Username to auth (default: "rancher")
   --password value          Password to auth
   --ssh_agent_auth          Use SSH agent auth (default: false)
   --ssh_key value           SSH key to auth
   --ssh_key_pass value      SSH key passphrase to auth. Optional
   --ssh_key_path value      SSH key path to auth (default: "/Users/rsanchez/.ssh/id_rsa")
   --ssh_keep_alive value    SSH connection keep alive interval (default: "60s")
   --ssh_timeout value       SSH connection timeout interval (default: "60s")
   --timeout value           Command execution timeout interval (default: "300s")
   --help, -h                show help (default: false)
```

* using config file `--config file`. The config file should be in yaml format:
```
hosts:
- address: string
  port: string
  user: string
  password: string
  ssh_agent_auth: bool
  ssh_key: string
  ssh_key_pass: string
  ssh_key_path: string
  ssh_cert: string
  ssh_cert_path: string
  ssh_timeout: string
  ssh_keep_alive: string
cmd: 
  - cmd1
  ...
  - cmdN
cmd_file:
  - file1
  ...
  - fileN 
timeout: string
```

## Authenticating

The tool can ssh auth in different ways:
* Using ssh key, `--ssh_key key` and optionally `--ssh_key_pass value` if key requires password 
* Using ssh key path, `--ssh_key_path file` and optionally `--ssh_key_pass value` if key requires password 
* Using ssh key agent, `--ssh_agent_auth`
* Using password, `--password value`

## License
Copyright (c) 2019 [Rancher Labs, Inc.](http://rancher.com)

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

[http://www.apache.org/licenses/LICENSE-2.0](http://www.apache.org/licenses/LICENSE-2.0)

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
