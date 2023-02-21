package main

import "github.com/urfave/cli/v2"

var appCopyFlag = &cli.BoolFlag{
	Name:    "clipboard",
	Value:   false,
	Aliases: []string{"clip", "copy", "c"},
	Usage:   "Copy content to clipboard",
}

var appPasswordFlags = []cli.Flag{
	&cli.IntFlag{
		Name:    "length",
		Value:   32,
		Aliases: []string{"l"},
		Usage:   "Password length",
	},
	&cli.BoolFlag{
		Name:    "symbols",
		Value:   true,
		Aliases: []string{"s"},
		Usage:   "Add symbols to password",
	},
}

var appSSHKeygenFlags = []cli.Flag{
	&cli.StringFlag{
		Name:    "type",
		Value:   "ed25519",
		Aliases: []string{"t"},
		Usage:   "Ssh key type",
	},
	&cli.StringFlag{
		Name:    "comment",
		Value:   "",
		Aliases: []string{"C"},
		Usage:   "Ssh key comment",
	},
	&cli.IntFlag{
		Name:    "bits",
		Value:   4096,
		Aliases: []string{"bit", "b"},
		Usage:   "Ssh key bits",
	},
}
