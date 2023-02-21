// main package for gopass-ssh-add
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"

	"github.com/gopasspw/gopass/pkg/ctxutil"
	"github.com/urfave/cli/v2"

	apexlog "github.com/apex/log"
	apexlogcli "github.com/apex/log/handlers/cli"
)

const (
	appName = "gopass-ssh-add"
)

// Version is the released version of gopass.
var (
	version string
)

func main() {
	ctx := context.Background()

	// trap Ctrl+C and call cancel on the context.
	ctx, cancel := context.WithCancel(ctx)
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt)
	defer func() {
		signal.Stop(sigChan)
		cancel()
	}()
	go func() {
		select {
		case <-sigChan:
			cancel()
		case <-ctx.Done():
		}
	}()

	// reading from stdin?
	if info, err := os.Stdin.Stat(); err == nil && info.Mode()&os.ModeCharDevice == 0 {
		ctx = ctxutil.WithInteractive(ctx, false)
		ctx = ctxutil.WithStdin(ctx, true)
	}

	gs, err := newGopassStorage(ctx)
	if err != nil {
		fmt.Printf("Failed to initialize gopass API: %s\n", err)
		os.Exit(1)
	}

	sshAgentObj, err := newSSHAgent()
	if err != nil {
		fmt.Printf("Failed to open ssh-agent: %s\n", err)
		os.Exit(1)
	}

	cb, err := newClipboard(ctx)
	if err != nil {
		fmt.Printf("Failed to open clipboard agent: %s\n", err)
		os.Exit(1)
	}

	logger := apexlog.Logger{
		Handler: apexlogcli.New(os.Stdout),
		Level:   apexlog.InfoLevel,
	}

	gc := &gc{
		gs:     gs,
		sa:     sshAgentObj,
		cb:     cb,
		logger: logger,
	}

	app := cli.NewApp()
	app.Name = appName
	app.Version = getVersion().String()
	app.Usage = `Use "gopass" as storage for ssh keys`
	app.Description = "" +
		"This command allows you to generate ssh keys, save it to gopass store " +
		"and add it to ssh-agent."
	app.EnableBashCompletion = true
	app.Flags = []cli.Flag{
		&cli.StringFlag{
			Name:  "store",
			Value: "ssh-keys",
			Usage: "First part of path to find the secret.",
		},
		&cli.BoolFlag{
			Name:    "quiet",
			Value:   false,
			Aliases: []string{"q", "silent"},
			Usage:   "Do not write logs to stdout",
		},
		&cli.BoolFlag{
			Name:    "yes",
			Value:   false,
			Aliases: []string{"y"},
			Usage:   "answer yes to all confirmations",
		},
	}
	app.Commands = []*cli.Command{
		// working with ssh-agent
		{
			Name:        "ssh-agent",
			Description: "manage with ssh-agent",
			Aliases:     []string{"ssh", "ssh-add"},
			Hidden:      false,
			Subcommands: []*cli.Command{
				{
					Name:         "add",
					Description:  "add ssh-key to ssh-agent",
					Aliases:      []string{"a"},
					Hidden:       false,
					Action:       gc.SSHAdd,
					Before:       gc.Before,
					BashComplete: gc.PathAutocomplete,
					Flags: []cli.Flag{
						&cli.IntFlag{
							Name:    "lifetime",
							Value:   0,
							Aliases: []string{"time", "t"},
							Usage:   "Set a maximum lifetime when adding identities to an agent.",
						},
					},
				},
				{
					Name:         "delete",
					Description:  "delete ssh-key from ssh-agent",
					Aliases:      []string{"remove", "del", "rm"},
					Hidden:       false,
					Action:       gc.SSHDelete,
					Before:       gc.Before,
					BashComplete: gc.PathAutocomplete,
				},
				{
					Name:        "list",
					Description: "show keys list in ssh-agent",
					Aliases:     []string{"ls"},
					Hidden:      false,
					Action:      gc.SSHList,
					Before:      gc.BeforeBase,
				},
				{
					Name:        "clear",
					Description: "delete all keys from ssh agent",
					Aliases:     []string{},
					Hidden:      false,
					Action:      gc.SSHClear,
					Before:      gc.BeforeBase,
				},
			},
		},

		// manage secret
		{
			Name:        "secret",
			Aliases:     []string{},
			Description: "manage secrets",
			Hidden:      false,
			Subcommands: []*cli.Command{
				// delete ssh-key secret completely
				{
					Name:         "delete",
					Description:  "delete secret from gopass storage",
					Hidden:       false,
					Action:       gc.Delete,
					Before:       gc.Before,
					Aliases:      []string{"remove", "del", "rm"},
					BashComplete: gc.PathAutocomplete,
				},
				// password section
				{
					Name:        "password",
					Description: "manage secret password",
					Hidden:      false,
					Aliases:     []string{"pass", "passwd"},
					Subcommands: []*cli.Command{
						{
							Name:         "show",
							Description:  "show secret password",
							Hidden:       false,
							Action:       gc.ShowPassword,
							Before:       gc.Before,
							Aliases:      []string{},
							BashComplete: gc.PathAutocomplete,
							Flags: []cli.Flag{
								appCopyFlag,
							},
						},
						{
							Name:         "delete",
							Description:  "delete secret password",
							Hidden:       false,
							Action:       gc.DeletePassword,
							Before:       gc.Before,
							Aliases:      []string{"remove", "del", "rm"},
							BashComplete: gc.PathAutocomplete,
						},
						{
							Name:         "generate",
							Description:  "generate secret password",
							Hidden:       false,
							Action:       gc.GeneratePassword,
							Before:       gc.Before,
							Aliases:      []string{"gen", "random", "rand"},
							BashComplete: gc.PathAutocomplete,
							Flags:        append([]cli.Flag{}, appPasswordFlags...),
						},
						{
							Name:         "insert",
							Description:  "insert secret password from stdin",
							Hidden:       false,
							Action:       gc.InsertPassword,
							Before:       gc.Before,
							Aliases:      []string{"import"},
							BashComplete: gc.PathAutocomplete,
						},
					},
				},
				{
					Name:        "key",
					Description: "manage ssh-key in secret",
					Hidden:      false,
					Aliases:     []string{"ssh-key"},
					Subcommands: []*cli.Command{
						// run ssh-keygen
						{
							Name:         "keygen",
							Description:  "generate ssh-key and save it",
							Hidden:       false,
							Action:       gc.SSHKeygen,
							Before:       gc.Before,
							Aliases:      []string{"generate", "gen"},
							BashComplete: gc.PathAutocomplete,
							Flags:        append(appSSHKeygenFlags, appPasswordFlags...),
						},
						// delete ssh-key (private and puplic) from secret
						{
							Name:         "delete",
							Description:  "delete ssh-key from secret",
							Hidden:       false,
							Action:       gc.DeleteSSHKey,
							Before:       gc.Before,
							Aliases:      []string{"remove", "del", "rm"},
							BashComplete: gc.PathAutocomplete,
						},
						{
							Name:        "private",
							Description: "manage private ssh-key section",
							Hidden:      false,
							Aliases:     []string{},
							Subcommands: []*cli.Command{
								{
									Name:         "insert",
									Description:  "insert private ssh-key from stdin",
									Hidden:       false,
									Action:       gc.InsertSSHPrivateKey,
									Before:       gc.Before,
									Aliases:      []string{"import"},
									BashComplete: gc.PathAutocomplete,
								},
								{
									Name:         "show",
									Description:  "show private ssh-key",
									Hidden:       false,
									Action:       gc.ShowSSHPrivateKey,
									Before:       gc.Before,
									Aliases:      []string{},
									BashComplete: gc.PathAutocomplete,
									Flags: []cli.Flag{
										appCopyFlag,
									},
								},
								{
									Name:         "delete",
									Description:  "delete private ssh-key",
									Hidden:       false,
									Action:       gc.DeleteSSHPrivateKey,
									Before:       gc.Before,
									Aliases:      []string{"remove", "del", "rm"},
									BashComplete: gc.PathAutocomplete,
								},
							},
						},
						{
							Name:        "public",
							Description: "manage public ssh-key section",
							Hidden:      false,
							Aliases:     []string{},
							Subcommands: []*cli.Command{
								{
									Name:         "insert",
									Description:  "insert public ssh-key from stdin",
									Hidden:       false,
									Action:       gc.InsertSSHPublicKey,
									Before:       gc.Before,
									Aliases:      []string{"import"},
									BashComplete: gc.PathAutocomplete,
								},
								{
									Name:         "show",
									Description:  "show public ssh-key",
									Hidden:       false,
									Action:       gc.ShowSSHPublicKey,
									Before:       gc.Before,
									Aliases:      []string{},
									BashComplete: gc.PathAutocomplete,
									Flags: []cli.Flag{
										appCopyFlag,
									},
								},
								{
									Name:         "delete",
									Description:  "delete public ssh-key",
									Hidden:       false,
									Action:       gc.DeleteSSHPublicKey,
									Before:       gc.Before,
									Aliases:      []string{"remove", "del", "rm"},
									BashComplete: gc.PathAutocomplete,
								},
							},
						},
					},
				},
			},
		},

		// show version
		{
			Name: "version",
			Action: func(c *cli.Context) error {
				cli.VersionPrinter(c)
				return nil
			},
		},
	}

	if err := app.RunContext(ctx, os.Args); err != nil {
		log.Fatal(err)
	}
}
