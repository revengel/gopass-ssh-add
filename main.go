// main package for gopass-ssh-add
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"

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
			Name:        "store",
			Value:       "ssh-keys",
			DefaultText: "ssh-keys",
			Usage:       "first part of path to find the secret",
		},
		&cli.BoolFlag{
			Name:    "quiet",
			Value:   false,
			Aliases: []string{"q", "silent"},
			Usage:   "do not write logs to stdout",
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
			Name:        "agent",
			Description: "Manage ssh-agent",
			Usage:       "manage ssh-agent",
			Aliases:     []string{},
			Hidden:      false,
			Subcommands: []*cli.Command{
				{
					Name:        "add",
					Description: "Add ssh-key to ssh-agent",
					Usage:       "add ssh-key to ssh-agent",
					UsageText: "`gopass-ssh-add --store=ssh-keys agent add path/to/ssh/key` # Add ssh-key to agent forever\n\n" +
						"`gopass-ssh-add --store=ssh-keys agent add --time=300 path/to/ssh/key` # Add ssh-key to agent for 5 minutes",
					Aliases:      []string{},
					Hidden:       false,
					Action:       gc.SSHAdd,
					Before:       gc.Before,
					BashComplete: gc.PathAutocomplete,
					Flags: []cli.Flag{
						&cli.IntFlag{
							Name:    "lifetime",
							Value:   0,
							Aliases: []string{"time", "t"},
							Usage:   "set a maximum lifetime when adding identities to an agent.",
						},
					},
				},
				{
					Name:         "delete",
					Description:  "Delete ssh-key from ssh-agent",
					Usage:        "delete ssh-key from ssh-agent",
					UsageText:    "`gopass-ssh-add --store=ssh-keys agent delete path/to/ssh/key`",
					Aliases:      []string{"remove", "del", "rm"},
					Hidden:       false,
					Action:       gc.SSHDelete,
					Before:       gc.Before,
					BashComplete: gc.PathAutocomplete,
				},
				{
					Name:        "list",
					Description: "Show keys list in ssh-agent",
					Usage:       "show keys list in ssh-agent",
					UsageText:   "`gopass-ssh-add --store=ssh-keys agent list`",
					Aliases:     []string{"ls"},
					Hidden:      false,
					Action:      gc.SSHList,
					Before:      gc.BeforeBase,
				},
				{
					Name:        "clear",
					Description: "Delete all keys from ssh agent",
					Usage:       "delete all keys from ssh agent",
					UsageText:   "`gopass-ssh-add --store=ssh-keys agent clear`",
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
			Description: "Manage secrets",
			Usage:       "manage ssh-key secrets in gopass",
			Hidden:      false,
			Subcommands: []*cli.Command{
				// delete ssh-key secret completely
				{
					Name:         "delete",
					Description:  "Delete secret from gopass storage",
					Usage:        "delete secret from gopass storage",
					UsageText:    "`gopass-ssh-add --store=ssh-keys secret delete path/to/ssh/key`",
					Hidden:       false,
					Action:       gc.Delete,
					Before:       gc.Before,
					Aliases:      []string{"remove", "del", "rm"},
					BashComplete: gc.PathAutocomplete,
				},
				// run ssh-keygen
				{
					Name:         "generate",
					Description:  "Generate ssh-key and save it to gopass storage",
					Usage:        "generate password, run ssh-keygen save it to gopass storage",
					UsageText:    "`gopass-ssh-add --store=ssh-keys secret generate path/to/ssh/key`",
					Hidden:       false,
					Action:       gc.SSHKeygen,
					Before:       gc.Before,
					Aliases:      []string{"keygen", "gen", "ssh-keygen"},
					BashComplete: gc.PathAutocomplete,
					Flags:        append(appSSHKeygenFlags, appPasswordFlags...),
				},
				// password section
				{
					Name:        "password",
					Description: "Manage ssh-key password",
					Usage:       "manage ssh-key password",
					Hidden:      false,
					Aliases:     []string{"pass", "passwd"},
					Subcommands: []*cli.Command{
						{
							Name:        "show",
							Description: "Show ssh-key password",
							Usage:       "show ssh-key password",
							UsageText: "`gopass-ssh-add --store=ssh-keys secret password show path/to/ssh/key/secret` # show ssh-key password" +
								"\n\n" +
								"`gopass-ssh-add --store=ssh-keys secret password show -c path/to/ssh/key/secret` # copy ssh-key password to clipboard",
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
							Description:  "Delete ssh-key password",
							Usage:        "delete ssh-key password",
							UsageText:    "`gopass-ssh-add --store=ssh-keys secret password delete path/to/ssh/key/secret`",
							Hidden:       false,
							Action:       gc.DeletePassword,
							Before:       gc.Before,
							Aliases:      []string{"remove", "del", "rm"},
							BashComplete: gc.PathAutocomplete,
						},
						{
							Name:         "generate",
							Description:  "Generate ssh-key password",
							Usage:        "generate ssh-key password",
							UsageText:    "`gopass-ssh-add --store=ssh-keys secret password generate -l=32 -s path/to/ssh/key/secret`",
							Hidden:       false,
							Action:       gc.GeneratePassword,
							Before:       gc.Before,
							Aliases:      []string{"gen", "random", "rand"},
							BashComplete: gc.PathAutocomplete,
							Flags:        append([]cli.Flag{}, appPasswordFlags...),
						},
						{
							Name:         "insert",
							Description:  "Insert ssh-key password from stdin",
							Usage:        "insert ssh-key password from stdin",
							UsageText:    "`echo \"some-password\" | gopass-ssh-add --store=ssh-keys secret password insert path/to/ssh/key/secret`",
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
					Description: "Manage ssh-key in secret",
					Usage:       "manage ssh-key in secret",
					Hidden:      false,
					Aliases:     []string{"ssh-key"},
					Subcommands: []*cli.Command{
						// delete ssh-key (private and puplic) from secret
						{
							Name:         "delete",
							Description:  "Delete ssh-key (private and public) from secret",
							Usage:        "delete ssh-key (private and public) from secret",
							UsageText:    "`gopass-ssh-add --store=ssh-keys secret key delete path/to/ssh/key/secret`",
							Hidden:       false,
							Action:       gc.DeleteSSHKey,
							Before:       gc.Before,
							Aliases:      []string{"remove", "del", "rm"},
							BashComplete: gc.PathAutocomplete,
						},
						{
							Name:        "private",
							Description: "Manage private ssh-key section",
							Usage:       "manage private ssh-key section",
							Hidden:      false,
							Aliases:     []string{},
							Subcommands: []*cli.Command{
								{
									Name:         "insert",
									Description:  "Insert private ssh-key from stdin",
									Usage:        "insert private ssh-key from stdin",
									UsageText:    "`cat ./private/ssh-key/path | gopass-ssh-add --store=ssh-keys secret key private insert path/to/ssh/key/secret`",
									Hidden:       false,
									Action:       gc.InsertSSHPrivateKey,
									Before:       gc.Before,
									Aliases:      []string{"import"},
									BashComplete: gc.PathAutocomplete,
								},
								{
									Name:         "show",
									Description:  "Show private ssh-key",
									Usage:        "show private ssh-key",
									UsageText:    "`gopass-ssh-add --store=ssh-keys secret key private show path/to/ssh/key/secret`",
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
									Description:  "Delete private ssh-key",
									Usage:        "delete private ssh-key",
									UsageText:    "`gopass-ssh-add --store=ssh-keys secret key private delete path/to/ssh/key/secret`",
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
							Description: "Manage public ssh-key section",
							Usage:       "manage public ssh-key section",
							Hidden:      false,
							Aliases:     []string{},
							Subcommands: []*cli.Command{
								{
									Name:         "insert",
									Description:  "Insert public ssh-key from stdin",
									Usage:        "insert public ssh-key from stdin",
									UsageText:    "`cat ./public/ssh-key/path | gopass-ssh-add --store=ssh-keys secret key public insert path/to/ssh/key/secret`",
									Hidden:       false,
									Action:       gc.InsertSSHPublicKey,
									Before:       gc.Before,
									Aliases:      []string{"import"},
									BashComplete: gc.PathAutocomplete,
								},
								{
									Name:         "show",
									Description:  "Show public ssh-key",
									Usage:        "show public ssh-key",
									UsageText:    "`gopass-ssh-add --store=ssh-keys secret key public show path/to/ssh/key/secret`",
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
									Description:  "Delete public ssh-key",
									Usage:        "delete public ssh-key",
									UsageText:    "`gopass-ssh-add --store=ssh-keys secret key public delete path/to/ssh/key/secret`",
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

		{
			Name:        "gen-readme",
			Description: "Generate markdown readme file",
			Hidden:      true,
			Action: func(c *cli.Context) error {
				doc, err := app.ToMarkdown()
				if err != nil {
					logger.Fatalf("Cannot generate readme: %s", err.Error())
				}

				filePath := c.Args().Get(0)
				if filePath == "" {
					filePath = "./README.md"
				}

				absFilePath, err := filepath.Abs(filePath)
				if err != nil {
					logger.Fatalf("Cannot get abs path of readme file: %s", err.Error())
				}

				err = os.WriteFile(absFilePath, []byte(doc), 0644)
				if err != nil {
					logger.Fatalf("Cannot write docs to readme file: %s", err.Error())
				}

				return nil
			},
		},
	}

	if err := app.RunContext(ctx, os.Args); err != nil {
		log.Fatal(err)
	}
}
