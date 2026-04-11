package gpgsmith

import (
	"context"
	"fmt"
	"os"
	"text/tabwriter"

	"connectrpc.com/connect"
	"github.com/urfave/cli/v3"

	v1 "github.com/excavador/locksmith/pkg/gen/gpgsmith/v1"
)

func serverCmd() *cli.Command {
	return &cli.Command{
		Name:  "server",
		Usage: "manage publish targets (keyservers and GitHub)",
		Commands: []*cli.Command{
			{Name: "list", Usage: "list all publish targets", Action: serverList},
			{
				Name:      "add",
				Usage:     "add a custom keyserver",
				ArgsUsage: "<alias> <url>",
				Action:    serverAdd,
			},
			{
				Name:      "remove",
				Usage:     "remove a server from the registry",
				ArgsUsage: "<alias>",
				Action:    serverRemove,
			},
			{
				Name:      "enable",
				Usage:     "enable a server for publishing",
				ArgsUsage: "<alias>",
				Action:    serverEnable,
			},
			{
				Name:      "disable",
				Usage:     "disable a server for publishing",
				ArgsUsage: "<alias>",
				Action:    serverDisable,
			},
			{
				Name:      "publish",
				Usage:     "publish public key to enabled servers",
				ArgsUsage: "[alias...]",
				Action:    serverPublish,
			},
			{Name: "lookup", Usage: "check which servers have your public key", Action: serverLookup},
		},
	}
}

func serverList(ctx context.Context, cmd *cli.Command) error {
	client, err := ensureClient(ctx)
	if err != nil {
		return fmt.Errorf("server list: %w", err)
	}
	defer client.Close()

	vaultName, err := resolveVaultName(ctx, client, cmd)
	if err != nil {
		return fmt.Errorf("server list: %w", err)
	}

	resp, err := client.Server.List(ctx, connect.NewRequest(&v1.ListServersRequest{VaultName: vaultName}))
	if err != nil {
		return fmt.Errorf("server list: %w", err)
	}

	if len(resp.Msg.GetServers()) == 0 {
		fmt.Println("No servers configured.")
		return nil
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "ALIAS\tTYPE\tURL\tENABLED")
	for _, s := range resp.Msg.GetServers() {
		enabled := "no"
		if s.GetEnabled() {
			enabled = "yes"
		}
		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", s.GetAlias(), s.GetType(), dash(s.GetUrl()), enabled)
	}
	return w.Flush()
}

func serverAdd(ctx context.Context, cmd *cli.Command) error {
	args := cmd.Args()
	if args.Len() < 2 { //nolint:mnd // alias + url
		return fmt.Errorf("server add: usage: add <alias> <url>")
	}
	return simpleServerCall(ctx, cmd, "add", func(v string) error {
		client, err := ensureClient(ctx)
		if err != nil {
			return err
		}
		defer client.Close()
		_, err = client.Server.Add(ctx, connect.NewRequest(&v1.AddServerRequest{
			VaultName: v,
			Alias:     args.Get(0),
			Url:       args.Get(1),
		}))
		return err
	})
}

func serverRemove(ctx context.Context, cmd *cli.Command) error {
	alias := cmd.Args().First()
	if alias == "" {
		return fmt.Errorf("server remove: missing <alias>")
	}
	return simpleServerCall(ctx, cmd, "remove", func(v string) error {
		client, err := ensureClient(ctx)
		if err != nil {
			return err
		}
		defer client.Close()
		_, err = client.Server.Remove(ctx, connect.NewRequest(&v1.RemoveServerRequest{
			VaultName: v,
			Alias:     alias,
		}))
		return err
	})
}

func serverEnable(ctx context.Context, cmd *cli.Command) error {
	alias := cmd.Args().First()
	if alias == "" {
		return fmt.Errorf("server enable: missing <alias>")
	}
	return simpleServerCall(ctx, cmd, "enable", func(v string) error {
		client, err := ensureClient(ctx)
		if err != nil {
			return err
		}
		defer client.Close()
		_, err = client.Server.Enable(ctx, connect.NewRequest(&v1.EnableServerRequest{
			VaultName: v,
			Alias:     alias,
		}))
		return err
	})
}

func serverDisable(ctx context.Context, cmd *cli.Command) error {
	alias := cmd.Args().First()
	if alias == "" {
		return fmt.Errorf("server disable: missing <alias>")
	}
	return simpleServerCall(ctx, cmd, "disable", func(v string) error {
		client, err := ensureClient(ctx)
		if err != nil {
			return err
		}
		defer client.Close()
		_, err = client.Server.Disable(ctx, connect.NewRequest(&v1.DisableServerRequest{
			VaultName: v,
			Alias:     alias,
		}))
		return err
	})
}

func serverPublish(ctx context.Context, cmd *cli.Command) error {
	client, err := ensureClient(ctx)
	if err != nil {
		return fmt.Errorf("server publish: %w", err)
	}
	defer client.Close()

	vaultName, err := resolveVaultName(ctx, client, cmd)
	if err != nil {
		return fmt.Errorf("server publish: %w", err)
	}

	resp, err := client.Server.Publish(ctx, connect.NewRequest(&v1.PublishRequest{
		VaultName: vaultName,
		Aliases:   cmd.Args().Slice(),
	}))
	if err != nil {
		return fmt.Errorf("server publish: %w", err)
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "ALIAS\tRESULT\tERROR")
	for _, r := range resp.Msg.GetResults() {
		result := "ok"
		if !r.GetSuccess() {
			result = "failed"
		}
		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\n", r.GetAlias(), result, dash(r.GetError()))
	}
	return w.Flush()
}

func serverLookup(ctx context.Context, cmd *cli.Command) error {
	client, err := ensureClient(ctx)
	if err != nil {
		return fmt.Errorf("server lookup: %w", err)
	}
	defer client.Close()

	vaultName, err := resolveVaultName(ctx, client, cmd)
	if err != nil {
		return fmt.Errorf("server lookup: %w", err)
	}

	resp, err := client.Server.Lookup(ctx, connect.NewRequest(&v1.LookupRequest{VaultName: vaultName}))
	if err != nil {
		return fmt.Errorf("server lookup: %w", err)
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "URL\tSTATUS")
	for _, r := range resp.Msg.GetResults() {
		_, _ = fmt.Fprintf(w, "%s\t%s\n", r.GetUrl(), dash(r.GetStatus()))
	}
	return w.Flush()
}

// simpleServerCall is a tiny shared helper that resolves the vault name
// and calls the supplied fn, wrapping errors with the operation label.
func simpleServerCall(ctx context.Context, cmd *cli.Command, label string, fn func(vault string) error) error {
	client, err := ensureClient(ctx)
	if err != nil {
		return fmt.Errorf("server %s: %w", label, err)
	}
	defer client.Close()

	vaultName, err := resolveVaultName(ctx, client, cmd)
	if err != nil {
		return fmt.Errorf("server %s: %w", label, err)
	}
	if err := fn(vaultName); err != nil {
		return fmt.Errorf("server %s: %w", label, err)
	}
	return nil
}
