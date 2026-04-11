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

func serverList(ctx context.Context, _ *cli.Command) error {
	client, err := ensureClient(ctx)
	if err != nil {
		return fmt.Errorf("server list: %w", err)
	}
	defer client.Close()

	if err := ensureSessionToken(ctx, client); err != nil {
		return fmt.Errorf("server list: %w", err)
	}

	resp, err := client.Server.List(ctx, connect.NewRequest(&v1.ListServersRequest{}))
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
	client, err := ensureClient(ctx)
	if err != nil {
		return fmt.Errorf("server add: %w", err)
	}
	defer client.Close()
	if err := ensureSessionToken(ctx, client); err != nil {
		return fmt.Errorf("server add: %w", err)
	}
	if _, err := client.Server.Add(ctx, connect.NewRequest(&v1.AddServerRequest{
		Alias: args.Get(0),
		Url:   args.Get(1),
	})); err != nil {
		return fmt.Errorf("server add: %w", err)
	}
	return nil
}

func serverRemove(ctx context.Context, cmd *cli.Command) error {
	alias := cmd.Args().First()
	if alias == "" {
		return fmt.Errorf("server remove: missing <alias>")
	}
	client, err := ensureClient(ctx)
	if err != nil {
		return fmt.Errorf("server remove: %w", err)
	}
	defer client.Close()
	if err := ensureSessionToken(ctx, client); err != nil {
		return fmt.Errorf("server remove: %w", err)
	}
	if _, err := client.Server.Remove(ctx, connect.NewRequest(&v1.RemoveServerRequest{
		Alias: alias,
	})); err != nil {
		return fmt.Errorf("server remove: %w", err)
	}
	return nil
}

func serverEnable(ctx context.Context, cmd *cli.Command) error {
	alias := cmd.Args().First()
	if alias == "" {
		return fmt.Errorf("server enable: missing <alias>")
	}
	client, err := ensureClient(ctx)
	if err != nil {
		return fmt.Errorf("server enable: %w", err)
	}
	defer client.Close()
	if err := ensureSessionToken(ctx, client); err != nil {
		return fmt.Errorf("server enable: %w", err)
	}
	if _, err := client.Server.Enable(ctx, connect.NewRequest(&v1.EnableServerRequest{
		Alias: alias,
	})); err != nil {
		return fmt.Errorf("server enable: %w", err)
	}
	return nil
}

func serverDisable(ctx context.Context, cmd *cli.Command) error {
	alias := cmd.Args().First()
	if alias == "" {
		return fmt.Errorf("server disable: missing <alias>")
	}
	client, err := ensureClient(ctx)
	if err != nil {
		return fmt.Errorf("server disable: %w", err)
	}
	defer client.Close()
	if err := ensureSessionToken(ctx, client); err != nil {
		return fmt.Errorf("server disable: %w", err)
	}
	if _, err := client.Server.Disable(ctx, connect.NewRequest(&v1.DisableServerRequest{
		Alias: alias,
	})); err != nil {
		return fmt.Errorf("server disable: %w", err)
	}
	return nil
}

func serverPublish(ctx context.Context, cmd *cli.Command) error {
	client, err := ensureClient(ctx)
	if err != nil {
		return fmt.Errorf("server publish: %w", err)
	}
	defer client.Close()

	if err := ensureSessionToken(ctx, client); err != nil {
		return fmt.Errorf("server publish: %w", err)
	}

	resp, err := client.Server.Publish(ctx, connect.NewRequest(&v1.PublishRequest{
		Aliases: cmd.Args().Slice(),
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

func serverLookup(ctx context.Context, _ *cli.Command) error {
	client, err := ensureClient(ctx)
	if err != nil {
		return fmt.Errorf("server lookup: %w", err)
	}
	defer client.Close()

	if err := ensureSessionToken(ctx, client); err != nil {
		return fmt.Errorf("server lookup: %w", err)
	}

	resp, err := client.Server.Lookup(ctx, connect.NewRequest(&v1.LookupRequest{}))
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
