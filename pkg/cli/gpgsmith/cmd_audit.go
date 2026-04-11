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

func auditCmd() *cli.Command {
	return &cli.Command{
		Name:  "audit",
		Usage: "operation audit log",
		Commands: []*cli.Command{
			{
				Name:  "show",
				Usage: "display audit entries",
				Flags: []cli.Flag{
					&cli.IntFlag{Name: "last", Usage: "show only the last N entries"},
				},
				Action: auditShow,
			},
		},
	}
}

func auditShow(ctx context.Context, cmd *cli.Command) error {
	client, err := ensureClient(ctx)
	if err != nil {
		return fmt.Errorf("audit show: %w", err)
	}
	defer client.Close()

	vaultName, err := resolveVaultName(ctx, client, cmd)
	if err != nil {
		return fmt.Errorf("audit show: %w", err)
	}

	resp, err := client.Audit.Show(ctx, connect.NewRequest(&v1.ShowRequest{
		VaultName: vaultName,
		Last:      int32(cmd.Int("last")), //nolint:gosec // user-supplied, bounded by int32 proto field
	}))
	if err != nil {
		return fmt.Errorf("audit show: %w", err)
	}

	entries := resp.Msg.GetEntries()
	if len(entries) == 0 {
		fmt.Println("No audit entries.")
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "TIMESTAMP\tACTION\tDETAILS")
	for _, e := range entries {
		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\n",
			e.GetTimestamp().AsTime().Format("2006-01-02 15:04:05"),
			e.GetAction(),
			e.GetDetails(),
		)
	}
	return w.Flush()
}
