package gpgsmith

import (
	"context"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/urfave/cli/v3"

	"github.com/excavador/locksmith/pkg/audit"
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

func auditShow(_ context.Context, cmd *cli.Command) error {
	gnupghome := os.Getenv("GNUPGHOME")
	if gnupghome == "" {
		return fmt.Errorf("GNUPGHOME not set (run vault open first)")
	}

	entries, err := audit.Load(gnupghome)
	if err != nil {
		return err
	}

	if len(entries) == 0 {
		fmt.Println("No audit entries.")
		return nil
	}

	last := cmd.Int("last")
	if last > 0 && last < len(entries) {
		entries = entries[len(entries)-last:]
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "TIMESTAMP\tACTION\tDETAILS")
	for i := range entries {
		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\n",
			entries[i].Timestamp.Format("2006-01-02 15:04:05"),
			entries[i].Action,
			entries[i].Details,
		)
	}
	return w.Flush()
}
