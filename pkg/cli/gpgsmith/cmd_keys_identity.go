package gpgsmith

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"text/tabwriter"

	"github.com/urfave/cli/v3"

	"github.com/excavador/locksmith/pkg/audit"
	"github.com/excavador/locksmith/pkg/gpg"
)

// identityStatus returns a human-readable status for an identity based on
// the gpg validity field.
func identityStatus(validity string) string {
	switch validity {
	case "r":
		return statusRevoked
	case "e":
		return statusExpired
	case "u":
		return "ultimate"
	case "f":
		return "full"
	case "m":
		return "marginal"
	case "n":
		return "never"
	case "q":
		return "unknown"
	default:
		if validity == "" {
			return statusActive
		}
		return validity
	}
}

// resolveIdentity resolves a CLI argument to an identity (uid) string. If the
// argument parses as a positive integer, it is treated as a 1-based index
// into the master key's current identity list. Otherwise it is returned
// as-is and must be an exact match for an existing identity.
func resolveIdentity(ctx context.Context, client *gpg.Client, masterFP, arg string) (string, error) {
	if n, err := strconv.Atoi(arg); err == nil {
		uids, listErr := client.ListUIDs(ctx, masterFP)
		if listErr != nil {
			return "", listErr
		}
		if n < 1 || n > len(uids) {
			return "", fmt.Errorf("identity index %d out of range (have %d identities)", n, len(uids))
		}
		return uids[n-1].UID, nil
	}
	return arg, nil
}

// republishKey publishes the master key to all enabled servers.
// Failures are logged as warnings but do not abort the caller.
func republishKey(ctx context.Context, client *gpg.Client, masterFP string) {
	targets, err := enabledPublishTargets(client)
	if err != nil || len(targets) == 0 {
		return
	}

	logger := loggerFrom(ctx)
	results := client.Publish(ctx, masterFP, targets)
	for _, r := range results {
		if r.Err != nil {
			logger.WarnContext(ctx, "publish failed",
				slog.String("target", r.Target.Type),
				slog.String("error", r.Err.Error()),
			)
		}
	}
}

func keysIdentityList(ctx context.Context, _ *cli.Command) error {
	client, err := newGPGClient(ctx)
	if err != nil {
		return err
	}

	cfg, err := loadGPGConfig(ctx, client)
	if err != nil {
		return err
	}

	uids, err := client.ListUIDs(ctx, cfg.MasterFP)
	if err != nil {
		return err
	}

	if len(uids) == 0 {
		fmt.Println("No identities on the master key.")
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "INDEX\tSTATUS\tCREATED\tREVOKED\tIDENTITY")
	for i := range uids {
		created := "-"
		if !uids[i].Created.IsZero() {
			created = uids[i].Created.Format("2006-01-02")
		}
		revoked := "-"
		if !uids[i].Revoked.IsZero() {
			revoked = uids[i].Revoked.Format("2006-01-02")
		}
		_, _ = fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\n",
			uids[i].Index,
			identityStatus(uids[i].Validity),
			created,
			revoked,
			uids[i].UID,
		)
	}
	return w.Flush()
}

func keysIdentityAdd(ctx context.Context, cmd *cli.Command) error {
	uid := cmd.Args().First()
	if uid == "" {
		return fmt.Errorf(`identity add requires an identity argument (e.g. "Name <email@example.com>")`)
	}

	client, err := newGPGClient(ctx)
	if err != nil {
		return err
	}

	cfg, err := loadGPGConfig(ctx, client)
	if err != nil {
		return err
	}

	if err := client.AddUID(ctx, cfg.MasterFP, uid); err != nil {
		return err
	}

	republishKey(ctx, client, cfg.MasterFP)

	return audit.Append(client.HomeDir(), audit.Entry{
		Action:  "add-identity",
		Details: fmt.Sprintf("added identity %q", uid),
		Metadata: map[string]string{
			"identity": uid,
		},
	})
}

func keysIdentityRevoke(ctx context.Context, cmd *cli.Command) error {
	arg := cmd.Args().First()
	if arg == "" {
		return fmt.Errorf("identity revoke requires an identity argument or 1-based index")
	}

	client, err := newGPGClient(ctx)
	if err != nil {
		return err
	}

	cfg, err := loadGPGConfig(ctx, client)
	if err != nil {
		return err
	}

	uid, err := resolveIdentity(ctx, client, cfg.MasterFP, arg)
	if err != nil {
		return err
	}

	if err := client.RevokeUID(ctx, cfg.MasterFP, uid); err != nil {
		return err
	}

	republishKey(ctx, client, cfg.MasterFP)

	return audit.Append(client.HomeDir(), audit.Entry{
		Action:  "revoke-identity",
		Details: fmt.Sprintf("revoked identity %q", uid),
		Metadata: map[string]string{
			"identity": uid,
		},
	})
}

func keysIdentityPrimary(ctx context.Context, cmd *cli.Command) error {
	arg := cmd.Args().First()
	if arg == "" {
		return fmt.Errorf("identity primary requires an identity argument or 1-based index")
	}

	client, err := newGPGClient(ctx)
	if err != nil {
		return err
	}

	cfg, err := loadGPGConfig(ctx, client)
	if err != nil {
		return err
	}

	uid, err := resolveIdentity(ctx, client, cfg.MasterFP, arg)
	if err != nil {
		return err
	}

	if err := client.SetPrimaryUID(ctx, cfg.MasterFP, uid); err != nil {
		return err
	}

	republishKey(ctx, client, cfg.MasterFP)

	return audit.Append(client.HomeDir(), audit.Entry{
		Action:  "set-primary-identity",
		Details: fmt.Sprintf("set primary identity %q", uid),
		Metadata: map[string]string{
			"identity": uid,
		},
	})
}
