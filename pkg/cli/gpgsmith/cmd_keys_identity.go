package gpgsmith

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"text/tabwriter"

	"connectrpc.com/connect"
	"github.com/urfave/cli/v3"

	v1 "github.com/excavador/locksmith/pkg/gen/gpgsmith/v1"
	"github.com/excavador/locksmith/pkg/wire"
)

func keysIdentityList(ctx context.Context, cmd *cli.Command) error {
	client, err := ensureClient(ctx)
	if err != nil {
		return fmt.Errorf("identity list: %w", err)
	}
	defer client.Close()

	vaultName, err := resolveVaultName(ctx, client, cmd)
	if err != nil {
		return fmt.Errorf("identity list: %w", err)
	}

	resp, err := client.Identity.List(ctx, connect.NewRequest(&v1.ListIdentitiesRequest{VaultName: vaultName}))
	if err != nil {
		return fmt.Errorf("identity list: %w", err)
	}

	ids := resp.Msg.GetIdentities()
	if len(ids) == 0 {
		fmt.Println("No identities on the master key.")
		return nil
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "INDEX\tSTATUS\tCREATED\tREVOKED\tIDENTITY")
	for _, id := range ids {
		created := "-"
		if t := id.GetCreated(); t != nil && !t.AsTime().IsZero() {
			created = t.AsTime().Format("2006-01-02")
		}
		revoked := "-"
		if t := id.GetRevoked(); t != nil && !t.AsTime().IsZero() {
			revoked = t.AsTime().Format("2006-01-02")
		}
		_, _ = fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\n",
			id.GetIndex(),
			dash(id.GetStatus()),
			created,
			revoked,
			id.GetUid(),
		)
	}
	return w.Flush()
}

func keysIdentityAdd(ctx context.Context, cmd *cli.Command) error {
	uid := cmd.Args().First()
	if uid == "" {
		return fmt.Errorf(`identity add requires an identity argument (e.g. "Name <email@example.com>")`)
	}

	client, err := ensureClient(ctx)
	if err != nil {
		return fmt.Errorf("identity add: %w", err)
	}
	defer client.Close()

	vaultName, err := resolveVaultName(ctx, client, cmd)
	if err != nil {
		return fmt.Errorf("identity add: %w", err)
	}

	_, err = client.Identity.Add(ctx, connect.NewRequest(&v1.AddIdentityRequest{
		VaultName: vaultName,
		Uid:       uid,
	}))
	if err != nil {
		return fmt.Errorf("identity add: %w", err)
	}
	fmt.Fprintf(os.Stderr, "added %q\n", uid)
	return nil
}

func keysIdentityRevoke(ctx context.Context, cmd *cli.Command) error {
	return identityMutate(ctx, cmd, "revoke", func(c *wire.Client, vault, uid string) error {
		_, err := c.Identity.Revoke(ctx, connect.NewRequest(&v1.RevokeIdentityRequest{
			VaultName: vault,
			Uid:       uid,
		}))
		return err
	})
}

func keysIdentityPrimary(ctx context.Context, cmd *cli.Command) error {
	return identityMutate(ctx, cmd, "primary", func(c *wire.Client, vault, uid string) error {
		_, err := c.Identity.Primary(ctx, connect.NewRequest(&v1.PrimaryIdentityRequest{
			VaultName: vault,
			Uid:       uid,
		}))
		return err
	})
}

// identityMutate wraps the shared path for identity revoke/primary: resolve
// the target identity (by exact match or by 1-based index) and invoke the
// supplied RPC call.
func identityMutate(ctx context.Context, cmd *cli.Command, label string, call func(*wire.Client, string, string) error) error {
	arg := cmd.Args().First()
	if arg == "" {
		return fmt.Errorf("identity %s: missing identity argument", label)
	}

	client, err := ensureClient(ctx)
	if err != nil {
		return fmt.Errorf("identity %s: %w", label, err)
	}
	defer client.Close()

	vaultName, err := resolveVaultName(ctx, client, cmd)
	if err != nil {
		return fmt.Errorf("identity %s: %w", label, err)
	}

	uid := arg
	if n, parseErr := strconv.Atoi(arg); parseErr == nil {
		resp, listErr := client.Identity.List(ctx, connect.NewRequest(&v1.ListIdentitiesRequest{VaultName: vaultName}))
		if listErr != nil {
			return fmt.Errorf("identity %s: %w", label, listErr)
		}
		ids := resp.Msg.GetIdentities()
		if n < 1 || n > len(ids) {
			return fmt.Errorf("identity %s: index %d out of range (have %d)", label, n, len(ids))
		}
		uid = ids[n-1].GetUid()
	}

	if err := call(client, vaultName, uid); err != nil {
		return fmt.Errorf("identity %s: %w", label, err)
	}
	fmt.Fprintf(os.Stderr, "%s: %s\n", label, uid)
	return nil
}
