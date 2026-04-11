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

func cardCmd() *cli.Command {
	return &cli.Command{
		Name:  "card",
		Usage: "high-level YubiKey workflows",
		Commands: []*cli.Command{
			{
				Name:      "provision",
				Usage:     "generate subkeys + to-card + publish + ssh-pubkey",
				ArgsUsage: "<label>",
				Flags: []cli.Flag{
					&cli.BoolFlag{Name: "same-keys", Usage: "copy same subkeys to card"},
					&cli.BoolFlag{Name: "unique-keys", Usage: "generate fresh subkeys for this card"},
					&cli.StringFlag{Name: "description", Usage: "optional card description"},
				},
				Action: cardProvision,
			},
			{
				Name:      "rotate",
				Usage:     "revoke old + generate new + to-card + publish + ssh",
				ArgsUsage: "<label>",
				Action:    cardRotate,
			},
			{
				Name:      "revoke",
				Usage:     "revoke all subkeys for a card",
				ArgsUsage: "<label>",
				Action:    cardRevoke,
			},
			{Name: "inventory", Usage: "list all known YubiKeys", Action: cardInventory},
			{Name: "discover", Usage: "detect connected YubiKey and add to inventory", Action: cardDiscover},
		},
	}
}

func cardProvision(ctx context.Context, cmd *cli.Command) error {
	label := cmd.Args().First()
	if label == "" {
		return fmt.Errorf("card provision: missing <label>")
	}

	client, err := ensureClient(ctx)
	if err != nil {
		return fmt.Errorf("card provision: %w", err)
	}
	defer client.Close()

	if err := ensureSessionToken(ctx, client); err != nil {
		return fmt.Errorf("card provision: %w", err)
	}

	resp, err := client.Card.Provision(ctx, connect.NewRequest(&v1.ProvisionRequest{
		Label:       label,
		Description: cmd.String("description"),
		SameKeys:    cmd.Bool("same-keys"),
		UniqueKeys:  cmd.Bool("unique-keys"),
	}))
	if err != nil {
		return fmt.Errorf("card provision: %w", err)
	}
	fmt.Fprintf(os.Stderr, "provisioned %s (serial %s)\n", label, resp.Msg.GetCard().GetSerial())
	if p := resp.Msg.GetSshPubkeyPath(); p != "" {
		fmt.Fprintf(os.Stderr, "ssh pubkey: %s\n", p)
	}
	return nil
}

func cardRotate(ctx context.Context, cmd *cli.Command) error {
	label := cmd.Args().First()
	if label == "" {
		return fmt.Errorf("card rotate: missing <label>")
	}

	client, err := ensureClient(ctx)
	if err != nil {
		return fmt.Errorf("card rotate: %w", err)
	}
	defer client.Close()

	if err := ensureSessionToken(ctx, client); err != nil {
		return fmt.Errorf("card rotate: %w", err)
	}

	resp, err := client.Card.Rotate(ctx, connect.NewRequest(&v1.RotateRequest{
		Label: label,
	}))
	if err != nil {
		return fmt.Errorf("card rotate: %w", err)
	}
	fmt.Fprintf(os.Stderr, "rotated %s (serial %s)\n", label, resp.Msg.GetCard().GetSerial())
	return nil
}

func cardRevoke(ctx context.Context, cmd *cli.Command) error {
	label := cmd.Args().First()
	if label == "" {
		return fmt.Errorf("card revoke: missing <label>")
	}

	client, err := ensureClient(ctx)
	if err != nil {
		return fmt.Errorf("card revoke: %w", err)
	}
	defer client.Close()

	if err := ensureSessionToken(ctx, client); err != nil {
		return fmt.Errorf("card revoke: %w", err)
	}

	_, err = client.Card.Revoke(ctx, connect.NewRequest(&v1.RevokeCardRequest{
		Label: label,
	}))
	if err != nil {
		return fmt.Errorf("card revoke: %w", err)
	}
	fmt.Fprintf(os.Stderr, "revoked %s\n", label)
	return nil
}

func cardInventory(ctx context.Context, _ *cli.Command) error {
	client, err := ensureClient(ctx)
	if err != nil {
		return fmt.Errorf("card inventory: %w", err)
	}
	defer client.Close()

	if err := ensureSessionToken(ctx, client); err != nil {
		return fmt.Errorf("card inventory: %w", err)
	}

	resp, err := client.Card.Inventory(ctx, connect.NewRequest(&v1.InventoryRequest{}))
	if err != nil {
		return fmt.Errorf("card inventory: %w", err)
	}

	cards := resp.Msg.GetCards()
	if len(cards) == 0 {
		fmt.Println("No cards in inventory.")
		return nil
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "LABEL\tSERIAL\tMODEL\tSTATUS\tPROVISIONING\tDESCRIPTION")
	for _, c := range cards {
		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
			dash(c.GetLabel()),
			dash(c.GetSerial()),
			dash(c.GetModel()),
			dash(c.GetStatus()),
			dash(c.GetProvisioning()),
			dash(c.GetDescription()),
		)
	}
	return w.Flush()
}

func cardDiscover(ctx context.Context, cmd *cli.Command) error {
	client, err := ensureClient(ctx)
	if err != nil {
		return fmt.Errorf("card discover: %w", err)
	}
	defer client.Close()

	if err := ensureSessionToken(ctx, client); err != nil {
		return fmt.Errorf("card discover: %w", err)
	}

	resp, err := client.Card.Discover(ctx, connect.NewRequest(&v1.DiscoverRequest{
		Label:       cmd.Args().Get(0),
		Description: cmd.String("description"),
	}))
	if err != nil {
		return fmt.Errorf("card discover: %w", err)
	}
	fmt.Fprintf(os.Stderr, "discovered %s (serial %s, already_known=%t)\n",
		resp.Msg.GetCard().GetLabel(),
		resp.Msg.GetCard().GetSerial(),
		resp.Msg.GetAlreadyInInventory(),
	)
	return nil
}
