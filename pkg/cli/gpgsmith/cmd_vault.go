package gpgsmith

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"connectrpc.com/connect"
	"github.com/urfave/cli/v3"

	v1 "github.com/excavador/locksmith/pkg/gen/gpgsmith/v1"
	"github.com/excavador/locksmith/pkg/wire"
)

func vaultCmd() *cli.Command {
	return &cli.Command{
		Name:  "vault",
		Usage: "manage encrypted vaults",
		Commands: []*cli.Command{
			{Name: "list", Usage: "list all configured vaults", Action: vaultList},
			{Name: "status", Usage: "show daemon-side vault state", Action: vaultStatus},
			{
				Name:      "create",
				Usage:     "create a new vault entry and initialize it",
				ArgsUsage: "<name>",
				Action:    vaultCreate,
			},
			{
				Name:      "open",
				Usage:     "open a vault by name and drop into a wrapped subshell",
				ArgsUsage: "<name>",
				Flags: []cli.Flag{
					&cli.BoolFlag{
						Name:  "no-shell",
						Usage: "print `export GPGSMITH_SESSION=<token>` to stdout instead of spawning a subshell",
					},
				},
				Action: vaultOpen,
			},
			{
				Name:      "seal",
				Usage:     "seal the current session (bound via GPGSMITH_SESSION)",
				ArgsUsage: "",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "message", Usage: "seal message", Value: ""},
				},
				Action: vaultSeal,
			},
			{
				Name:   "discard",
				Usage:  "discard the current session without sealing",
				Action: vaultDiscard,
			},
			{
				Name:      "snapshots",
				Usage:     "list canonical snapshots of a vault",
				ArgsUsage: "<name>",
				Action:    vaultSnapshots,
			},
			{
				Name:      "import",
				Usage:     "import an existing GNUPGHOME directory as a new vault snapshot",
				ArgsUsage: "<path>",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "name", Usage: "target vault name"},
				},
				Action: vaultImport,
			},
			{
				Name:      "export",
				Usage:     "decrypt the latest snapshot of a vault to a target directory",
				ArgsUsage: "<name> <target>",
				Action:    vaultExport,
			},
			{
				Name:      "trust",
				Usage:     "update the TOFU trust anchor for a vault",
				ArgsUsage: "<name> <fingerprint>",
				Action:    vaultTrust,
			},
		},
	}
}

func vaultList(ctx context.Context, _ *cli.Command) error {
	client, err := ensureClient(ctx)
	if err != nil {
		return fmt.Errorf("vault list: %w", err)
	}
	defer client.Close()

	resp, err := client.Vault.List(ctx, connect.NewRequest(&v1.ListRequest{}))
	if err != nil {
		return fmt.Errorf("vault list: %w", err)
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "NAME\tPATH\tDEFAULT\tTRUSTED_FP")
	for _, v := range resp.Msg.GetVaults() {
		marker := ""
		if v.GetName() == resp.Msg.GetDefaultVault() {
			marker = "*"
		}
		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", v.GetName(), v.GetPath(), dash(marker), dash(v.GetTrustedMasterFp()))
	}
	return w.Flush()
}

func vaultStatus(ctx context.Context, _ *cli.Command) error {
	client, err := ensureClient(ctx)
	if err != nil {
		return fmt.Errorf("vault status: %w", err)
	}
	defer client.Close()

	resp, err := client.Vault.Status(ctx, connect.NewRequest(&v1.StatusVaultRequest{}))
	if err != nil {
		return fmt.Errorf("vault status: %w", err)
	}

	open := resp.Msg.GetOpen()
	if len(open) == 0 {
		fmt.Println("No vaults open.")
	} else {
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		_, _ = fmt.Fprintln(w, "OPEN VAULT\tHOSTNAME\tSTARTED\tSTATUS")
		for _, s := range open {
			_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\n",
				s.GetVaultName(),
				dash(s.GetHostname()),
				s.GetStartedAt().AsTime().Format(time.RFC3339),
				dash(s.GetStatus()),
			)
		}
		_ = w.Flush()
	}

	rec := resp.Msg.GetRecoverable()
	if len(rec) == 0 {
		return nil
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "\nRECOVERABLE\tHOSTNAME\tLAST HEARTBEAT\tSTATUS\tDIVERGENT")
	for _, r := range rec {
		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%t\n",
			r.GetCanonicalBase(),
			dash(r.GetHostname()),
			r.GetLastHeartbeat().AsTime().Format(time.RFC3339),
			dash(r.GetStatus()),
			r.GetDivergent(),
		)
	}
	return w.Flush()
}

func vaultCreate(ctx context.Context, cmd *cli.Command) error {
	name := cmd.Args().First()
	if name == "" {
		return fmt.Errorf("vault create: missing <name>")
	}

	path, err := promptLine("Vault directory path: ")
	if err != nil {
		return err
	}
	if path == "" {
		return fmt.Errorf("vault create: path is required")
	}

	passphrase, err := readPassphraseWithConfirm()
	if err != nil {
		return err
	}

	client, err := ensureClient(ctx)
	if err != nil {
		return fmt.Errorf("vault create: %w", err)
	}
	defer client.Close()

	resp, err := client.Vault.Create(ctx, connect.NewRequest(&v1.CreateVaultRequest{
		Name:       name,
		Path:       path,
		Passphrase: passphrase,
	}))
	if err != nil {
		return fmt.Errorf("vault create: %w", err)
	}
	fmt.Fprintf(os.Stderr, "Created %s (initial snapshot: %s)\n", name, filepath.Base(resp.Msg.GetSnapshot().GetFilename()))

	// Bind the new session's token into this process's env so any
	// follow-up command issued by this same gpgsmith invocation
	// (typically none) inherits it via the client interceptor.
	if tok := resp.Msg.GetToken(); tok != "" {
		_ = os.Setenv(wire.SessionEnvVar, tok)
		_ = os.Setenv(wire.SessionVaultNameEnvVar, name)
	}
	return nil
}

func vaultOpen(ctx context.Context, cmd *cli.Command) error {
	name := cmd.Args().First()
	if name == "" {
		return fmt.Errorf("vault open: missing <name>")
	}

	passphrase, err := readPassphrase("Vault passphrase: ")
	if err != nil {
		return err
	}

	client, err := ensureClient(ctx)
	if err != nil {
		return fmt.Errorf("vault open: %w", err)
	}
	defer client.Close()

	resp, err := client.Vault.Open(ctx, connect.NewRequest(&v1.OpenRequest{
		VaultName:  name,
		Passphrase: passphrase,
		Source:     v1.LockSource_LOCK_SOURCE_CLI,
	}))
	if err != nil {
		return fmt.Errorf("vault open: %w", err)
	}

	token := resp.Msg.GetToken()

	if ra := resp.Msg.GetResumeAvailable(); ra != nil {
		fmt.Fprintf(os.Stderr, "A recoverable session exists for %q on %s (last heartbeat %s).\n",
			name, ra.GetHostname(), ra.GetLastHeartbeat().AsTime().Format(time.RFC3339))
		ans, perr := promptLine("Resume? [Y/n/cancel]: ")
		if perr != nil {
			return perr
		}
		ans = strings.ToLower(strings.TrimSpace(ans))
		var resumeResp *connect.Response[v1.ResumeResponse]
		switch ans {
		case "", "y", "yes":
			resumeResp, err = client.Vault.Resume(ctx, connect.NewRequest(&v1.ResumeRequest{
				VaultName:  name,
				Passphrase: passphrase,
				Source:     v1.LockSource_LOCK_SOURCE_CLI,
				Action:     v1.ResumeRequest_ACTION_RESUME,
			}))
		case "n", "no", "discard":
			resumeResp, err = client.Vault.Resume(ctx, connect.NewRequest(&v1.ResumeRequest{
				VaultName:  name,
				Passphrase: passphrase,
				Source:     v1.LockSource_LOCK_SOURCE_CLI,
				Action:     v1.ResumeRequest_ACTION_DISCARD,
			}))
		default:
			return fmt.Errorf("canceled")
		}
		if err != nil {
			return fmt.Errorf("vault open: %w", err)
		}
		token = resumeResp.Msg.GetToken()
	}

	if token == "" {
		return fmt.Errorf("vault open: daemon returned empty session token")
	}

	if cmd.Bool("no-shell") {
		// Scripted mode: print export statements for `eval $(...)`.
		fmt.Printf("export %s=%s;\n", wire.SessionEnvVar, shellEscapeSingleQuote(token))
		fmt.Printf("export %s=%s;\n", wire.SessionVaultNameEnvVar, shellEscapeSingleQuote(name))
		fmt.Fprintf(os.Stderr, "bound session token for %q\n", name)
		return nil
	}

	// Interactive mode: spawn a wrapped subshell and block on it.
	// When the subshell exits, the daemon's idle timer will take care
	// of sealing — we deliberately do NOT seal on exit here, because
	// users frequently open `gpgsmith vault open` in one pane and
	// continue working on the same session from others.
	return runWrappedSubshell(ctx, name, token)
}

func vaultSeal(ctx context.Context, cmd *cli.Command) error {
	client, err := ensureClient(ctx)
	if err != nil {
		return fmt.Errorf("vault seal: %w", err)
	}
	defer client.Close()

	if err := ensureSessionToken(ctx, client); err != nil {
		return fmt.Errorf("vault seal: %w", err)
	}

	message := cmd.String("message")
	if message == "" {
		message = fmt.Sprintf("session-%s", time.Now().UTC().Format("2006-01-02"))
	}

	resp, err := client.Vault.Seal(ctx, connect.NewRequest(&v1.SealRequest{
		Message: message,
	}))
	if err != nil {
		return fmt.Errorf("vault seal: %w", err)
	}
	fmt.Fprintf(os.Stderr, "sealed: %s\n", filepath.Base(resp.Msg.GetSnapshot().GetFilename()))
	return nil
}

func vaultDiscard(ctx context.Context, _ *cli.Command) error {
	client, err := ensureClient(ctx)
	if err != nil {
		return fmt.Errorf("vault discard: %w", err)
	}
	defer client.Close()

	if err := ensureSessionToken(ctx, client); err != nil {
		return fmt.Errorf("vault discard: %w", err)
	}

	if _, err := client.Vault.Discard(ctx, connect.NewRequest(&v1.DiscardRequest{})); err != nil {
		return fmt.Errorf("vault discard: %w", err)
	}
	fmt.Fprintln(os.Stderr, "discarded")
	return nil
}

func vaultSnapshots(ctx context.Context, cmd *cli.Command) error {
	name := cmd.Args().First()
	if name == "" {
		return fmt.Errorf("vault snapshots: missing <name>")
	}

	client, err := ensureClient(ctx)
	if err != nil {
		return fmt.Errorf("vault snapshots: %w", err)
	}
	defer client.Close()

	resp, err := client.Vault.Snapshots(ctx, connect.NewRequest(&v1.SnapshotsRequest{VaultName: name}))
	if err != nil {
		return fmt.Errorf("vault snapshots: %w", err)
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "TIMESTAMP\tFILENAME\tMESSAGE")
	for _, s := range resp.Msg.GetSnapshots() {
		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\n",
			s.GetTimestamp().AsTime().Format("2006-01-02 15:04:05"),
			filepath.Base(s.GetFilename()),
			dash(s.GetMessage()),
		)
	}
	return w.Flush()
}

func vaultImport(ctx context.Context, cmd *cli.Command) error {
	source := cmd.Args().First()
	if source == "" {
		return fmt.Errorf("vault import: missing <path>")
	}

	target := cmd.String("name")
	passphrase, err := readPassphrase("Vault passphrase: ")
	if err != nil {
		return err
	}

	client, err := ensureClient(ctx)
	if err != nil {
		return fmt.Errorf("vault import: %w", err)
	}
	defer client.Close()

	resp, err := client.Vault.Import(ctx, connect.NewRequest(&v1.ImportRequest{
		SourcePath:      source,
		Passphrase:      passphrase,
		TargetVaultName: target,
	}))
	if err != nil {
		return fmt.Errorf("vault import: %w", err)
	}
	fmt.Fprintf(os.Stderr, "imported: %s\n", filepath.Base(resp.Msg.GetSnapshot().GetFilename()))
	return nil
}

func vaultExport(ctx context.Context, cmd *cli.Command) error {
	args := cmd.Args()
	if args.Len() < 2 { //nolint:mnd // name + target
		return fmt.Errorf("vault export: usage: export <name> <target>")
	}
	name := args.Get(0)
	target := args.Get(1)

	passphrase, err := readPassphrase("Vault passphrase: ")
	if err != nil {
		return err
	}

	client, err := ensureClient(ctx)
	if err != nil {
		return fmt.Errorf("vault export: %w", err)
	}
	defer client.Close()

	resp, err := client.Vault.Export(ctx, connect.NewRequest(&v1.ExportRequest{
		VaultName:  name,
		Passphrase: passphrase,
		TargetDir:  target,
	}))
	if err != nil {
		return fmt.Errorf("vault export: %w", err)
	}
	fmt.Fprintf(os.Stderr, "exported %s to %s (from snapshot %s)\n", name, resp.Msg.GetTargetDir(), resp.Msg.GetSnapshot())
	return nil
}

func vaultTrust(ctx context.Context, cmd *cli.Command) error {
	args := cmd.Args()
	if args.Len() < 2 { //nolint:mnd // name + fingerprint
		return fmt.Errorf("vault trust: usage: trust <name> <fingerprint>")
	}
	name := args.Get(0)
	fp := args.Get(1)

	client, err := ensureClient(ctx)
	if err != nil {
		return fmt.Errorf("vault trust: %w", err)
	}
	defer client.Close()

	_, err = client.Vault.Trust(ctx, connect.NewRequest(&v1.TrustRequest{
		VaultName:   name,
		Fingerprint: fp,
	}))
	if err != nil {
		return fmt.Errorf("vault trust: %w", err)
	}
	fmt.Fprintf(os.Stderr, "trust anchor updated for %s\n", name)
	return nil
}
