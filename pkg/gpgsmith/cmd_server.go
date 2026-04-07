package gpgsmith

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"text/tabwriter"

	"github.com/urfave/cli/v3"

	"github.com/excavador/locksmith/pkg/audit"
	"github.com/excavador/locksmith/pkg/gpg"
)

func serverCmd() *cli.Command {
	return &cli.Command{
		Name:  "server",
		Usage: "manage publish targets (keyservers and GitHub)",
		Commands: []*cli.Command{
			{
				Name:      "publish",
				Usage:     "publish public key to enabled servers",
				ArgsUsage: "[alias...]",
				Action:    serverPublish,
			},
			{
				Name:   "lookup",
				Usage:  "check which servers have your public key",
				Action: serverLookup,
			},
			{
				Name:   "list",
				Usage:  "list all publish targets",
				Action: serverList,
			},
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
		},
	}
}

func serverList(ctx context.Context, _ *cli.Command) error {
	client, err := newGPGClient(ctx)
	if err != nil {
		return err
	}

	reg, err := client.LoadServerRegistry()
	if err != nil {
		return err
	}

	if len(reg.Servers) == 0 {
		fmt.Println("No servers configured.")
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "ALIAS\tTYPE\tURL\tENABLED")
	for i := range reg.Servers {
		s := &reg.Servers[i]
		url := s.URL
		if url == "" {
			url = "-"
		}
		enabled := "no"
		if s.Enabled {
			enabled = "yes"
		}
		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", s.Alias, s.Type, url, enabled)
	}
	return w.Flush()
}

func serverAdd(ctx context.Context, cmd *cli.Command) error {
	args := cmd.Args()
	if args.Len() < 2 { //nolint:mnd // alias + url pair
		return fmt.Errorf("usage: server add <alias> <url>")
	}

	alias := args.Get(0)
	url := args.Get(1)

	if err := gpg.ValidateServerAlias(alias); err != nil {
		return err
	}

	// Ensure URL has a scheme.
	if !strings.HasPrefix(url, "hkps://") && !strings.HasPrefix(url, "hkp://") {
		url = "hkps://" + url
	}

	client, err := newGPGClient(ctx)
	if err != nil {
		return err
	}

	reg, err := client.LoadServerRegistry()
	if err != nil {
		return err
	}

	if reg.FindByAlias(alias) != nil {
		return fmt.Errorf("server %q already exists", alias)
	}

	reg.Servers = append(reg.Servers, gpg.ServerEntry{
		Alias:   alias,
		Type:    gpg.TargetTypeKeyserver,
		URL:     url,
		Enabled: true,
	})

	if err := client.SaveServerRegistry(reg); err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "Added %q (%s)\n", alias, url)
	return nil
}

func serverRemove(ctx context.Context, cmd *cli.Command) error {
	alias := cmd.Args().First()
	if alias == "" {
		return fmt.Errorf("usage: server remove <alias>")
	}

	client, err := newGPGClient(ctx)
	if err != nil {
		return err
	}

	reg, err := client.LoadServerRegistry()
	if err != nil {
		return err
	}

	found := false
	var remaining []gpg.ServerEntry
	for i := range reg.Servers {
		if reg.Servers[i].Alias == alias {
			found = true
			continue
		}
		remaining = append(remaining, reg.Servers[i])
	}

	if !found {
		return fmt.Errorf("server %q not found", alias)
	}

	reg.Servers = remaining
	if err := client.SaveServerRegistry(reg); err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "Removed %q\n", alias)
	return nil
}

func serverEnable(ctx context.Context, cmd *cli.Command) error {
	alias := cmd.Args().First()
	if alias == "" {
		return fmt.Errorf("usage: server enable <alias>")
	}

	client, err := newGPGClient(ctx)
	if err != nil {
		return err
	}

	reg, err := client.LoadServerRegistry()
	if err != nil {
		return err
	}

	entry := reg.FindByAlias(alias)
	if entry == nil {
		return fmt.Errorf("server %q not found", alias)
	}

	// GitHub requires extra validation.
	if entry.Type == gpg.TargetTypeGitHub {
		if err := validateGitHubAccess(ctx); err != nil {
			return err
		}
	}

	entry.Enabled = true
	if err := client.SaveServerRegistry(reg); err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "Enabled %q\n", alias)
	return nil
}

func serverDisable(ctx context.Context, cmd *cli.Command) error {
	alias := cmd.Args().First()
	if alias == "" {
		return fmt.Errorf("usage: server disable <alias>")
	}

	client, err := newGPGClient(ctx)
	if err != nil {
		return err
	}

	reg, err := client.LoadServerRegistry()
	if err != nil {
		return err
	}

	entry := reg.FindByAlias(alias)
	if entry == nil {
		return fmt.Errorf("server %q not found", alias)
	}

	entry.Enabled = false
	if err := client.SaveServerRegistry(reg); err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "Disabled %q\n", alias)
	return nil
}

// validateGitHubAccess checks that the gh CLI is installed, authenticated,
// and has the required OAuth scopes for GPG and SSH key management.
func validateGitHubAccess(ctx context.Context) error {
	ghPath, err := exec.LookPath("gh")
	if err != nil {
		return fmt.Errorf("gh CLI not found; install it from https://cli.github.com")
	}

	out, err := exec.CommandContext(ctx, ghPath, "auth", "status").CombinedOutput() //nolint:gosec // ghPath from LookPath
	if err != nil {
		return fmt.Errorf("gh is not authenticated; run: gh auth login")
	}

	output := string(out)
	requiredScopes := []string{"admin:gpg_key", "admin:public_key"}
	var missing []string

	for _, scope := range requiredScopes {
		if !strings.Contains(output, scope) {
			missing = append(missing, scope)
		}
	}

	if len(missing) > 0 {
		fmt.Fprintln(os.Stderr, "GitHub publishing requires additional permissions. Run:")
		fmt.Fprintf(os.Stderr, "\n  gh auth refresh -s %s\n\n", strings.Join(missing, " -s "))
		return fmt.Errorf("missing GitHub OAuth scopes: %s", strings.Join(missing, ", "))
	}

	return nil
}

// enabledPublishTargets loads the server registry and returns publish targets
// for all enabled servers. Used by card commands that auto-publish after key operations.
func enabledPublishTargets(client *gpg.Client) ([]gpg.PublishTarget, error) {
	reg, err := client.LoadServerRegistry()
	if err != nil {
		return nil, err
	}
	return gpg.ToPublishTargets(reg.EnabledServers()), nil
}

func serverPublish(ctx context.Context, cmd *cli.Command) error {
	client, err := newGPGClient(ctx)
	if err != nil {
		return err
	}

	cfg, err := loadGPGConfig(ctx, client)
	if err != nil {
		return err
	}

	reg, err := client.LoadServerRegistry()
	if err != nil {
		return err
	}

	// Resolve which servers to publish to.
	var servers []gpg.ServerEntry
	if cmd.Args().Present() {
		for _, alias := range cmd.Args().Slice() {
			entry := reg.FindByAlias(alias)
			if entry == nil {
				return fmt.Errorf("unknown server %q (run 'server list' to see available targets)", alias)
			}
			servers = append(servers, *entry)
		}
	} else {
		servers = reg.EnabledServers()
		if len(servers) == 0 {
			return fmt.Errorf("no servers enabled (run 'server enable <alias>' or 'server list')")
		}
	}

	targets := gpg.ToPublishTargets(servers)
	results := client.Publish(ctx, cfg.MasterFP, targets)
	logger := loggerFrom(ctx)

	var firstErr error
	for i, r := range results {
		label := servers[i].Alias
		if r.Err != nil {
			logger.ErrorContext(ctx, "publish failed",
				slog.String("target", label),
				slog.String("error", r.Err.Error()),
			)
			if firstErr == nil {
				firstErr = r.Err
			}
		} else {
			logger.InfoContext(ctx, "published",
				slog.String("target", label),
			)
		}
	}

	// Audit successful publishes.
	var published []string
	for i, r := range results {
		if r.Err == nil {
			published = append(published, servers[i].Alias)
		}
	}
	if len(published) > 0 {
		_ = audit.Append(client.HomeDir(), audit.Entry{
			Action:  "publish",
			Details: fmt.Sprintf("published to %s", strings.Join(published, ", ")),
		})
	}

	return firstErr
}

func serverLookup(ctx context.Context, _ *cli.Command) error {
	client, err := newGPGClient(ctx)
	if err != nil {
		return err
	}

	cfg, err := loadGPGConfig(ctx, client)
	if err != nil {
		return err
	}

	reg, err := client.LoadServerRegistry()
	if err != nil {
		return err
	}

	// Use all keyserver URLs from the registry (enabled + disabled).
	servers := reg.AllServerURLs()

	// Check if any server is github type.
	hasGitHub := false
	for i := range reg.Servers {
		if reg.Servers[i].Type == gpg.TargetTypeGitHub {
			hasGitHub = true
			break
		}
	}

	extra := ""
	if hasGitHub {
		extra = " + GitHub"
	}
	fmt.Fprintf(os.Stderr, "Looking up %s on %d keyservers%s...\n", cfg.MasterFP, len(servers), extra)

	results := client.LookupKeyservers(ctx, cfg.MasterFP, servers)

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "TARGET\tSTATUS")
	for _, r := range results {
		status := "found"
		if !r.Found {
			if r.Err != nil && strings.Contains(r.Err.Error(), "context deadline exceeded") {
				status = "timeout"
			} else {
				status = "not found"
			}
		}
		_, _ = fmt.Fprintf(w, "%s\t%s\n", r.URL, status)
	}

	// Also check GitHub if in registry.
	if hasGitHub {
		ghResult := client.LookupGitHub(ctx, cfg.MasterFP)
		ghStatus := "found"
		if !ghResult.Found {
			if ghResult.Err != nil {
				ghStatus = ghResult.Err.Error()
			} else {
				ghStatus = "not found"
			}
		}
		_, _ = fmt.Fprintf(w, "%s\t%s\n", "github", ghStatus)
	}

	return w.Flush()
}
