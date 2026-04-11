package gpgsmith

import (
	"context"

	"connectrpc.com/connect"

	v1 "github.com/excavador/locksmith/pkg/gen/gpgsmith/v1"
	"github.com/excavador/locksmith/pkg/wire"
)

type (
	// wireAdapter is the production DaemonClient — it forwards calls
	// to a *wire.Client. All session-bearing calls take the daemon
	// session token explicitly and stamp it onto the per-request
	// context via wire.ContextWithSessionToken, so each browser tab's
	// RPCs carry its own token instead of the process-global
	// GPGSMITH_SESSION env var.
	wireAdapter struct {
		c *wire.Client
	}
)

// NewWireAdapter wraps a *wire.Client so the web UI can call it via
// the DaemonClient interface.
func NewWireAdapter(c *wire.Client) DaemonClient {
	return &wireAdapter{c: c}
}

func withToken(ctx context.Context, token string) context.Context {
	if token == "" {
		return ctx
	}
	return wire.ContextWithSessionToken(ctx, token)
}

func (a *wireAdapter) VaultList(ctx context.Context) (*v1.ListResponse, error) {
	resp, err := a.c.Vault.List(ctx, connect.NewRequest(&v1.ListRequest{}))
	if err != nil {
		return nil, err
	}
	return resp.Msg, nil
}

func (a *wireAdapter) VaultStatus(ctx context.Context) (*v1.StatusVaultResponse, error) {
	resp, err := a.c.Vault.Status(ctx, connect.NewRequest(&v1.StatusVaultRequest{}))
	if err != nil {
		return nil, err
	}
	return resp.Msg, nil
}

func (a *wireAdapter) VaultOpen(ctx context.Context, vaultName, passphrase string) (*v1.OpenResponse, error) {
	resp, err := a.c.Vault.Open(ctx, connect.NewRequest(&v1.OpenRequest{
		VaultName:  vaultName,
		Passphrase: passphrase,
		Source:     v1.LockSource_LOCK_SOURCE_UI,
	}))
	if err != nil {
		return nil, err
	}
	return resp.Msg, nil
}

func (a *wireAdapter) VaultResume(ctx context.Context, vaultName, passphrase string, resume bool) (*v1.ResumeResponse, error) {
	action := v1.ResumeRequest_ACTION_DISCARD
	if resume {
		action = v1.ResumeRequest_ACTION_RESUME
	}
	resp, err := a.c.Vault.Resume(ctx, connect.NewRequest(&v1.ResumeRequest{
		VaultName:  vaultName,
		Passphrase: passphrase,
		Source:     v1.LockSource_LOCK_SOURCE_UI,
		Action:     action,
	}))
	if err != nil {
		return nil, err
	}
	return resp.Msg, nil
}

func (a *wireAdapter) VaultDiscard(ctx context.Context, sessionToken string) error {
	_, err := a.c.Vault.Discard(withToken(ctx, sessionToken), connect.NewRequest(&v1.DiscardRequest{}))
	return err
}

func (a *wireAdapter) KeyList(ctx context.Context, sessionToken string) (*v1.ListKeysResponse, error) {
	resp, err := a.c.Key.List(withToken(ctx, sessionToken), connect.NewRequest(&v1.ListKeysRequest{}))
	if err != nil {
		return nil, err
	}
	return resp.Msg, nil
}

func (a *wireAdapter) KeyStatus(ctx context.Context, sessionToken string) (*v1.KeyStatusResponse, error) {
	resp, err := a.c.Key.Status(withToken(ctx, sessionToken), connect.NewRequest(&v1.KeyStatusRequest{}))
	if err != nil {
		return nil, err
	}
	return resp.Msg, nil
}

func (a *wireAdapter) IdentityList(ctx context.Context, sessionToken string) (*v1.ListIdentitiesResponse, error) {
	resp, err := a.c.Identity.List(withToken(ctx, sessionToken), connect.NewRequest(&v1.ListIdentitiesRequest{}))
	if err != nil {
		return nil, err
	}
	return resp.Msg, nil
}

func (a *wireAdapter) CardInventory(ctx context.Context, sessionToken string) (*v1.InventoryResponse, error) {
	resp, err := a.c.Card.Inventory(withToken(ctx, sessionToken), connect.NewRequest(&v1.InventoryRequest{}))
	if err != nil {
		return nil, err
	}
	return resp.Msg, nil
}

func (a *wireAdapter) ServerList(ctx context.Context, sessionToken string) (*v1.ListServersResponse, error) {
	resp, err := a.c.Server.List(withToken(ctx, sessionToken), connect.NewRequest(&v1.ListServersRequest{}))
	if err != nil {
		return nil, err
	}
	return resp.Msg, nil
}

func (a *wireAdapter) ServerLookup(ctx context.Context, sessionToken string) (*v1.LookupResponse, error) {
	resp, err := a.c.Server.Lookup(withToken(ctx, sessionToken), connect.NewRequest(&v1.LookupRequest{}))
	if err != nil {
		return nil, err
	}
	return resp.Msg, nil
}

func (a *wireAdapter) AuditShow(ctx context.Context, sessionToken string, last int32) (*v1.ShowResponse, error) {
	resp, err := a.c.Audit.Show(withToken(ctx, sessionToken), connect.NewRequest(&v1.ShowRequest{Last: last}))
	if err != nil {
		return nil, err
	}
	return resp.Msg, nil
}
