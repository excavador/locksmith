package wire

import (
	"context"

	"connectrpc.com/connect"

	v1 "github.com/excavador/locksmith/pkg/gen/gpgsmith/v1"
	"github.com/excavador/locksmith/pkg/gen/gpgsmith/v1/gpgsmithv1connect"
)

type (
	vaultHandler struct {
		gpgsmithv1connect.UnimplementedVaultServiceHandler
		backend Backend
	}
)

func newVaultHandler(b Backend) *vaultHandler {
	return &vaultHandler{backend: b}
}

func (h *vaultHandler) List(ctx context.Context, _ *connect.Request[v1.ListRequest]) (*connect.Response[v1.ListResponse], error) {
	entries, defaultName, err := h.backend.ListVaults(ctx)
	if err != nil {
		return nil, connectErr(err)
	}
	return connect.NewResponse(&v1.ListResponse{
		Vaults:       toProtoVaultEntries(entries),
		DefaultVault: defaultName,
	}), nil
}

func (h *vaultHandler) Status(ctx context.Context, _ *connect.Request[v1.StatusVaultRequest]) (*connect.Response[v1.StatusVaultResponse], error) {
	open, recoverable, err := h.backend.StatusVaults(ctx)
	if err != nil {
		return nil, connectErr(err)
	}
	return connect.NewResponse(&v1.StatusVaultResponse{
		Open:        toProtoSessionInfos(open),
		Recoverable: toProtoResumeOptions(recoverable),
	}), nil
}

func (h *vaultHandler) Open(ctx context.Context, req *connect.Request[v1.OpenRequest]) (*connect.Response[v1.OpenResponse], error) {
	res, err := h.backend.OpenVault(ctx, req.Msg.VaultName, req.Msg.Passphrase, fromProtoLockSource(req.Msg.Source))
	if err != nil {
		return nil, connectErr(err)
	}
	resp := &v1.OpenResponse{}
	if res.Session != nil {
		resp.Session = toProtoSessionInfo(*res.Session)
	}
	if res.ResumeAvailable != nil {
		resp.ResumeAvailable = toProtoResumeOption(*res.ResumeAvailable)
	}
	return connect.NewResponse(resp), nil
}

func (h *vaultHandler) Resume(ctx context.Context, req *connect.Request[v1.ResumeRequest]) (*connect.Response[v1.ResumeResponse], error) {
	resume := req.Msg.Action == v1.ResumeRequest_ACTION_RESUME
	info, err := h.backend.ResumeVault(ctx, req.Msg.VaultName, req.Msg.Passphrase, fromProtoLockSource(req.Msg.Source), resume)
	if err != nil {
		return nil, connectErr(err)
	}
	return connect.NewResponse(&v1.ResumeResponse{
		Session: toProtoSessionInfo(info),
	}), nil
}

func (h *vaultHandler) Seal(ctx context.Context, req *connect.Request[v1.SealRequest]) (*connect.Response[v1.SealResponse], error) {
	snap, err := h.backend.SealVault(ctx, req.Msg.VaultName, req.Msg.Message)
	if err != nil {
		return nil, connectErr(err)
	}
	return connect.NewResponse(&v1.SealResponse{
		Snapshot: toProtoSnapshot(snap),
	}), nil
}

func (h *vaultHandler) Discard(ctx context.Context, req *connect.Request[v1.DiscardRequest]) (*connect.Response[v1.DiscardResponse], error) {
	if err := h.backend.DiscardVault(ctx, req.Msg.VaultName); err != nil {
		return nil, connectErr(err)
	}
	return connect.NewResponse(&v1.DiscardResponse{}), nil
}

func (h *vaultHandler) Snapshots(ctx context.Context, req *connect.Request[v1.SnapshotsRequest]) (*connect.Response[v1.SnapshotsResponse], error) {
	snaps, err := h.backend.Snapshots(ctx, req.Msg.VaultName)
	if err != nil {
		return nil, connectErr(err)
	}
	return connect.NewResponse(&v1.SnapshotsResponse{
		Snapshots: toProtoSnapshots(snaps),
	}), nil
}

func (h *vaultHandler) Create(ctx context.Context, req *connect.Request[v1.CreateVaultRequest]) (*connect.Response[v1.CreateVaultResponse], error) {
	snap, info, err := h.backend.CreateVault(ctx, req.Msg.Name, req.Msg.Path, req.Msg.Passphrase)
	if err != nil {
		return nil, connectErr(err)
	}
	return connect.NewResponse(&v1.CreateVaultResponse{
		Snapshot: toProtoSnapshot(snap),
		Session:  toProtoSessionInfo(info),
	}), nil
}

func (h *vaultHandler) Import(ctx context.Context, req *connect.Request[v1.ImportRequest]) (*connect.Response[v1.ImportResponse], error) {
	snap, err := h.backend.ImportVault(ctx, req.Msg.SourcePath, req.Msg.Passphrase, req.Msg.TargetVaultName)
	if err != nil {
		return nil, connectErr(err)
	}
	return connect.NewResponse(&v1.ImportResponse{
		Snapshot: toProtoSnapshot(snap),
	}), nil
}

func (h *vaultHandler) Export(ctx context.Context, req *connect.Request[v1.ExportRequest]) (*connect.Response[v1.ExportResponse], error) {
	snapName, err := h.backend.ExportVault(ctx, req.Msg.VaultName, req.Msg.Passphrase, req.Msg.TargetDir)
	if err != nil {
		return nil, connectErr(err)
	}
	return connect.NewResponse(&v1.ExportResponse{
		TargetDir: req.Msg.TargetDir,
		Snapshot:  snapName,
	}), nil
}

func (h *vaultHandler) Trust(ctx context.Context, req *connect.Request[v1.TrustRequest]) (*connect.Response[v1.TrustResponse], error) {
	if err := h.backend.TrustVault(ctx, req.Msg.VaultName, req.Msg.Fingerprint); err != nil {
		return nil, connectErr(err)
	}
	return connect.NewResponse(&v1.TrustResponse{}), nil
}
