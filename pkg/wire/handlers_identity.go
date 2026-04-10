package wire

import (
	"context"

	"connectrpc.com/connect"

	v1 "github.com/excavador/locksmith/pkg/gen/gpgsmith/v1"
	"github.com/excavador/locksmith/pkg/gen/gpgsmith/v1/gpgsmithv1connect"
)

type (
	identityHandler struct {
		gpgsmithv1connect.UnimplementedIdentityServiceHandler
		backend Backend
	}
)

func newIdentityHandler(b Backend) *identityHandler {
	return &identityHandler{backend: b}
}

func (h *identityHandler) List(ctx context.Context, req *connect.Request[v1.ListIdentitiesRequest]) (*connect.Response[v1.ListIdentitiesResponse], error) {
	uids, err := h.backend.ListIdentities(ctx, req.Msg.VaultName)
	if err != nil {
		return nil, connectErr(err)
	}
	return connect.NewResponse(&v1.ListIdentitiesResponse{
		Identities: toProtoIdentities(uids),
	}), nil
}

func (h *identityHandler) Add(ctx context.Context, req *connect.Request[v1.AddIdentityRequest]) (*connect.Response[v1.AddIdentityResponse], error) {
	if err := h.backend.AddIdentity(ctx, req.Msg.VaultName, req.Msg.Uid); err != nil {
		return nil, connectErr(err)
	}
	return connect.NewResponse(&v1.AddIdentityResponse{}), nil
}

func (h *identityHandler) Revoke(ctx context.Context, req *connect.Request[v1.RevokeIdentityRequest]) (*connect.Response[v1.RevokeIdentityResponse], error) {
	if err := h.backend.RevokeIdentity(ctx, req.Msg.VaultName, req.Msg.Uid); err != nil {
		return nil, connectErr(err)
	}
	return connect.NewResponse(&v1.RevokeIdentityResponse{}), nil
}

func (h *identityHandler) Primary(ctx context.Context, req *connect.Request[v1.PrimaryIdentityRequest]) (*connect.Response[v1.PrimaryIdentityResponse], error) {
	if err := h.backend.PrimaryIdentity(ctx, req.Msg.VaultName, req.Msg.Uid); err != nil {
		return nil, connectErr(err)
	}
	return connect.NewResponse(&v1.PrimaryIdentityResponse{}), nil
}
