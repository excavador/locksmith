package wire

import (
	"context"

	"connectrpc.com/connect"

	v1 "github.com/excavador/locksmith/pkg/gen/gpgsmith/v1"
	"github.com/excavador/locksmith/pkg/gen/gpgsmith/v1/gpgsmithv1connect"
)

type (
	keyHandler struct {
		gpgsmithv1connect.UnimplementedKeyServiceHandler
		backend Backend
	}
)

func newKeyHandler(b Backend) *keyHandler {
	return &keyHandler{backend: b}
}

func (h *keyHandler) Create(ctx context.Context, req *connect.Request[v1.CreateRequest]) (*connect.Response[v1.CreateResponse], error) {
	token, ok := TokenFromContext(ctx)
	if !ok {
		return nil, errMissingSessionToken()
	}
	fp, subkeys, err := h.backend.CreateMasterKey(ctx, token, CreateKeyOpts{
		Name:         req.Msg.Name,
		Email:        req.Msg.Email,
		Algo:         req.Msg.Algo,
		Expiry:       req.Msg.Expiry,
		SubkeyAlgo:   req.Msg.SubkeyAlgo,
		SubkeyExpiry: req.Msg.SubkeyExpiry,
	})
	if err != nil {
		return nil, connectErr(err)
	}
	return connect.NewResponse(&v1.CreateResponse{
		MasterFp: fp,
		Subkeys:  toProtoSubKeys(subkeys),
	}), nil
}

func (h *keyHandler) Generate(ctx context.Context, _ *connect.Request[v1.GenerateRequest]) (*connect.Response[v1.GenerateResponse], error) {
	token, ok := TokenFromContext(ctx)
	if !ok {
		return nil, errMissingSessionToken()
	}
	subkeys, err := h.backend.GenerateSubkeys(ctx, token)
	if err != nil {
		return nil, connectErr(err)
	}
	return connect.NewResponse(&v1.GenerateResponse{
		Subkeys: toProtoSubKeys(subkeys),
	}), nil
}

func (h *keyHandler) List(ctx context.Context, _ *connect.Request[v1.ListKeysRequest]) (*connect.Response[v1.ListKeysResponse], error) {
	token, ok := TokenFromContext(ctx)
	if !ok {
		return nil, errMissingSessionToken()
	}
	keys, err := h.backend.ListKeys(ctx, token)
	if err != nil {
		return nil, connectErr(err)
	}
	return connect.NewResponse(&v1.ListKeysResponse{
		Keys: toProtoSubKeys(keys),
	}), nil
}

func (h *keyHandler) Revoke(ctx context.Context, req *connect.Request[v1.RevokeRequest]) (*connect.Response[v1.RevokeResponse], error) {
	token, ok := TokenFromContext(ctx)
	if !ok {
		return nil, errMissingSessionToken()
	}
	if err := h.backend.RevokeSubkey(ctx, token, req.Msg.KeyId); err != nil {
		return nil, connectErr(err)
	}
	return connect.NewResponse(&v1.RevokeResponse{}), nil
}

func (h *keyHandler) Export(ctx context.Context, _ *connect.Request[v1.ExportKeyRequest]) (*connect.Response[v1.ExportKeyResponse], error) {
	token, ok := TokenFromContext(ctx)
	if !ok {
		return nil, errMissingSessionToken()
	}
	target, err := h.backend.ExportKey(ctx, token)
	if err != nil {
		return nil, connectErr(err)
	}
	return connect.NewResponse(&v1.ExportKeyResponse{Target: target}), nil
}

func (h *keyHandler) SSHPubKey(ctx context.Context, _ *connect.Request[v1.SSHPubKeyRequest]) (*connect.Response[v1.SSHPubKeyResponse], error) {
	token, ok := TokenFromContext(ctx)
	if !ok {
		return nil, errMissingSessionToken()
	}
	path, err := h.backend.SSHPubKey(ctx, token)
	if err != nil {
		return nil, connectErr(err)
	}
	return connect.NewResponse(&v1.SSHPubKeyResponse{Path: path}), nil
}

func (h *keyHandler) Status(ctx context.Context, _ *connect.Request[v1.KeyStatusRequest]) (*connect.Response[v1.KeyStatusResponse], error) {
	token, ok := TokenFromContext(ctx)
	if !ok {
		return nil, errMissingSessionToken()
	}
	keys, card, err := h.backend.KeyStatus(ctx, token)
	if err != nil {
		return nil, connectErr(err)
	}
	resp := &v1.KeyStatusResponse{
		Keys: toProtoSubKeys(keys),
	}
	if card != nil {
		resp.Card = &v1.CardInfo{
			Serial: card.Serial,
			Model:  card.Model,
		}
	}
	return connect.NewResponse(resp), nil
}
