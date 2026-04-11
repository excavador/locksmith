package wire

import (
	"context"

	"connectrpc.com/connect"

	v1 "github.com/excavador/locksmith/pkg/gen/gpgsmith/v1"
	"github.com/excavador/locksmith/pkg/gen/gpgsmith/v1/gpgsmithv1connect"
)

type (
	cardHandler struct {
		gpgsmithv1connect.UnimplementedCardServiceHandler
		backend Backend
	}
)

func newCardHandler(b Backend) *cardHandler {
	return &cardHandler{backend: b}
}

func (h *cardHandler) Provision(ctx context.Context, req *connect.Request[v1.ProvisionRequest]) (*connect.Response[v1.ProvisionResponse], error) {
	token, ok := TokenFromContext(ctx)
	if !ok {
		return nil, errMissingSessionToken()
	}
	card, sshPath, err := h.backend.ProvisionCard(ctx, token, ProvisionCardOpts{
		Label:       req.Msg.Label,
		Description: req.Msg.Description,
		SameKeys:    req.Msg.SameKeys,
		UniqueKeys:  req.Msg.UniqueKeys,
	})
	if err != nil {
		return nil, connectErr(err)
	}
	return connect.NewResponse(&v1.ProvisionResponse{
		Card:          toProtoCardInfo(card),
		SshPubkeyPath: sshPath,
	}), nil
}

func (h *cardHandler) Rotate(ctx context.Context, req *connect.Request[v1.RotateRequest]) (*connect.Response[v1.RotateResponse], error) {
	token, ok := TokenFromContext(ctx)
	if !ok {
		return nil, errMissingSessionToken()
	}
	card, err := h.backend.RotateCard(ctx, token, req.Msg.Label)
	if err != nil {
		return nil, connectErr(err)
	}
	return connect.NewResponse(&v1.RotateResponse{
		Card: toProtoCardInfo(card),
	}), nil
}

func (h *cardHandler) Revoke(ctx context.Context, req *connect.Request[v1.RevokeCardRequest]) (*connect.Response[v1.RevokeCardResponse], error) {
	token, ok := TokenFromContext(ctx)
	if !ok {
		return nil, errMissingSessionToken()
	}
	if err := h.backend.RevokeCard(ctx, token, req.Msg.Label); err != nil {
		return nil, connectErr(err)
	}
	return connect.NewResponse(&v1.RevokeCardResponse{}), nil
}

func (h *cardHandler) Inventory(ctx context.Context, _ *connect.Request[v1.InventoryRequest]) (*connect.Response[v1.InventoryResponse], error) {
	token, ok := TokenFromContext(ctx)
	if !ok {
		return nil, errMissingSessionToken()
	}
	cards, err := h.backend.CardInventory(ctx, token)
	if err != nil {
		return nil, connectErr(err)
	}
	return connect.NewResponse(&v1.InventoryResponse{
		Cards: toProtoCardInfos(cards),
	}), nil
}

func (h *cardHandler) Discover(ctx context.Context, req *connect.Request[v1.DiscoverRequest]) (*connect.Response[v1.DiscoverResponse], error) {
	token, ok := TokenFromContext(ctx)
	if !ok {
		return nil, errMissingSessionToken()
	}
	card, alreadyKnown, err := h.backend.DiscoverCard(ctx, token, req.Msg.Label, req.Msg.Description)
	if err != nil {
		return nil, connectErr(err)
	}
	return connect.NewResponse(&v1.DiscoverResponse{
		Card:               toProtoCardInfo(card),
		AlreadyInInventory: alreadyKnown,
	}), nil
}
