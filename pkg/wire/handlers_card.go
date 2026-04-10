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
	card, sshPath, err := h.backend.ProvisionCard(ctx, req.Msg.VaultName, ProvisionCardOpts{
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
	card, err := h.backend.RotateCard(ctx, req.Msg.VaultName, req.Msg.Label)
	if err != nil {
		return nil, connectErr(err)
	}
	return connect.NewResponse(&v1.RotateResponse{
		Card: toProtoCardInfo(card),
	}), nil
}

func (h *cardHandler) Revoke(ctx context.Context, req *connect.Request[v1.RevokeCardRequest]) (*connect.Response[v1.RevokeCardResponse], error) {
	if err := h.backend.RevokeCard(ctx, req.Msg.VaultName, req.Msg.Label); err != nil {
		return nil, connectErr(err)
	}
	return connect.NewResponse(&v1.RevokeCardResponse{}), nil
}

func (h *cardHandler) Inventory(ctx context.Context, req *connect.Request[v1.InventoryRequest]) (*connect.Response[v1.InventoryResponse], error) {
	cards, err := h.backend.CardInventory(ctx, req.Msg.VaultName)
	if err != nil {
		return nil, connectErr(err)
	}
	return connect.NewResponse(&v1.InventoryResponse{
		Cards: toProtoCardInfos(cards),
	}), nil
}

func (h *cardHandler) Discover(ctx context.Context, req *connect.Request[v1.DiscoverRequest]) (*connect.Response[v1.DiscoverResponse], error) {
	card, alreadyKnown, err := h.backend.DiscoverCard(ctx, req.Msg.VaultName, req.Msg.Label, req.Msg.Description)
	if err != nil {
		return nil, connectErr(err)
	}
	return connect.NewResponse(&v1.DiscoverResponse{
		Card:               toProtoCardInfo(card),
		AlreadyInInventory: alreadyKnown,
	}), nil
}
