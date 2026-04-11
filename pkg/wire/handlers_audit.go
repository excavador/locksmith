package wire

import (
	"context"

	"connectrpc.com/connect"

	v1 "github.com/excavador/locksmith/pkg/gen/gpgsmith/v1"
	"github.com/excavador/locksmith/pkg/gen/gpgsmith/v1/gpgsmithv1connect"
)

type (
	auditHandler struct {
		gpgsmithv1connect.UnimplementedAuditServiceHandler
		backend Backend
	}
)

func newAuditHandler(b Backend) *auditHandler {
	return &auditHandler{backend: b}
}

func (h *auditHandler) Show(ctx context.Context, req *connect.Request[v1.ShowRequest]) (*connect.Response[v1.ShowResponse], error) {
	token, ok := TokenFromContext(ctx)
	if !ok {
		return nil, errMissingSessionToken()
	}
	entries, err := h.backend.ShowAudit(ctx, token, int(req.Msg.Last))
	if err != nil {
		return nil, connectErr(err)
	}
	return connect.NewResponse(&v1.ShowResponse{
		Entries: toProtoAuditEntries(entries),
	}), nil
}
