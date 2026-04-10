package wire

import (
	"context"

	"connectrpc.com/connect"

	v1 "github.com/excavador/locksmith/pkg/gen/gpgsmith/v1"
	"github.com/excavador/locksmith/pkg/gen/gpgsmith/v1/gpgsmithv1connect"
)

type (
	eventHandler struct {
		gpgsmithv1connect.UnimplementedEventServiceHandler
		backend Backend
	}
)

func newEventHandler(b Backend) *eventHandler {
	return &eventHandler{backend: b}
}

// Subscribe is a server-streaming RPC. The handler subscribes to the
// backend's event channel for the requested vault and forwards each event
// to the Connect stream until the client disconnects (which cancels ctx)
// or the backend channel is closed (which means the daemon is shutting
// down).
func (h *eventHandler) Subscribe(ctx context.Context, req *connect.Request[v1.SubscribeRequest], stream *connect.ServerStream[v1.Event]) error {
	events, err := h.backend.SubscribeEvents(ctx, req.Msg.VaultName)
	if err != nil {
		return connectErr(err)
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		case e, ok := <-events:
			if !ok {
				// Backend closed the channel — shutdown.
				return nil
			}
			if err := stream.Send(toProtoEvent(e)); err != nil {
				return connectErr(err)
			}
		}
	}
}
