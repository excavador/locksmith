package wire

import (
	"context"

	"connectrpc.com/connect"

	v1 "github.com/excavador/locksmith/pkg/gen/gpgsmith/v1"
	"github.com/excavador/locksmith/pkg/gen/gpgsmith/v1/gpgsmithv1connect"
)

// daemonHandler implements gpgsmithv1connect.DaemonServiceHandler by
// translating proto in/out and delegating to the Backend.
type (
	daemonHandler struct {
		gpgsmithv1connect.UnimplementedDaemonServiceHandler
		backend Backend
	}
)

func newDaemonHandler(b Backend) *daemonHandler {
	return &daemonHandler{backend: b}
}

func (h *daemonHandler) Status(ctx context.Context, _ *connect.Request[v1.StatusRequest]) (*connect.Response[v1.StatusResponse], error) {
	st, err := h.backend.DaemonStatus(ctx)
	if err != nil {
		return nil, connectErr(err)
	}
	return connect.NewResponse(&v1.StatusResponse{
		Pid:            int32(st.PID), //nolint:gosec // pid fits in int32 on Linux/macOS
		Version:        st.Version,
		Commit:         st.Commit,
		SocketPath:     st.SocketPath,
		StartedAt:      toProtoTime(st.StartedAt),
		ActiveSessions: int32(st.ActiveSessions), //nolint:gosec // session count is small
	}), nil
}

func (h *daemonHandler) Shutdown(ctx context.Context, req *connect.Request[v1.ShutdownRequest]) (*connect.Response[v1.ShutdownResponse], error) {
	if err := h.backend.DaemonShutdown(ctx, int(req.Msg.GracefulTimeoutSeconds)); err != nil {
		return nil, connectErr(err)
	}
	return connect.NewResponse(&v1.ShutdownResponse{}), nil
}

func (h *daemonHandler) ListSessions(ctx context.Context, _ *connect.Request[v1.ListSessionsRequest]) (*connect.Response[v1.ListSessionsResponse], error) {
	sessions, err := h.backend.ListSessions(ctx)
	if err != nil {
		return nil, connectErr(err)
	}
	return connect.NewResponse(&v1.ListSessionsResponse{
		Sessions: toProtoSessionInfos(sessions),
	}), nil
}
