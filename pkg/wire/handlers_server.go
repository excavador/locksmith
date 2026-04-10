package wire

import (
	"context"

	"connectrpc.com/connect"

	v1 "github.com/excavador/locksmith/pkg/gen/gpgsmith/v1"
	"github.com/excavador/locksmith/pkg/gen/gpgsmith/v1/gpgsmithv1connect"
)

type (
	serverHandler struct {
		gpgsmithv1connect.UnimplementedServerServiceHandler
		backend Backend
	}
)

func newServerHandler(b Backend) *serverHandler {
	return &serverHandler{backend: b}
}

func (h *serverHandler) List(ctx context.Context, req *connect.Request[v1.ListServersRequest]) (*connect.Response[v1.ListServersResponse], error) {
	servers, err := h.backend.ListPublishServers(ctx, req.Msg.VaultName)
	if err != nil {
		return nil, connectErr(err)
	}
	return connect.NewResponse(&v1.ListServersResponse{
		Servers: toProtoPublishServers(servers),
	}), nil
}

func (h *serverHandler) Add(ctx context.Context, req *connect.Request[v1.AddServerRequest]) (*connect.Response[v1.AddServerResponse], error) {
	if err := h.backend.AddPublishServer(ctx, req.Msg.VaultName, req.Msg.Alias, req.Msg.Url); err != nil {
		return nil, connectErr(err)
	}
	return connect.NewResponse(&v1.AddServerResponse{}), nil
}

func (h *serverHandler) Remove(ctx context.Context, req *connect.Request[v1.RemoveServerRequest]) (*connect.Response[v1.RemoveServerResponse], error) {
	if err := h.backend.RemovePublishServer(ctx, req.Msg.VaultName, req.Msg.Alias); err != nil {
		return nil, connectErr(err)
	}
	return connect.NewResponse(&v1.RemoveServerResponse{}), nil
}

func (h *serverHandler) Enable(ctx context.Context, req *connect.Request[v1.EnableServerRequest]) (*connect.Response[v1.EnableServerResponse], error) {
	if err := h.backend.EnablePublishServer(ctx, req.Msg.VaultName, req.Msg.Alias); err != nil {
		return nil, connectErr(err)
	}
	return connect.NewResponse(&v1.EnableServerResponse{}), nil
}

func (h *serverHandler) Disable(ctx context.Context, req *connect.Request[v1.DisableServerRequest]) (*connect.Response[v1.DisableServerResponse], error) {
	if err := h.backend.DisablePublishServer(ctx, req.Msg.VaultName, req.Msg.Alias); err != nil {
		return nil, connectErr(err)
	}
	return connect.NewResponse(&v1.DisableServerResponse{}), nil
}

func (h *serverHandler) Publish(ctx context.Context, req *connect.Request[v1.PublishRequest]) (*connect.Response[v1.PublishResponse], error) {
	results, err := h.backend.Publish(ctx, req.Msg.VaultName, req.Msg.Aliases)
	if err != nil {
		return nil, connectErr(err)
	}
	return connect.NewResponse(&v1.PublishResponse{
		Results: toProtoPublishResults(results),
	}), nil
}

func (h *serverHandler) Lookup(ctx context.Context, req *connect.Request[v1.LookupRequest]) (*connect.Response[v1.LookupResponse], error) {
	results, err := h.backend.LookupPublished(ctx, req.Msg.VaultName)
	if err != nil {
		return nil, connectErr(err)
	}
	return connect.NewResponse(&v1.LookupResponse{
		Results: toProtoLookupResults(results),
	}), nil
}
