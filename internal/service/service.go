package service

import (
	"context"
	"fmt"
	"strings"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	catchyv1 "github.com/catchysh/catchy/gen/catchy/v1"
	"github.com/catchysh/catchy/gen/catchy/v1/catchyv1connect"
	"github.com/catchysh/catchy/internal/auth"
	"github.com/catchysh/catchy/internal/db"
	"github.com/catchysh/catchy/internal/payload"
)

const defaultPageSize = 50

// Service implements the HookService and ChannelService APIs. Hooks and
// channels are shared by everyone with an API key on this instance.
type Service struct {
	db *db.DB
}

var (
	_ catchyv1connect.HookServiceHandler    = (*Service)(nil)
	_ catchyv1connect.ChannelServiceHandler = (*Service)(nil)
)

func New(database *db.DB) *Service {
	return &Service{db: database}
}

// dbError maps a db-layer error to the appropriate connect code.
func dbError(err error) error {
	if strings.Contains(err.Error(), "not found") {
		return connect.NewError(connect.CodeNotFound, err)
	}
	return connect.NewError(connect.CodeInternal, err)
}

func hookProto(h *db.Hook, events []db.Event) (*catchyv1.Hook, error) {
	p := &catchyv1.Hook{
		Id:          h.ID,
		Channel:     h.Channel,
		Status:      h.Status,
		Method:      h.Method,
		Query:       h.Query,
		Headers:     h.Headers,
		ContentType: h.ContentType,
		Body:        h.Body,
		Ip:          h.IP,
		Events:      make([]*catchyv1.Event, 0, len(events)),
		CreatedAt:   timestamppb.New(h.CreatedAt),
	}
	if fields := payload.Decode(h.ContentType, h.Body); fields != nil {
		s, err := structpb.NewStruct(fields)
		if err != nil {
			return nil, fmt.Errorf("converting payload of hook %s: %w", h.ID, err)
		}
		p.Payload = s
	}
	for _, e := range events {
		p.Events = append(p.Events, &catchyv1.Event{Kind: e.Kind, Actor: e.Actor, Message: e.Message, CreatedAt: timestamppb.New(e.CreatedAt)})
	}
	if h.FinalizedAt != nil {
		p.FinalizedAt = timestamppb.New(*h.FinalizedAt)
	}
	return p, nil
}

func channelProto(c *db.Channel) *catchyv1.Channel {
	return &catchyv1.Channel{
		Name:   c.Name,
		Paused: c.Paused(),
		Guards: c.Guards,
		Stats: &catchyv1.ChannelStats{
			Pending:   c.Stats.Pending,
			Handled:   c.Stats.Handled,
			Failed:    c.Stats.Failed,
			Discarded: c.Stats.Discarded,
		},
	}
}

// Hooks

func (s *Service) ListHooks(ctx context.Context, req *connect.Request[catchyv1.ListHooksRequest]) (*connect.Response[catchyv1.ListHooksResponse], error) {
	limit := defaultPageSize
	if req.Msg.Limit != nil {
		limit = int(*req.Msg.Limit)
	}
	hooks, err := s.db.ListHooks(ctx, db.HookFilter{
		Channel: req.Msg.GetChannel(),
		Status:  req.Msg.GetStatus(),
		After:   req.Msg.GetAfter(),
	}, limit)
	if err != nil {
		return nil, dbError(err)
	}
	ids := make([]string, len(hooks))
	for i, h := range hooks {
		ids[i] = h.ID
	}
	events, err := s.db.HookEvents(ctx, ids)
	if err != nil {
		return nil, dbError(err)
	}
	resp := &catchyv1.ListHooksResponse{Hooks: make([]*catchyv1.Hook, 0, len(hooks))}
	for _, h := range hooks {
		p, err := hookProto(&h, events[h.ID])
		if err != nil {
			return nil, connect.NewError(connect.CodeInternal, err)
		}
		resp.Hooks = append(resp.Hooks, p)
	}
	return connect.NewResponse(resp), nil
}

func (s *Service) GetHook(ctx context.Context, req *connect.Request[catchyv1.GetHookRequest]) (*connect.Response[catchyv1.GetHookResponse], error) {
	h, err := s.db.GetHook(ctx, req.Msg.Id)
	if err != nil {
		return nil, dbError(err)
	}
	p, err := s.hookProto(ctx, h)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&catchyv1.GetHookResponse{Hook: p}), nil
}

func (s *Service) DiscardHook(ctx context.Context, req *connect.Request[catchyv1.DiscardHookRequest]) (*connect.Response[catchyv1.DiscardHookResponse], error) {
	h, err := s.setHookStatus(ctx, req.Msg.Id, db.StatusDiscarded)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&catchyv1.DiscardHookResponse{Hook: h}), nil
}

func (s *Service) RetryHook(ctx context.Context, req *connect.Request[catchyv1.RetryHookRequest]) (*connect.Response[catchyv1.RetryHookResponse], error) {
	h, err := s.setHookStatus(ctx, req.Msg.Id, db.StatusPending)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&catchyv1.RetryHookResponse{Hook: h}), nil
}

// setHookStatus sets a hook's status as the API key making the request.
func (s *Service) setHookStatus(ctx context.Context, id, status string) (*catchyv1.Hook, error) {
	h, err := s.db.SetHookStatus(ctx, id, status, auth.ActorFromContext(ctx), "")
	if err != nil {
		return nil, dbError(err)
	}
	return s.hookProto(ctx, h)
}

// hookProto converts a hook with its events.
func (s *Service) hookProto(ctx context.Context, h *db.Hook) (*catchyv1.Hook, error) {
	events, err := s.db.HookEvents(ctx, []string{h.ID})
	if err != nil {
		return nil, dbError(err)
	}
	p, err := hookProto(h, events[h.ID])
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return p, nil
}

func (s *Service) DeleteHook(ctx context.Context, req *connect.Request[catchyv1.DeleteHookRequest]) (*connect.Response[catchyv1.DeleteHookResponse], error) {
	if err := s.db.DeleteHook(ctx, req.Msg.Id); err != nil {
		return nil, dbError(err)
	}
	return connect.NewResponse(&catchyv1.DeleteHookResponse{}), nil
}

// Channels

func (s *Service) ListChannels(ctx context.Context, _ *connect.Request[catchyv1.ListChannelsRequest]) (*connect.Response[catchyv1.ListChannelsResponse], error) {
	channels, err := s.db.ListChannels(ctx)
	if err != nil {
		return nil, dbError(err)
	}
	resp := &catchyv1.ListChannelsResponse{Channels: make([]*catchyv1.Channel, 0, len(channels))}
	for _, c := range channels {
		resp.Channels = append(resp.Channels, channelProto(&c))
	}
	return connect.NewResponse(resp), nil
}

func (s *Service) GetChannel(ctx context.Context, req *connect.Request[catchyv1.GetChannelRequest]) (*connect.Response[catchyv1.GetChannelResponse], error) {
	c, err := s.db.GetChannel(ctx, req.Msg.Name)
	if err != nil {
		return nil, dbError(err)
	}
	return connect.NewResponse(&catchyv1.GetChannelResponse{Channel: channelProto(c)}), nil
}

func (s *Service) PauseChannel(ctx context.Context, req *connect.Request[catchyv1.PauseChannelRequest]) (*connect.Response[catchyv1.PauseChannelResponse], error) {
	c, err := s.db.SetChannelPaused(ctx, req.Msg.Name, true)
	if err != nil {
		return nil, dbError(err)
	}
	return connect.NewResponse(&catchyv1.PauseChannelResponse{Channel: channelProto(c)}), nil
}

func (s *Service) ResumeChannel(ctx context.Context, req *connect.Request[catchyv1.ResumeChannelRequest]) (*connect.Response[catchyv1.ResumeChannelResponse], error) {
	c, err := s.db.SetChannelPaused(ctx, req.Msg.Name, false)
	if err != nil {
		return nil, dbError(err)
	}
	return connect.NewResponse(&catchyv1.ResumeChannelResponse{Channel: channelProto(c)}), nil
}

func (s *Service) DeleteChannel(ctx context.Context, req *connect.Request[catchyv1.DeleteChannelRequest]) (*connect.Response[catchyv1.DeleteChannelResponse], error) {
	if err := s.db.DeleteChannel(ctx, req.Msg.Name); err != nil {
		return nil, dbError(err)
	}
	return connect.NewResponse(&catchyv1.DeleteChannelResponse{}), nil
}
