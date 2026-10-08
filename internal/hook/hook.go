// Package hook catches hooks: anonymous POSTs to /?channel={channel}, such as
// a provider's webhook or a website's contact form submitting straight from
// the visitor's browser. Each is stored as received, for consumers to process.
package hook

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"strings"

	"github.com/catchysh/catchy/internal/db"
	"github.com/catchysh/catchy/internal/env"
	"github.com/catchysh/catchy/internal/guard"
)

// MaxBodySize caps a hook's request body.
const MaxBodySize = 1 << 20 // 1 MiB

type Handler struct {
	db     *db.DB
	guards *guard.Checker
	// autoCreate lets a hook to an unknown channel create it. Without it,
	// only channels created in the dashboard accept hooks.
	autoCreate bool
	// trustProxy takes the client IP from X-Forwarded-For. Enable it only
	// behind a proxy that sets the header, since clients can forge it.
	trustProxy bool
	// env has the secrets guards check with, by name.
	env env.Env
}

func NewHandler(database *db.DB, guards *guard.Checker, e env.Env, autoCreate, trustProxy bool) *Handler {
	return &Handler{db: database, guards: guards, env: e, autoCreate: autoCreate, trustProxy: trustProxy}
}

// ServeHTTP handles POST / by storing a hook in the ?channel= channel
// (DefaultChannel when absent), and answers OPTIONS / CORS preflights so pages
// on any origin can send hooks with fetch.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	switch r.Method {
	case http.MethodOptions:
		w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
		if hdrs := r.Header.Get("Access-Control-Request-Headers"); hdrs != "" {
			w.Header().Set("Access-Control-Allow-Headers", hdrs)
		}
		w.Header().Set("Access-Control-Max-Age", "86400")
		w.WriteHeader(http.StatusNoContent)
		return
	case http.MethodPost:
	default:
		w.Header().Set("Allow", "POST, OPTIONS")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	channel := strings.ToLower(r.URL.Query().Get("channel"))
	if channel == "" {
		channel = db.DefaultChannel
	}
	if !db.ValidChannel(channel) {
		respondError(w, http.StatusBadRequest, "invalid channel: use up to 64 lowercase letters and digits, separated by single _ or -")
		return
	}

	// A paused channel refuses hooks with a 503, which webhook providers retry
	// later, so nothing sent while it's paused is lost.
	exists, paused, guards, err := h.db.ChannelPolicy(r.Context(), channel)
	if err != nil {
		log.Printf("hook: %v", err)
		respondError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if !exists && !h.autoCreate {
		respondError(w, http.StatusNotFound, "channel not found")
		return
	}
	if paused {
		w.Header().Set("Retry-After", "60")
		respondError(w, http.StatusServiceUnavailable, "channel paused")
		return
	}

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxBodySize))
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			respondError(w, http.StatusRequestEntityTooLarge, "hook too large")
			return
		}
		respondError(w, http.StatusBadRequest, "reading body failed")
		return
	}

	ip := h.clientIP(r)
	specs := make([]guard.Spec, len(guards))
	for i, g := range guards {
		opts, err := guard.ParseOptions(g.Options)
		if err != nil {
			log.Printf("hook: guard %s: %v", g.Name, err)
			respondError(w, http.StatusInternalServerError, "internal error")
			return
		}
		var secret string
		if g.Secret != "" {
			secret, err = h.env.Secret(g.Secret)
		}
		if err != nil {
			log.Printf("hook: guard %s: %v", g.Name, err)
			respondError(w, http.StatusInternalServerError, "internal error")
			return
		}
		specs[i] = guard.Spec{Name: g.Name, Type: g.Type, Scheme: g.Scheme, Secret: secret, Options: opts}
	}
	err = h.guards.Check(r.Context(), specs, guard.Hook{
		Header:      r.Header,
		ContentType: r.Header.Get("Content-Type"),
		Body:        body,
		IP:          ip,
	})
	var rejected *guard.RejectedError
	switch {
	case errors.Is(err, guard.ErrBot):
		// Answer exactly like a success, with an ID that's never stored, so the
		// bot doesn't adapt.
		respondOK(w, db.NewID())
		return
	case errors.As(err, &rejected):
		respondError(w, http.StatusForbidden, "verification failed: "+rejected.Error())
		return
	case err != nil:
		log.Printf("hook: %v", err)
		respondError(w, http.StatusBadGateway, "verification unavailable")
		return
	}

	hook, err := h.db.CreateHook(r.Context(), db.Hook{
		Channel:     channel,
		Method:      r.Method,
		Query:       r.URL.RawQuery,
		Headers:     storedHeaders(r.Header),
		ContentType: r.Header.Get("Content-Type"),
		Body:        body,
		IP:          ip,
	})
	if err != nil {
		log.Printf("hook: %v", err)
		respondError(w, http.StatusInternalServerError, "internal error")
		return
	}
	// The hook is stored; if queueing deliveries fails it can be retried.
	if _, err := h.db.EnqueueDeliveries(r.Context(), hook.ID, channel); err != nil {
		log.Printf("hook %s: queueing deliveries: %v", hook.ID, err)
	}
	respondOK(w, hook.ID)
}

// storedHeaders flattens request headers for storage, joining repeated values
// with ", ". Cookies are dropped: they may carry a signed-in user's session.
func storedHeaders(h http.Header) map[string]string {
	out := make(map[string]string, len(h))
	for k, v := range h {
		if k == "Cookie" {
			continue
		}
		out[k] = strings.Join(v, ", ")
	}
	return out
}

func (h *Handler) clientIP(r *http.Request) string {
	if h.trustProxy {
		if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
			first, _, _ := strings.Cut(fwd, ",")
			return strings.TrimSpace(first)
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// respondOK acknowledges a hook with its ID: {"id": "..."}.
func respondOK(w http.ResponseWriter, id string) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"id": id})
}

func respondError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
