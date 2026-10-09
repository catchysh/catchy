package web

import (
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/catchysh/catchy/internal/auth"
	"github.com/catchysh/catchy/internal/db"
	"github.com/catchysh/catchy/internal/env"
	"github.com/catchysh/catchy/internal/guard"
	"github.com/catchysh/catchy/internal/handler"
	"github.com/catchysh/catchy/internal/payload"
)

//go:embed templates/*.html
var templateFS embed.FS

type Handler struct {
	db       *db.DB
	sessions *auth.SessionManager
	hostname string
	version  string
	env      env.Env                       // variables and secrets from the environment
	login    *template.Template            // standalone pages
	pages    map[string]*template.Template // layout-composed pages
}

// NewHandler builds the web UI. version is the server build version ("dev"
// for local builds); it is shown to signed-in users only.
func NewHandler(database *db.DB, sessions *auth.SessionManager, hostname, version string, e env.Env) *Handler {
	h := &Handler{
		db:       database,
		env:      e,
		sessions: sessions,
		hostname: strings.TrimRight(hostname, "/"),
		version:  version,
		pages:    map[string]*template.Template{},
	}
	funcs := template.FuncMap{
		"version": func() string { return h.version },
		"asset":   assetURL,
		"has":     func(list []string, s string) bool { return slices.Contains(list, s) },
		"secretOptions": func(e env.Env, selected string) map[string]any {
			return map[string]any{"Names": e.SecretNames(), "Selected": selected, "Set": e.Has(selected)}
		},
		// missingSecrets is for the layout's banner; signed-in pages only.
		"missingSecrets": func() []MissingSecret {
			missing, err := MissingSecrets(context.Background(), h.db, h.env)
			if err != nil {
				log.Printf("checking secrets: %v", err)
			}
			return missing
		},
	}
	h.login = template.Must(template.New("login.html").Funcs(funcs).ParseFS(templateFS, "templates/login.html"))
	// Partials some pages share.
	partials := map[string][]string{
		"handlers": {"templates/handler_form.html"},
		"handler":  {"templates/handler_form.html"},
		"guards":   {"templates/guard_form.html"},
		"guard":    {"templates/guard_form.html"},
	}
	for _, p := range []string{"hooks", "hook", "channels", "channel", "guards", "guard", "handlers", "handler", "apikeys"} {
		files := append([]string{"templates/layout.html", "templates/" + p + ".html"}, partials[p]...)
		h.pages[p] = template.Must(template.New("layout.html").Funcs(funcs).ParseFS(templateFS, files...))
	}
	return h
}

// assetDir holds the static files served at the root, e.g. /logo.svg.
const assetDir = "public"

// assetURL returns a static file's URL with a fingerprint of its content, so
// browsers fetch it again whenever it changes (favicons especially are cached
// hard). Fingerprints are computed once per file.
func assetURL(name string) string {
	assetMu.Lock()
	defer assetMu.Unlock()
	if v, ok := assetVersions[name]; ok {
		return v
	}
	u := "/" + name
	if b, err := os.ReadFile(filepath.Join(assetDir, name)); err == nil {
		sum := sha256.Sum256(b)
		u += "?v=" + hex.EncodeToString(sum[:4])
	}
	assetVersions[name] = u
	return u
}

var (
	assetMu       sync.Mutex
	assetVersions = map[string]string{}
)

// RegisterRoutes registers the dashboard's pages and form actions.
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /{$}", h.HooksPage)
	mux.HandleFunc("GET /{id}", h.HookPage)
	mux.HandleFunc("GET /keys", h.KeysPage)
	mux.HandleFunc("GET /guards", h.GuardsPage)
	mux.HandleFunc("POST /guards", h.createGuard)
	mux.HandleFunc("GET /guards/{name}", h.GuardPage)
	mux.HandleFunc("POST /guards/{name}", h.updateGuard)
	mux.HandleFunc("POST /guards/{name}/delete", h.deleteGuard)
	mux.HandleFunc("GET /channels", h.ChannelsPage)
	mux.HandleFunc("GET /channels/{name}", h.ChannelPage)
	mux.HandleFunc("POST /channels", h.createChannel)
	mux.HandleFunc("POST /channels/{name}/guards", h.setChannelGuards)
	mux.HandleFunc("POST /channels/{name}/handlers", h.setChannelHandlers)
	mux.HandleFunc("GET /handlers", h.HandlersPage)
	mux.HandleFunc("POST /handlers", h.createHandler)
	mux.HandleFunc("GET /handlers/{name}", h.HandlerPage)
	mux.HandleFunc("POST /handlers/{name}", h.updateHandler)
	mux.HandleFunc("POST /handlers/{name}/delete", h.deleteHandler)
	mux.HandleFunc("POST /channels/{name}/pause", h.pauseChannel)
	mux.HandleFunc("POST /channels/{name}/resume", h.resumeChannel)
	mux.HandleFunc("POST /channels/{name}/delete", h.deleteChannel)
	mux.HandleFunc("POST /hooks/{id}/handle", h.hookAction(db.StatusHandled))
	mux.HandleFunc("POST /hooks/{id}/discard", h.hookAction(db.StatusDiscarded))
	mux.HandleFunc("POST /hooks/{id}/retry", h.hookAction(db.StatusPending))
	mux.HandleFunc("POST /hooks/{id}/delete", h.deleteHook)
}

type layoutData struct {
	ActiveTab string
	Title     string
	User      *db.User
}

// Hooks

type field struct {
	Key   string
	Value string
}

// handlerSummary sums up a hook's handlers for the list: how many succeeded,
// and the overall state: failed if one gave up, pending while one is still
// running or retrying, succeeded otherwise.
type handlerSummary struct {
	State string
	Done  int
	Total int
	Title string // each handler and how it went, one per line
}

func summarizeHandlers(rows []hookHandlerRow) *handlerSummary {
	if len(rows) == 0 {
		return nil
	}
	s := &handlerSummary{State: db.AttemptSucceeded, Total: len(rows)}
	var lines []string
	for _, r := range rows {
		line := r.Handler + ": "
		switch {
		case r.Status == db.AttemptSucceeded:
			s.Done++
			line += "succeeded"
		case r.Status == db.AttemptFailed:
			s.State = db.AttemptFailed
			line += "gave up: " + r.LastError
		default:
			if s.State != db.AttemptFailed {
				s.State = db.AttemptPending
			}
			if r.NextAt != "" {
				line += "retry at " + r.NextAt + ": " + r.LastError
			} else {
				line += "running"
			}
		}
		lines = append(lines, line)
	}
	s.Title = strings.Join(lines, "\n")
	return s
}

type eventRow struct {
	At      string
	Kind    string // one of the db.Event* constants
	Actor   string
	Message string
}

type hookHandlerRow struct {
	Handler   string
	Status    string
	Attempts  int
	LastError string
	NextAt    string // when a pending attempt is tried next
	History   []attemptRow
}

type attemptRow struct {
	Date   string // when it was tried, split so phones can show just the time
	Time   string
	Code   int // the response code; 0 when there was none
	Error  string
	Output string // what a script logged
	MS     int64
}

type hookRow struct {
	Handlers       []hookHandlerRow
	ID             string
	Channel        string
	Status         string
	HandlerSummary *handlerSummary // nil without handlers
	Events         []eventRow      // newest first
	Method         string
	ContentType    string
	Payload        []field // decoded body; nil when the body isn't JSON or a form
	Body           string  // raw body as text; empty when binary or empty
	BodyNote       string  // shown instead of Body: "empty" or "binary, N bytes"
	Headers        []field
	IP             string
	UserAgent      string
	Referer        string
	CreatedAt      string
	CreatedISO     string
	Ago            string // CreatedAt relative to now, e.g. "5m ago"
	FinalizedAt    string // when handled or discarded; empty otherwise
	Summary        string // one line for the list: the first fields, or the body
	URL            string // its page, keeping the list's filters
}

type statusTab struct {
	Label  string
	Status string
	Count  int64
	URL    string
	Active bool
}

// statusTabs builds the status filter for a hooks list with stats; urlFor
// gives each status's link.
func statusTabs(stats db.ChannelStats, active string, urlFor func(status string) string) []statusTab {
	tabs := []statusTab{
		{Label: "All", Count: stats.Total()},
		{Label: "Pending", Status: db.StatusPending, Count: stats.Pending},
		{Label: "Handled", Status: db.StatusHandled, Count: stats.Handled},
		{Label: "Failed", Status: db.StatusFailed, Count: stats.Failed},
		{Label: "Discarded", Status: db.StatusDiscarded, Count: stats.Discarded},
	}
	for i := range tabs {
		tabs[i].URL = urlFor(tabs[i].Status)
		tabs[i].Active = tabs[i].Status == active
	}
	return tabs
}

type guardOption struct {
	Name    string
	Kind    string // e.g. "signature · stripe"
	Enabled bool
}

// guardKind describes a guard for display, e.g. "signature · hmac ·
// X-Hub-Signature-256 · sha256 hex".
func guardKind(g db.Guard) string {
	opts, _ := guard.ParseOptions(g.Options)
	return guard.Describe(g.Type, g.Scheme, opts)
}

// hmacSnippet is how to sign a curl request for an hmac guard.
type hmacSnippet struct {
	Header    string
	Algorithm string
	Base64    bool
	Prefix    string
}

type channelOption struct {
	Name     string
	Selected bool
}

type hooksData struct {
	layoutData
	Channels  []channelOption // for the channel filter
	Channel   string          // the selected channel; empty shows all
	Status    string          // the selected status; empty shows all
	Statuses  []statusTab
	HookURL   string // where hooks are sent
	Hooks     []hookRow
	Back      string // this page, for form actions to return to
	NewestURL string // first page; empty when on it
	NextURL   string // next (older) page; empty on the last page
}

const hooksPerPage = 50

// pageURL builds a hooks page URL for the given filters.
func pageURL(channel, status, after string) string {
	q := url.Values{}
	if channel != "" {
		q.Set("channel", channel)
	}
	if status != "" {
		q.Set("status", status)
	}
	if after != "" {
		q.Set("after", after)
	}
	if len(q) == 0 {
		return "/"
	}
	return "/?" + q.Encode()
}

// channelURL is a channel's dashboard page.
func channelURL(name string) string {
	return "/channels/" + url.PathEscape(name)
}

func (h *Handler) HooksPage(w http.ResponseWriter, r *http.Request) {
	user := h.requireUser(w, r)
	if user == nil {
		return
	}

	query := r.URL.Query()
	selected, status, after := query.Get("channel"), query.Get("status"), query.Get("after")
	if status != "" && !db.ValidStatus(status) {
		status = ""
	}

	channels, err := h.db.ListChannels(r.Context())
	if err != nil {
		log.Printf("listing channels: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	data := hooksData{
		layoutData: layoutData{ActiveTab: "hooks", Title: "Hooks", User: user},
		Channel:    selected,
		Status:     status,
		HookURL:    h.hookURL(""),
		Back:       pageURL(selected, status, after),
	}
	var stats db.ChannelStats
	found := selected == ""
	for _, c := range channels {
		data.Channels = append(data.Channels, channelOption{Name: c.Name, Selected: c.Name == selected})
		if selected == "" || c.Name == selected {
			stats.Pending += c.Stats.Pending
			stats.Handled += c.Stats.Handled
			stats.Failed += c.Stats.Failed
			stats.Discarded += c.Stats.Discarded
		}
		if c.Name == selected {
			found = true
		}
	}
	if !found {
		http.NotFound(w, r)
		return
	}
	data.Statuses = statusTabs(stats, status, func(st string) string { return pageURL(selected, st, "") })

	// Fetch one row beyond the page to learn whether an older page exists.
	hooks, err := h.db.ListHooks(r.Context(), db.HookFilter{Channel: selected, Status: status, After: after}, hooksPerPage+1)
	if err != nil {
		log.Printf("listing hooks: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if after != "" {
		data.NewestURL = pageURL(selected, status, "")
	}
	if len(hooks) > hooksPerPage {
		hooks = hooks[:hooksPerPage]
		data.NextURL = pageURL(selected, status, hooks[len(hooks)-1].ID)
	}
	ids := make([]string, len(hooks))
	for i, hk := range hooks {
		ids[i] = hk.ID
	}
	attempts, err := h.db.HookAttempts(r.Context(), ids)
	if err != nil {
		log.Printf("listing attempts: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	events, err := h.db.HookEvents(r.Context(), ids)
	if err != nil {
		log.Printf("listing events: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	for _, hk := range hooks {
		row := newHookRow(&hk)
		row.Handlers = hookHandlerRows(attempts[hk.ID])
		row.HandlerSummary = summarizeHandlers(row.Handlers)
		row.setEvents(events[hk.ID])
		row.URL = hookURL(hk.ID, selected, status)
		data.Hooks = append(data.Hooks, row)
	}
	h.render(w, "hooks", data)
}

// hookHandlerRows sums up a hook's tries per handler: its state is the
// latest try, and the tried ones are its history. dls is sorted by
// handler, oldest first.
func hookHandlerRows(dls []db.Attempt) []hookHandlerRow {
	var rows []hookHandlerRow
	for _, dl := range dls {
		if n := len(rows); n == 0 || rows[n-1].Handler != dl.Handler {
			rows = append(rows, hookHandlerRow{Handler: dl.Handler})
		}
		row := &rows[len(rows)-1]
		row.Status = dl.Status
		if dl.Status == db.AttemptPending {
			// A pending try after failed ones is a retry: say when.
			if row.Attempts > 0 {
				row.NextAt = dl.DueAt.Local().Format("15:04:05")
			}
			continue
		}
		row.NextAt = ""
		row.Attempts++
		row.LastError = dl.Error
		at := dl.CreatedAt
		if dl.FinishedAt != nil {
			at = *dl.FinishedAt
		}
		row.History = append(row.History, attemptRow{Date: at.Local().Format(time.DateOnly), Time: at.Local().Format(time.TimeOnly), Code: dl.Code, Error: dl.Error, Output: dl.Output, MS: dl.MS})
	}
	return rows
}

// hookURL is a hook's page, at /{id}, keeping the list's filters for its
// back link and its newer and older links.
func hookURL(id, channel, status string) string {
	q := url.Values{}
	if channel != "" {
		q.Set("channel", channel)
	}
	if status != "" {
		q.Set("status", status)
	}
	if len(q) == 0 {
		return "/" + id
	}
	return "/" + id + "?" + q.Encode()
}

type hookData struct {
	layoutData
	Hook       hookRow
	Back       string // this page, for form actions to return to
	ListURL    string // the list it was opened from
	FilterNote string // the list's filters, e.g. "#contact · failed"
	NewerURL   string // the next newer hook in that list; empty when none
	OlderURL   string
}

// HookPage shows one hook at /{id}. ?channel= and ?status= are the list it
// was opened from, which its newer and older links step through.
func (h *Handler) HookPage(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !db.ValidID(id) {
		http.NotFound(w, r)
		return
	}
	user := h.requireUser(w, r)
	if user == nil {
		return
	}
	hk, err := h.db.GetHook(r.Context(), id)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			http.NotFound(w, r)
			return
		}
		h.dbError(w, r, "getting hook", err)
		return
	}
	query := r.URL.Query()
	channel, status := query.Get("channel"), query.Get("status")
	if status != "" && !db.ValidStatus(status) {
		status = ""
	}

	attempts, err := h.db.HookAttempts(r.Context(), []string{id})
	if err != nil {
		h.dbError(w, r, "listing attempts", err)
		return
	}
	events, err := h.db.HookEvents(r.Context(), []string{id})
	if err != nil {
		h.dbError(w, r, "listing events", err)
		return
	}
	row := newHookRow(hk)
	row.Handlers = hookHandlerRows(attempts[id])
	row.setEvents(events[id])
	data := hookData{
		layoutData: layoutData{ActiveTab: "hooks", Title: "Hook " + id, User: user},
		Hook:       row,
		Back:       hookURL(id, channel, status),
		ListURL:    pageURL(channel, status, ""),
	}
	var note []string
	if channel != "" {
		note = append(note, "#"+channel)
	}
	if status != "" {
		note = append(note, status)
	}
	data.FilterNote = strings.Join(note, " · ")

	filter := db.HookFilter{Channel: channel, Status: status}
	newer, older := filter, filter
	newer.Before, older.After = id, id
	if hs, err := h.db.ListHooks(r.Context(), newer, 1); err == nil && len(hs) > 0 {
		data.NewerURL = hookURL(hs[0].ID, channel, status)
	}
	if hs, err := h.db.ListHooks(r.Context(), older, 1); err == nil && len(hs) > 0 {
		data.OlderURL = hookURL(hs[0].ID, channel, status)
	}
	h.render(w, "hook", data)
}

// Channels

type channelRow struct {
	Name   string
	URL    string // its dashboard page
	Paused bool
	Guards []string
	Stats  db.ChannelStats
}

type channelsData struct {
	layoutData
	Channels []channelRow
	HookURL  string
	Error    string
}

func (h *Handler) ChannelsPage(w http.ResponseWriter, r *http.Request) {
	user := h.requireUser(w, r)
	if user == nil {
		return
	}
	channels, err := h.db.ListChannels(r.Context())
	if err != nil {
		log.Printf("listing channels: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	data := channelsData{
		layoutData: layoutData{ActiveTab: "channels", Title: "Channels", User: user},
		HookURL:    h.hookURL(""),
		Error:      r.URL.Query().Get("error"),
	}
	for _, c := range channels {
		data.Channels = append(data.Channels, channelRow{
			Name:   c.Name,
			URL:    channelURL(c.Name),
			Paused: c.Paused(),
			Guards: c.Guards,
			Stats:  c.Stats,
		})
	}
	h.render(w, "channels", data)
}

type channelData struct {
	layoutData
	Channel  *db.Channel
	HookURL  string // where to send hooks to this channel
	HooksURL string // the hooks page filtered to it
	Statuses []statusTab
	Guards   []guardOption
	Honeypot string
	Handlers []guardOption // reuses guardOption: name, summary, attached
	Captcha  string        // the captcha scheme the channel requires, if any
	HMAC     *hmacSnippet  // set when the channel requires an hmac signature
}

func (h *Handler) ChannelPage(w http.ResponseWriter, r *http.Request) {
	user := h.requireUser(w, r)
	if user == nil {
		return
	}
	c, err := h.db.GetChannel(r.Context(), r.PathValue("name"))
	if err != nil {
		h.dbError(w, r, "getting channel", err)
		return
	}
	guards, err := h.db.ListGuards(r.Context())
	if err != nil {
		log.Printf("listing guards: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	data := channelData{
		layoutData: layoutData{ActiveTab: "channels", Title: c.Name, User: user},
		Channel:    c,
		HookURL:    h.hookURL(c.Name),
		HooksURL:   pageURL(c.Name, "", ""),
		Honeypot:   payload.HoneypotField,
	}
	data.Statuses = statusTabs(c.Stats, "-", func(st string) string { return pageURL(c.Name, st, "") })
	for _, g := range guards {
		enabled := slices.Contains(c.Guards, g.Name)
		data.Guards = append(data.Guards, guardOption{Name: g.Name, Kind: guardKind(g), Enabled: enabled})
		if enabled && g.Type == guard.Honeypot && data.Honeypot == payload.HoneypotField {
			if opts, _ := guard.ParseOptions(g.Options); opts.Field != "" {
				data.Honeypot = opts.Field
			}
		}
		if enabled && g.Type == guard.Captcha && data.Captcha == "" {
			data.Captcha = g.Scheme
		}
		if enabled && g.Type == guard.Signature && g.Scheme == guard.HMAC && data.HMAC == nil {
			opts, _ := guard.ParseOptions(g.Options)
			data.HMAC = &hmacSnippet{Header: opts.Header, Algorithm: opts.Algorithm, Base64: opts.Encoding == "base64", Prefix: opts.Prefix}
		}
	}
	dsts, err := h.db.ListHandlers(r.Context())
	if err != nil {
		log.Printf("listing handlers: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	for _, dst := range dsts {
		opts, _ := handler.ParseOptions(dst.Options)
		data.Handlers = append(data.Handlers, guardOption{
			Name:    dst.Name,
			Kind:    handler.Describe(dst.Type, opts),
			Enabled: slices.Contains(dst.Channels, c.Name),
		})
	}
	h.render(w, "channel", data)
}

// setEvents adds a hook's events, oldest first, as its activity, newest
// first.
func (row *hookRow) setEvents(events []db.Event) {
	for i := len(events) - 1; i >= 0; i-- {
		e := events[i]
		row.Events = append(row.Events, eventRow{At: e.CreatedAt.Local().Format(time.DateTime), Kind: e.Kind, Actor: e.Actor, Message: e.Message})
	}
}

func newHookRow(hk *db.Hook) hookRow {
	row := hookRow{
		ID:          hk.ID,
		Channel:     hk.Channel,
		Status:      hk.Status,
		Method:      hk.Method,
		ContentType: hk.ContentType,
		IP:          hk.IP,
		UserAgent:   hk.Headers["User-Agent"],
		Referer:     hk.Headers["Referer"],
		CreatedAt:   hk.CreatedAt.Local().Format(time.DateTime),
		CreatedISO:  hk.CreatedAt.UTC().Format(time.RFC3339),
		Ago:         ago(hk.CreatedAt, time.Now()),
	}
	if hk.FinalizedAt != nil {
		row.FinalizedAt = hk.FinalizedAt.Local().Format(time.DateTime)
	}
	if data := payload.Decode(hk.ContentType, hk.Body); data != nil {
		row.Payload = fields(data)
	}
	switch {
	case len(hk.Body) == 0:
		row.BodyNote = "empty"
	case utf8.Valid(hk.Body):
		row.Body = string(hk.Body)
	default:
		row.BodyNote = fmt.Sprintf("binary, %d bytes", len(hk.Body))
	}
	row.Summary = summary(row.Payload, row.Body)
	for k, v := range hk.Headers {
		row.Headers = append(row.Headers, field{Key: k, Value: v})
	}
	slices.SortFunc(row.Headers, func(a, b field) int { return strings.Compare(a.Key, b.Key) })
	return row
}

// fields flattens a hook's payload into display rows, sorted by key.
// summary is a hook on one line: its first field values, or the start of its
// body.
func summary(payload []field, body string) string {
	var parts []string
	for _, f := range payload {
		if v := strings.TrimSpace(f.Value); v != "" {
			parts = append(parts, v)
		}
		if len(parts) == 4 {
			break
		}
	}
	s := strings.Join(parts, " · ")
	if payload == nil {
		s = body
	}
	s = strings.Join(strings.Fields(s), " ")
	if r := []rune(s); len(r) > 200 {
		s = string(r[:200]) + "…"
	}
	return s
}

// ago says how long before now t was, briefly: "just now", "5m ago",
// "3h ago", "2d ago", then the date.
func ago(t, now time.Time) string {
	d := now.Sub(t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	case d < 7*24*time.Hour:
		return fmt.Sprintf("%dd ago", int(d.Hours()/24))
	case t.Year() == now.Year():
		return t.Local().Format("Jan 2")
	default:
		return t.Local().Format("Jan 2, 2006")
	}
}

func fields(data map[string]any) []field {
	keys := make([]string, 0, len(data))
	for k := range data {
		keys = append(keys, k)
	}
	slices.Sort(keys)

	out := make([]field, 0, len(keys))
	for _, k := range keys {
		out = append(out, field{Key: k, Value: displayValue(data[k])})
	}
	return out
}

func displayValue(v any) string {
	switch v := v.(type) {
	case string:
		return v
	case []any:
		parts := make([]string, len(v))
		for i, p := range v {
			parts[i] = displayValue(p)
		}
		return strings.Join(parts, ", ")
	default:
		b, _ := json.Marshal(v)
		return string(b)
	}
}

// backURL returns the form's "back" field when it is a dashboard path, else
// fallback.
func backURL(r *http.Request, fallback string) string {
	back := r.FormValue("back")
	if !strings.HasPrefix(back, "/") || strings.HasPrefix(back, "//") || strings.HasPrefix(back, "/\\") {
		return fallback
	}
	return back
}

func (h *Handler) createChannel(w http.ResponseWriter, r *http.Request) {
	user := h.requireUser(w, r)
	if user == nil {
		return
	}
	name := strings.ToLower(strings.TrimSpace(r.FormValue("name")))
	if !db.ValidChannel(name) {
		http.Redirect(w, r, "/channels?error="+url.QueryEscape("Channel names are up to 64 lowercase letters and digits, separated by single _ or -."), http.StatusSeeOther)
		return
	}
	if err := h.db.EnsureChannel(r.Context(), name); err != nil {
		h.dbError(w, r, "creating channel", err)
		return
	}
	http.Redirect(w, r, channelURL(name), http.StatusSeeOther)
}

func (h *Handler) setChannelHandlers(w http.ResponseWriter, r *http.Request) {
	user := h.requireUser(w, r)
	if user == nil {
		return
	}
	name := r.PathValue("name")
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	if err := h.db.SetChannelHandlers(r.Context(), name, r.Form["handler"]); err != nil {
		h.dbError(w, r, "setting channel handlers", err)
		return
	}
	http.Redirect(w, r, channelURL(name), http.StatusSeeOther)
}

func (h *Handler) setChannelGuards(w http.ResponseWriter, r *http.Request) {
	user := h.requireUser(w, r)
	if user == nil {
		return
	}
	name := r.PathValue("name")
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	if _, err := h.db.SetChannelGuards(r.Context(), name, r.Form["guard"]); err != nil {
		h.dbError(w, r, "setting channel guards", err)
		return
	}
	http.Redirect(w, r, channelURL(name), http.StatusSeeOther)
}

func (h *Handler) pauseChannel(w http.ResponseWriter, r *http.Request) {
	h.setChannelPaused(w, r, true)
}

func (h *Handler) resumeChannel(w http.ResponseWriter, r *http.Request) {
	h.setChannelPaused(w, r, false)
}

func (h *Handler) setChannelPaused(w http.ResponseWriter, r *http.Request, paused bool) {
	user := h.requireUser(w, r)
	if user == nil {
		return
	}
	name := r.PathValue("name")
	if _, err := h.db.SetChannelPaused(r.Context(), name, paused); err != nil {
		h.dbError(w, r, "pausing channel", err)
		return
	}
	http.Redirect(w, r, backURL(r, channelURL(name)), http.StatusSeeOther)
}

func (h *Handler) deleteChannel(w http.ResponseWriter, r *http.Request) {
	user := h.requireUser(w, r)
	if user == nil {
		return
	}
	if err := h.db.DeleteChannel(r.Context(), r.PathValue("name")); err != nil {
		h.dbError(w, r, "deleting channel", err)
		return
	}
	http.Redirect(w, r, "/channels", http.StatusSeeOther)
}

// hookAction handles a dashboard button that moves a hook to status.
func (h *Handler) hookAction(status string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := h.requireUser(w, r)
		if user == nil {
			return
		}
		if _, err := h.db.SetHookStatus(r.Context(), r.PathValue("id"), status, user.Email, ""); err != nil {
			h.dbError(w, r, "updating hook", err)
			return
		}
		http.Redirect(w, r, backURL(r, "/"), http.StatusSeeOther)
	}
}

func (h *Handler) deleteHook(w http.ResponseWriter, r *http.Request) {
	user := h.requireUser(w, r)
	if user == nil {
		return
	}
	if err := h.db.DeleteHook(r.Context(), r.PathValue("id")); err != nil {
		h.dbError(w, r, "deleting hook", err)
		return
	}
	http.Redirect(w, r, backURL(r, "/"), http.StatusSeeOther)
}

// Guards

type guardRow struct {
	Name      string
	Type      string
	Kind      string
	Secret    string // the secret's name
	SecretSet bool   // whether it's set in the environment
	Channels  []string
	CreatedAt string
}

type guardsData struct {
	layoutData
	Guards     []guardRow
	Presets    []guard.PresetGroup
	Types      []string
	Schemes    map[string][]string // by type, for types that have schemes
	Algorithms []string
	Encodings  []string
	Error      string    // a failed action; for Create guard, shown in its form
	Form       guardForm // Create guard input to restore after a failed create
	Env        env.Env
	Editing    bool // the form edits Form.Name; false for Create
}

// guardData is a guard's own page: its settings to edit, its channels, and
// Delete. It embeds guardsData for the form's choices.
type guardData struct {
	guardsData
	Kind     string
	Channels []string
	Saved    bool
}

// guardForm is the Create guard form's input, kept when creating fails so the
// form is refilled as it was.
type guardForm struct {
	Restore   bool // refill the form
	Preset    string
	Name      string
	Secret    string // the secret's name
	Type      string
	Scheme    string
	Field     string
	Header    string
	Algorithm string
	Encoding  string
	Prefix    string
	MinScore  string
}

func (h *Handler) GuardsPage(w http.ResponseWriter, r *http.Request) {
	user := h.requireUser(w, r)
	if user == nil {
		return
	}
	h.renderGuards(w, r, user, r.URL.Query().Get("error"), guardForm{})
}

func (h *Handler) renderGuards(w http.ResponseWriter, r *http.Request, user *db.User, errMsg string, form guardForm) {
	guards, err := h.db.ListGuards(r.Context())
	if err != nil {
		log.Printf("listing guards: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	data := guardsData{
		layoutData: layoutData{ActiveTab: "guards", Title: "Guards", User: user},
		Env:        h.env,
		Presets:    guard.PresetGroups(),
		Types:      guard.Types,
		Schemes:    map[string][]string{guard.Captcha: guard.CaptchaSchemes, guard.Signature: guard.Schemes},
		Algorithms: guard.Algorithms,
		Encodings:  guard.Encodings,
		Error:      errMsg,
		Form:       form,
	}
	for _, g := range guards {
		data.Guards = append(data.Guards, guardRow{
			Name:      g.Name,
			Type:      g.Type,
			Kind:      guardKind(g),
			Secret:    g.Secret,
			SecretSet: h.env.Has(g.Secret),
			Channels:  g.Channels,
			CreatedAt: g.CreatedAt.Local().Format("2006-01-02 15:04"),
		})
	}
	if form.Restore {
		w.WriteHeader(http.StatusUnprocessableEntity)
	}
	h.render(w, "guards", data)
}

func (h *Handler) createGuard(w http.ResponseWriter, r *http.Request) {
	user := h.requireUser(w, r)
	if user == nil {
		return
	}
	form := readGuardForm(r)
	form.Name = strings.ToLower(strings.TrimSpace(r.FormValue("name")))
	// Failures refill the form with what was entered.
	fail := func(msg string) { h.renderGuards(w, r, user, msg, form) }
	if !db.ValidChannel(form.Name) {
		fail("Guard names are up to 64 lowercase letters and digits, separated by single _ or -.")
		return
	}
	g, msg := validateGuardForm(form)
	if msg != "" {
		fail(msg)
		return
	}
	if _, err := h.db.CreateGuard(r.Context(), g); err != nil {
		if strings.Contains(err.Error(), "already exists") {
			fail("A guard named " + form.Name + " already exists.")
			return
		}
		h.dbError(w, r, "creating guard", err)
		return
	}
	http.Redirect(w, r, "/guards", http.StatusSeeOther)
}

// readGuardForm reads the guard form's fields, except the name.
func readGuardForm(r *http.Request) guardForm {
	return guardForm{
		Restore:   true,
		Preset:    r.FormValue("preset"),
		Secret:    strings.TrimSpace(r.FormValue("secret")),
		Type:      r.FormValue("type"),
		Scheme:    r.FormValue("scheme"),
		Field:     strings.TrimSpace(r.FormValue("field")),
		Header:    strings.TrimSpace(r.FormValue("header")),
		Algorithm: r.FormValue("algorithm"),
		Encoding:  r.FormValue("encoding"),
		Prefix:    r.FormValue("prefix"),
		MinScore:  strings.TrimSpace(r.FormValue("min_score")),
	}
}

// validateGuardForm checks the form and returns the guard it describes, or a
// message saying what's wrong.
func validateGuardForm(form guardForm) (db.Guard, string) {
	typ, scheme, secret := form.Type, form.Scheme, form.Secret
	if secret != "" && !env.ValidName(secret) {
		return db.Guard{}, "Secret names are letters, digits, and _."
	}
	if typ != guard.Signature && typ != guard.Captcha {
		scheme = ""
	}
	var minScore float64
	if form.MinScore != "" {
		f, err := strconv.ParseFloat(form.MinScore, 64)
		if err != nil {
			return db.Guard{}, "The minimum score must be a number between 0 and 1."
		}
		minScore = f
	}
	opts, err := guard.Validate(typ, scheme, secret, guard.Options{
		Field:     form.Field,
		Header:    form.Header,
		Algorithm: form.Algorithm,
		Encoding:  form.Encoding,
		Prefix:    form.Prefix,
		MinScore:  minScore,
	})
	if err != nil {
		msg := err.Error()
		return db.Guard{}, strings.ToUpper(msg[:1]) + msg[1:] + "."
	}
	return db.Guard{Name: form.Name, Type: typ, Scheme: scheme, Options: opts.JSON(), Secret: secret}, ""
}

func (h *Handler) GuardPage(w http.ResponseWriter, r *http.Request) {
	user := h.requireUser(w, r)
	if user == nil {
		return
	}
	h.renderGuard(w, r, user, nil, r.URL.Query().Get("error"))
}

// renderGuard shows a guard's page; a non-nil form is input to keep after a
// failed save.
func (h *Handler) renderGuard(w http.ResponseWriter, r *http.Request, user *db.User, form *guardForm, errMsg string) {
	g, err := h.db.GetGuard(r.Context(), r.PathValue("name"))
	if err != nil {
		h.dbError(w, r, "getting guard", err)
		return
	}
	data := guardData{
		guardsData: guardsData{
			layoutData: layoutData{ActiveTab: "guards", Title: g.Name, User: user},
			Env:        h.env,
			Types:      guard.Types,
			Schemes:    map[string][]string{guard.Captcha: guard.CaptchaSchemes, guard.Signature: guard.Schemes},
			Algorithms: guard.Algorithms,
			Encodings:  guard.Encodings,
			Error:      errMsg,
			Editing:    true,
		},
		Kind:     guardKind(*g),
		Channels: g.Channels,
		Saved:    r.URL.Query().Has("saved"),
	}
	if form != nil {
		data.Form = *form
	} else {
		opts, _ := guard.ParseOptions(g.Options)
		data.Form = guardForm{Type: g.Type, Scheme: g.Scheme, Secret: g.Secret, Field: opts.Field, Header: opts.Header,
			Algorithm: opts.Algorithm, Encoding: opts.Encoding, Prefix: opts.Prefix}
		if opts.MinScore != 0 {
			data.Form.MinScore = strconv.FormatFloat(opts.MinScore, 'f', -1, 64)
		}
	}
	data.Form.Name = g.Name
	if form != nil {
		w.WriteHeader(http.StatusUnprocessableEntity)
	}
	h.render(w, "guard", data)
}

func (h *Handler) updateGuard(w http.ResponseWriter, r *http.Request) {
	user := h.requireUser(w, r)
	if user == nil {
		return
	}
	name := r.PathValue("name")
	form := readGuardForm(r)
	form.Name = name
	g, msg := validateGuardForm(form)
	if msg != "" {
		h.renderGuard(w, r, user, &form, msg)
		return
	}
	if _, err := h.db.UpdateGuard(r.Context(), g); err != nil {
		h.dbError(w, r, "updating guard", err)
		return
	}
	http.Redirect(w, r, "/guards/"+url.PathEscape(name)+"?saved", http.StatusSeeOther)
}

func (h *Handler) deleteGuard(w http.ResponseWriter, r *http.Request) {
	user := h.requireUser(w, r)
	if user == nil {
		return
	}
	if err := h.db.DeleteGuard(r.Context(), r.PathValue("name")); err != nil {
		if errors.Is(err, db.ErrGuardInUse) {
			http.Redirect(w, r, "/guards/"+url.PathEscape(r.PathValue("name"))+"?error="+url.QueryEscape("Detach it from its channels before deleting it."), http.StatusSeeOther)
			return
		}
		h.dbError(w, r, "deleting guard", err)
		return
	}
	http.Redirect(w, r, "/guards", http.StatusSeeOther)
}

// Handlers

type handlerRow struct {
	Name     string
	Type     string
	Target   string   // what it does, e.g. "POST api.resend.com" or "3 lines"
	Secrets  []string // names of the secrets it uses
	Missing  []string // those not set in the environment
	Channels []string
	Last     *lastAttempt // its latest finished attempt; nil if it never ran
}

type lastAttempt struct {
	Status string
	Error  string
	At     string
	Ago    string
	HookID string
}

func newLastAttempt(a db.Attempt) *lastAttempt {
	at := a.CreatedAt
	if a.FinishedAt != nil {
		at = *a.FinishedAt
	}
	return &lastAttempt{Status: a.Status, Error: a.Error, At: at.Local().Format(time.DateTime), Ago: ago(at, time.Now()), HookID: a.HookID}
}

type handlersData struct {
	layoutData
	Handlers []handlerRow
	Presets  []handler.PresetGroup
	Types    []string
	Error    string
	Form     handlerForm
	Env      env.Env
	Editing  bool // the form edits Form.Name; false for Create
}

// handlerForm is the Create handler form's input, kept when creating
// fails.
type handlerForm struct {
	Restore     bool
	Preset      string
	Name        string
	Type        string
	Method      string
	URL         string
	Headers     string
	ContentType string
	SignWith    string
	Body        string
	Script      string
}

func (h *Handler) HandlersPage(w http.ResponseWriter, r *http.Request) {
	user := h.requireUser(w, r)
	if user == nil {
		return
	}
	h.renderHandlers(w, r, user, r.URL.Query().Get("error"), handlerForm{})
}

func (h *Handler) renderHandlers(w http.ResponseWriter, r *http.Request, user *db.User, errMsg string, form handlerForm) {
	dsts, err := h.db.ListHandlers(r.Context())
	if err != nil {
		log.Printf("listing handlers: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	data := handlersData{
		layoutData: layoutData{ActiveTab: "handlers", Title: "Handlers", User: user},
		Env:        h.env,
		Presets:    handler.PresetGroups(),
		Types:      handler.Types,
		Error:      errMsg,
		Form:       form,
	}
	last, err := h.db.LastAttempts(r.Context())
	if err != nil {
		log.Printf("listing last attempts: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	for _, dst := range dsts {
		opts, _ := handler.ParseOptions(dst.Options)
		row := handlerRow{
			Name:     dst.Name,
			Type:     dst.Type,
			Target:   handler.Target(dst.Type, opts),
			Secrets:  handler.SecretsUsed(opts),
			Channels: dst.Channels,
		}
		if a, ok := last[dst.Name]; ok {
			row.Last = newLastAttempt(a)
		}
		for _, name := range row.Secrets {
			if _, ok := h.env.Secrets[name]; !ok {
				row.Missing = append(row.Missing, name)
			}
		}
		data.Handlers = append(data.Handlers, row)
	}
	if form.Restore {
		w.WriteHeader(http.StatusUnprocessableEntity)
	}
	h.render(w, "handlers", data)
}

func (h *Handler) createHandler(w http.ResponseWriter, r *http.Request) {
	user := h.requireUser(w, r)
	if user == nil {
		return
	}
	form := readHandlerForm(r)
	form.Name = strings.ToLower(strings.TrimSpace(r.FormValue("name")))
	fail := func(msg string) { h.renderHandlers(w, r, user, msg, form) }
	if !db.ValidChannel(form.Name) {
		fail("Handler names are up to 64 lowercase letters and digits, separated by single _ or -.")
		return
	}
	opts, msg := h.validateHandlerForm(form)
	if msg != "" {
		fail(msg)
		return
	}
	dst := db.Handler{Name: form.Name, Type: form.Type, Options: opts.JSON()}
	if _, err := h.db.CreateHandler(r.Context(), dst); err != nil {
		if strings.Contains(err.Error(), "already exists") {
			fail("A handler named " + form.Name + " already exists.")
			return
		}
		h.dbError(w, r, "creating handler", err)
		return
	}
	http.Redirect(w, r, "/handlers", http.StatusSeeOther)
}

// readHandlerForm reads the handler form's fields, except the name.
func readHandlerForm(r *http.Request) handlerForm {
	return handlerForm{
		Restore:     true,
		Preset:      r.FormValue("preset"),
		Type:        r.FormValue("type"),
		Method:      r.FormValue("method"),
		URL:         strings.TrimSpace(r.FormValue("url")),
		Headers:     r.FormValue("headers"),
		ContentType: strings.TrimSpace(r.FormValue("content_type")),
		SignWith:    strings.TrimSpace(r.FormValue("sign_with")),
		Body:        r.FormValue("body"),
		Script:      r.FormValue("script"),
	}
}

// validateHandlerForm checks the form's settings and returns them, or a
// message saying what's wrong.
func (h *Handler) validateHandlerForm(form handlerForm) (handler.Options, string) {
	if form.SignWith != "" && !env.ValidName(form.SignWith) {
		return handler.Options{}, "Secret names are letters, digits, and _."
	}
	opts, err := handler.Validate(form.Type, handler.Options{
		Method: form.Method, URL: form.URL, Headers: form.Headers, ContentType: form.ContentType, SignWith: form.SignWith, Body: form.Body, Script: form.Script,
	}, h.env)
	if err != nil {
		msg := err.Error()
		return handler.Options{}, strings.ToUpper(msg[:1]) + msg[1:] + "."
	}
	return opts, ""
}

// handlerData is a handler's own page: its settings to edit, its channels,
// its last attempt, and Delete.
type handlerData struct {
	layoutData
	Form     handlerForm
	Type     string // as saved
	Types    []string
	Env      env.Env
	Editing  bool
	Channels []string
	Last     *lastAttempt
	Error    string
	Saved    bool
}

func (h *Handler) HandlerPage(w http.ResponseWriter, r *http.Request) {
	user := h.requireUser(w, r)
	if user == nil {
		return
	}
	h.renderHandler(w, r, user, nil, r.URL.Query().Get("error"))
}

// renderHandler shows a handler's page; a non-nil form is input to keep
// after a failed save.
func (h *Handler) renderHandler(w http.ResponseWriter, r *http.Request, user *db.User, form *handlerForm, errMsg string) {
	dst, err := h.db.GetHandler(r.Context(), r.PathValue("name"))
	if err != nil {
		h.dbError(w, r, "getting handler", err)
		return
	}
	data := handlerData{
		layoutData: layoutData{ActiveTab: "handlers", Title: dst.Name, User: user},
		Type:       dst.Type,
		Types:      handler.Types,
		Env:        h.env,
		Editing:    true,
		Channels:   dst.Channels,
		Error:      errMsg,
		Saved:      r.URL.Query().Has("saved"),
	}
	if form != nil {
		data.Form = *form
	} else {
		opts, _ := handler.ParseOptions(dst.Options)
		data.Form = handlerForm{Type: dst.Type, Method: opts.Method, URL: opts.URL, Headers: opts.Headers, ContentType: opts.ContentType,
			SignWith: opts.SignWith, Body: opts.Body, Script: opts.Script}
	}
	data.Form.Name = dst.Name
	last, err := h.db.LastAttempts(r.Context())
	if err != nil {
		h.dbError(w, r, "listing last attempts", err)
		return
	}
	if a, ok := last[dst.Name]; ok {
		data.Last = newLastAttempt(a)
	}
	if form != nil {
		w.WriteHeader(http.StatusUnprocessableEntity)
	}
	h.render(w, "handler", data)
}

func (h *Handler) updateHandler(w http.ResponseWriter, r *http.Request) {
	user := h.requireUser(w, r)
	if user == nil {
		return
	}
	name := r.PathValue("name")
	form := readHandlerForm(r)
	opts, msg := h.validateHandlerForm(form)
	if msg != "" {
		h.renderHandler(w, r, user, &form, msg)
		return
	}
	if _, err := h.db.UpdateHandler(r.Context(), db.Handler{Name: name, Type: form.Type, Options: opts.JSON()}); err != nil {
		h.dbError(w, r, "updating handler", err)
		return
	}
	http.Redirect(w, r, "/handlers/"+url.PathEscape(name)+"?saved", http.StatusSeeOther)
}

func (h *Handler) deleteHandler(w http.ResponseWriter, r *http.Request) {
	user := h.requireUser(w, r)
	if user == nil {
		return
	}
	if err := h.db.DeleteHandler(r.Context(), r.PathValue("name")); err != nil {
		if errors.Is(err, db.ErrHandlerInUse) {
			http.Redirect(w, r, "/handlers/"+url.PathEscape(r.PathValue("name"))+"?error="+url.QueryEscape("Detach it from its channels before deleting it."), http.StatusSeeOther)
			return
		}
		h.dbError(w, r, "deleting handler", err)
		return
	}
	http.Redirect(w, r, "/handlers", http.StatusSeeOther)
}

// API keys

type keyRow struct {
	ID        string
	Label     string
	Prefix    string
	CreatedAt string
}

type keysData struct {
	layoutData
	Keys []keyRow
}

func (h *Handler) KeysPage(w http.ResponseWriter, r *http.Request) {
	user := h.requireUser(w, r)
	if user == nil {
		return
	}

	keys, err := h.db.ListAPIKeys(r.Context(), user.ID)
	if err != nil {
		log.Printf("listing keys: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	data := keysData{layoutData: layoutData{ActiveTab: "keys", Title: "API Keys", User: user}}
	for _, k := range keys {
		data.Keys = append(data.Keys, keyRow{
			ID:        k.ID,
			Label:     k.Label,
			Prefix:    k.KeyPrefix,
			CreatedAt: k.CreatedAt.Local().Format(time.DateTime),
		})
	}
	h.render(w, "apikeys", data)
}

// Helpers

// hookURL is where to send hooks for channel; empty means the default.
func (h *Handler) hookURL(channel string) string {
	if channel == "" || channel == db.DefaultChannel {
		return h.hostname + "/"
	}
	return h.hostname + "/?channel=" + url.QueryEscape(channel)
}

func (h *Handler) dbError(w http.ResponseWriter, r *http.Request, action string, err error) {
	if strings.Contains(err.Error(), "not found") {
		http.NotFound(w, r)
		return
	}
	log.Printf("%s: %v", action, err)
	http.Error(w, "internal error", http.StatusInternalServerError)
}

func (h *Handler) requireUser(w http.ResponseWriter, r *http.Request) *db.User {
	userID, ok := h.sessions.GetUserID(r)
	if !ok {
		if r.Method != http.MethodGet {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return nil
		}
		h.renderStandalone(w, "login.html", nil)
		return nil
	}

	user, err := h.db.GetUserByID(r.Context(), userID)
	if err != nil {
		h.sessions.ClearSession(w)
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return nil
	}
	return user
}

func (h *Handler) render(w http.ResponseWriter, name string, data any) {
	t, ok := h.pages[name]
	if !ok {
		http.Error(w, "unknown page", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := t.ExecuteTemplate(w, "layout.html", data); err != nil {
		log.Printf("rendering %s: %v", name, err)
	}
}

func (h *Handler) renderStandalone(w http.ResponseWriter, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.login.ExecuteTemplate(w, name, data); err != nil {
		log.Printf("rendering %s: %v", name, err)
	}
}
