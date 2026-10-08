package web

import (
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
	"github.com/catchysh/catchy/internal/guard"
	"github.com/catchysh/catchy/internal/payload"
)

//go:embed templates/*.html
var templateFS embed.FS

type Handler struct {
	db       *db.DB
	sessions *auth.SessionManager
	hostname string
	version  string
	login    *template.Template            // standalone pages
	pages    map[string]*template.Template // layout-composed pages
}

// NewHandler builds the web UI. version is the server build version ("dev"
// for local builds); it is shown to signed-in users only.
func NewHandler(database *db.DB, sessions *auth.SessionManager, hostname, version string) *Handler {
	h := &Handler{
		db:       database,
		sessions: sessions,
		hostname: strings.TrimRight(hostname, "/"),
		version:  version,
		pages:    map[string]*template.Template{},
	}
	funcs := template.FuncMap{
		"version": func() string { return h.version },
		"asset":   assetURL,
	}
	h.login = template.Must(template.New("login.html").Funcs(funcs).ParseFS(templateFS, "templates/login.html"))
	for _, p := range []string{"hooks", "channels", "channel", "guards", "apikeys"} {
		h.pages[p] = template.Must(template.New("layout.html").Funcs(funcs).ParseFS(
			templateFS,
			"templates/layout.html",
			"templates/"+p+".html",
		))
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
	mux.HandleFunc("GET /keys", h.KeysPage)
	mux.HandleFunc("GET /guards", h.GuardsPage)
	mux.HandleFunc("POST /guards", h.createGuard)
	mux.HandleFunc("POST /guards/{name}/secret", h.rotateGuardSecret)
	mux.HandleFunc("POST /guards/{name}/delete", h.deleteGuard)
	mux.HandleFunc("GET /channels", h.ChannelsPage)
	mux.HandleFunc("GET /channels/{name}", h.ChannelPage)
	mux.HandleFunc("POST /channels", h.createChannel)
	mux.HandleFunc("POST /channels/{name}/guards", h.setChannelGuards)
	mux.HandleFunc("POST /channels/{name}/pause", h.pauseChannel)
	mux.HandleFunc("POST /channels/{name}/resume", h.resumeChannel)
	mux.HandleFunc("POST /channels/{name}/delete", h.deleteChannel)
	mux.HandleFunc("POST /hooks/{id}/process", h.hookAction(db.StatusProcessed))
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

type failureRow struct {
	At      string
	Message string
}

type hookRow struct {
	ID          string
	Channel     string
	Status      string
	Failures    []failureRow // oldest first
	LastFailure *failureRow
	Method      string
	ContentType string
	Payload     []field // decoded body; nil when the body isn't JSON or a form
	Body        string  // raw body as text; empty when binary or empty
	BodyNote    string  // shown instead of Body: "empty" or "binary, N bytes"
	Headers     []field
	IP          string
	UserAgent   string
	Referer     string
	CreatedAt   string
	FinalizedAt string // when processed or discarded; empty otherwise
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
		{Label: "Processed", Status: db.StatusProcessed, Count: stats.Processed},
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

const hooksPerPage = 25

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
			stats.Processed += c.Stats.Processed
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
	for _, hk := range hooks {
		data.Hooks = append(data.Hooks, newHookRow(&hk))
	}
	h.render(w, "hooks", data)
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
	Captcha  string       // the captcha scheme the channel requires, if any
	HMAC     *hmacSnippet // set when the channel requires an hmac signature
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
	h.render(w, "channel", data)
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
	}
	if hk.FinalizedAt != nil {
		row.FinalizedAt = hk.FinalizedAt.Local().Format(time.DateTime)
	}
	for _, f := range hk.Failures {
		row.Failures = append(row.Failures, failureRow{At: f.At.Local().Format(time.DateTime), Message: f.Message})
	}
	if n := len(row.Failures); n > 0 {
		row.LastFailure = &row.Failures[n-1]
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
	for k, v := range hk.Headers {
		row.Headers = append(row.Headers, field{Key: k, Value: v})
	}
	slices.SortFunc(row.Headers, func(a, b field) int { return strings.Compare(a.Key, b.Key) })
	return row
}

// fields flattens a hook's payload into display rows, sorted by key.
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
		if _, err := h.db.SetHookStatus(r.Context(), r.PathValue("id"), status, ""); err != nil {
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
	Name       string
	Type       string
	Kind       string
	NeedsKey   bool
	SecretHint string
	Channels   []string
	CreatedAt  string
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
}

// guardForm is the Create guard form's input, kept when creating fails so the
// form is refilled as it was. The secret is never echoed back.
type guardForm struct {
	Restore   bool // refill the form
	Preset    string
	Name      string
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
			Name:       g.Name,
			Type:       g.Type,
			Kind:       guardKind(g),
			NeedsKey:   guard.NeedsSecret(g.Type),
			SecretHint: g.SecretHint,
			Channels:   g.Channels,
			CreatedAt:  g.CreatedAt.Local().Format("2006-01-02 15:04"),
		})
	}
	if form.Restore {
		w.WriteHeader(http.StatusUnprocessableEntity)
	}
	h.render(w, "guards", data)
}

// guardsError sends the browser back to the guards page with a message.
func guardsError(w http.ResponseWriter, r *http.Request, msg string) {
	http.Redirect(w, r, "/guards?error="+url.QueryEscape(msg), http.StatusSeeOther)
}

func (h *Handler) createGuard(w http.ResponseWriter, r *http.Request) {
	user := h.requireUser(w, r)
	if user == nil {
		return
	}
	form := guardForm{
		Restore:   true,
		Preset:    r.FormValue("preset"),
		Name:      strings.ToLower(strings.TrimSpace(r.FormValue("name"))),
		Type:      r.FormValue("type"),
		Scheme:    r.FormValue("scheme"),
		Field:     strings.TrimSpace(r.FormValue("field")),
		Header:    strings.TrimSpace(r.FormValue("header")),
		Algorithm: r.FormValue("algorithm"),
		Encoding:  r.FormValue("encoding"),
		Prefix:    r.FormValue("prefix"),
		MinScore:  strings.TrimSpace(r.FormValue("min_score")),
	}
	// Failures refill the form with what was entered.
	fail := func(msg string) { h.renderGuards(w, r, user, msg, form) }

	typ, scheme, secret := form.Type, form.Scheme, strings.TrimSpace(r.FormValue("secret"))
	if typ != guard.Signature && typ != guard.Captcha {
		scheme = ""
	}
	if !db.ValidChannel(form.Name) {
		fail("Guard names are up to 64 lowercase letters and digits, separated by single _ or -.")
		return
	}
	var minScore float64
	if form.MinScore != "" {
		f, err := strconv.ParseFloat(form.MinScore, 64)
		if err != nil {
			fail("The minimum score must be a number between 0 and 1.")
			return
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
		fail(strings.ToUpper(msg[:1]) + msg[1:] + ".")
		return
	}
	g := db.Guard{Name: form.Name, Type: typ, Scheme: scheme, Options: opts.JSON(), Secret: secret}
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

func (h *Handler) rotateGuardSecret(w http.ResponseWriter, r *http.Request) {
	user := h.requireUser(w, r)
	if user == nil {
		return
	}
	secret := strings.TrimSpace(r.FormValue("secret"))
	if secret == "" {
		guardsError(w, r, "Enter the new secret.")
		return
	}
	if _, err := h.db.RotateGuardSecret(r.Context(), r.PathValue("name"), secret); err != nil {
		h.dbError(w, r, "rotating guard secret", err)
		return
	}
	http.Redirect(w, r, "/guards", http.StatusSeeOther)
}

func (h *Handler) deleteGuard(w http.ResponseWriter, r *http.Request) {
	user := h.requireUser(w, r)
	if user == nil {
		return
	}
	if err := h.db.DeleteGuard(r.Context(), r.PathValue("name")); err != nil {
		if errors.Is(err, db.ErrGuardInUse) {
			guardsError(w, r, "Detach "+r.PathValue("name")+" from its channels before deleting it.")
			return
		}
		h.dbError(w, r, "deleting guard", err)
		return
	}
	http.Redirect(w, r, "/guards", http.StatusSeeOther)
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
