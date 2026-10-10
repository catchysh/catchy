package main

import (
	"bytes"
	"context"
	"crypto/subtle"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"

	"connectrpc.com/connect"
	"connectrpc.com/validate"
	"connectrpc.com/vanguard"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/joho/godotenv"
	_ "modernc.org/sqlite"

	"github.com/catchysh/catchy/gen/catchy/v1/catchyv1connect"
	"github.com/catchysh/catchy/internal/auth"
	"github.com/catchysh/catchy/internal/db"
	envvars "github.com/catchysh/catchy/internal/env"
	"github.com/catchysh/catchy/internal/guard"
	"github.com/catchysh/catchy/internal/handler"
	"github.com/catchysh/catchy/internal/hook"
	"github.com/catchysh/catchy/internal/service"
	"github.com/catchysh/catchy/internal/web"
)

var Version = "dev"

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envRequired(key string) string {
	v := os.Getenv(key)
	if v == "" {
		log.Fatalf("%s is required", key)
	}
	return v
}

func driverFromDSN(dsn string) string {
	switch {
	case strings.HasPrefix(dsn, "postgres://"), strings.HasPrefix(dsn, "postgresql://"):
		return "pgx"
	default:
		return "sqlite"
	}
}

func openDB() (*db.DB, error) {
	dsn := env("DATABASE_URL", "file:catchy.db")
	return db.New(context.Background(), driverFromDSN(dsn), dsn)
}

var usage = "Usage: catchy " + Version + ` <command>

Commands:
  serve [--migrate]   Start the server (default)
  worker              Send queued attempts without serving
  migrate             Run database migrations and exit
`

func main() {
	godotenv.Load()

	cmd := "serve"
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}

	migrate := false
	for _, arg := range os.Args[1:] {
		if arg == "--migrate" {
			migrate = true
		}
	}

	switch cmd {
	case "serve":
		cmdServe(migrate)
	case "worker":
		cmdWorker()
	case "migrate":
		cmdMigrate()
	case "version", "-v", "--version":
		fmt.Println("catchy " + Version)
	case "help", "-h", "--help":
		fmt.Print(usage)
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(1)
	}
}

func cmdMigrate() {
	database, err := openDB()
	if err != nil {
		log.Fatalf("failed to connect to database: %v", err)
	}
	defer database.Close(context.Background())

	if err := database.Migrate(context.Background()); err != nil {
		log.Fatalf("migration failed: %v", err)
	}
	log.Println("migrations complete")
}

type config struct {
	hostname           string
	sessionSecret      string
	googleClientID     string
	googleClientSecret string
	allowedDomains     []string
	trustProxy         bool
	autoCreate         bool // hooks to unknown channels create them
	guards             guard.Checker
	env                envvars.Env // CATCHY_VAR_ and CATCHY_SECRET_ variables
	tickSecret         string      // when set, POST /tick needs it as its Bearer token
}

func cmdServe(migrate bool) {
	port := env("PORT", "8080")

	database, err := openDB()
	if err != nil {
		log.Fatalf("failed to connect to database: %v", err)
	}
	defer database.Close(context.Background())

	if migrate {
		if err := database.Migrate(context.Background()); err != nil {
			log.Fatalf("migration failed: %v", err)
		}
	}

	cfg := config{
		hostname:           env("HOSTNAME", "http://localhost:"+port),
		sessionSecret:      envRequired("SESSION_SECRET"),
		googleClientID:     envRequired("GOOGLE_CLIENT_ID"),
		googleClientSecret: envRequired("GOOGLE_CLIENT_SECRET"),
		trustProxy:         os.Getenv("TRUST_PROXY") == "true",
		autoCreate:         os.Getenv("AUTO_CREATE_CHANNELS") != "false",
		tickSecret:         os.Getenv("TICK_SECRET"),
	}
	var skipped []string
	cfg.env, skipped = envvars.Load(os.Environ())
	for _, name := range skipped {
		log.Printf("ignoring %s: names after CATCHY_VAR_ and CATCHY_SECRET_ are letters, digits, and _", name)
	}
	if v := os.Getenv("ALLOWED_DOMAINS"); v != "" {
		cfg.allowedDomains = strings.Split(v, ",")
	}

	// Secrets live in the environment, so one can go missing on any restart.
	// Say so now; what needs it fails closed until it's back.
	if missing, err := web.MissingSecrets(context.Background(), database, cfg.env); err != nil {
		log.Printf("checking secrets: %v", err)
	} else {
		for _, m := range missing {
			log.Printf("warning: secret %s isn't set (%s%s), so these fail until it is: %s",
				m.Name, envvars.SecretPrefix, m.Name, strings.Join(m.UsedBy, ", "))
		}
	}

	mux, err := newMux(database, cfg)
	if err != nil {
		log.Fatalf("failed to set up routes: %v", err)
	}

	// Send hooks to their channels' handlers in the background. Where that
	// can't run between requests, a scheduler calls POST /tick too.
	go newWorker(database, cfg.hostname, cfg.env).Run(context.Background())

	addr := ":" + port
	log.Printf("listening on %s", addr)

	if err := http.ListenAndServe(addr, h2c.NewHandler(mux, &http2.Server{})); err != nil {
		log.Fatalf("server error: %v", err)
	}
}

func newWorker(database *db.DB, hostname string, e envvars.Env) *handler.Worker {
	return &handler.Worker{DB: database, Runner: &handler.Runner{Dashboard: hostname, Env: e}}
}

// tick sends the attempts that are due, for a scheduler to call where
// nothing runs between requests. It's harmless to call, since it sends only
// what's due and never twice, so it's open unless secret is set; then that's
// its Bearer token. One tick runs at a time: calls during it return at once.
func tick(w *handler.Worker, secret string) http.HandlerFunc {
	var running sync.Mutex
	return func(rw http.ResponseWriter, r *http.Request) {
		token, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if secret != "" && subtle.ConstantTimeCompare([]byte(token), []byte(secret)) != 1 {
			http.Error(rw, "unauthorized", http.StatusUnauthorized)
			return
		}
		if !running.TryLock() {
			rw.WriteHeader(http.StatusNoContent)
			return
		}
		defer running.Unlock()
		// A caller hanging up doesn't cut sends short: that would leave
		// attempts claimed but unfinished, to be sent again later.
		if err := w.RunOnce(context.WithoutCancel(r.Context())); err != nil {
			log.Printf("tick: %v", err)
			http.Error(rw, "sending attempts failed", http.StatusInternalServerError)
			return
		}
		rw.WriteHeader(http.StatusNoContent)
	}
}

// cmdWorker sends queued attempts until stopped, in its own process, beside
// serve's own loop: workers claim attempts, so none is sent twice. It needs
// only the database and what handlers use: HOSTNAME and the CATCHY_
// variables.
func cmdWorker() {
	database, err := openDB()
	if err != nil {
		log.Fatalf("failed to connect to database: %v", err)
	}
	defer database.Close(context.Background())

	e, skipped := envvars.Load(os.Environ())
	for _, name := range skipped {
		log.Printf("ignoring %s: names after CATCHY_VAR_ and CATCHY_SECRET_ are letters, digits, and _", name)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	log.Println("sending attempts")
	newWorker(database, env("HOSTNAME", "http://localhost:8080"), e).Run(ctx)
}

func newMux(database *db.DB, cfg config) (*http.ServeMux, error) {
	sessions := auth.NewSessionManager(cfg.sessionSecret)
	oauth := auth.NewOAuthHandler(
		cfg.googleClientID,
		cfg.googleClientSecret,
		cfg.hostname+"/auth/google/callback",
		database,
		sessions,
		cfg.allowedDomains,
	)
	apiKeys := auth.NewAPIKeyHandler(database, sessions)

	svc := service.New(database)
	validator := connect.WithInterceptors(validate.NewInterceptor())
	hooksPath, hooksHandler := catchyv1connect.NewHookServiceHandler(svc, validator)
	channelsPath, channelsHandler := catchyv1connect.NewChannelServiceHandler(svc, validator)

	restOpts := vanguard.WithRESTUnmarshalOptions(vanguard.RESTUnmarshalOptions{
		DiscardUnknownQueryParams: true,
	})
	transcoder, err := vanguard.NewTranscoder([]*vanguard.Service{
		vanguard.NewService(hooksPath, hooksHandler, restOpts),
		vanguard.NewService(channelsPath, channelsHandler, restOpts),
	},
		vanguard.WithCodec(func(res vanguard.TypeResolver) vanguard.Codec {
			codec := vanguard.NewJSONCodec(res)
			codec.MarshalOptions.UseProtoNames = true
			codec.MarshalOptions.EmitUnpopulated = true
			codec.UnmarshalOptions.DiscardUnknown = true
			return codec
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("creating transcoder: %w", err)
	}

	apiAuth := auth.RequireAPIKey(database)
	mux := http.NewServeMux()

	oauth.RegisterRoutes(mux)
	apiKeys.RegisterRoutes(mux)

	mux.Handle("/v1/", apiAuth(transcoder))
	mux.Handle(hooksPath, apiAuth(transcoder))
	mux.Handle(channelsPath, apiAuth(transcoder))

	// Static files are revalidated on every use, so a changed logo or favicon
	// shows up without a hard refresh; unchanged files cost a 304.
	fileServer := http.FileServer(http.Dir("public"))
	publicFS := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-cache")
		fileServer.ServeHTTP(w, r)
	})
	if spec, err := os.ReadFile("public/openapi.yaml"); err == nil {
		spec = bytes.ReplaceAll(spec, []byte("https://catchy.example.com"), []byte(cfg.hostname))
		mux.HandleFunc("GET /openapi.yaml", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/yaml; charset=utf-8")
			w.Write(spec)
		})
	}
	if entries, err := os.ReadDir("public"); err == nil {
		for _, e := range entries {
			if !e.IsDir() && !strings.HasPrefix(e.Name(), ".") && e.Name() != "openapi.yaml" {
				mux.Handle("GET /"+e.Name(), publicFS)
			}
		}
	}

	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("POST /tick", tick(newWorker(database, cfg.hostname, cfg.env), cfg.tickSecret))

	web.NewHandler(database, sessions, cfg.hostname, Version, cfg.env).RegisterRoutes(mux)

	// Hooks are caught at the root, POST /?channel={channel}, beside the
	// dashboard's GET /.
	hooks := hook.NewHandler(database, &cfg.guards, cfg.env, cfg.autoCreate, cfg.trustProxy)
	mux.Handle("POST /{$}", hooks)
	mux.Handle("OPTIONS /{$}", hooks)

	return mux, nil
}
