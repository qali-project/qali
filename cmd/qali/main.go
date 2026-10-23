// Command qali runs the Qali server. This file only assembles the process.
//
//	qali                        serve HTTP and run background jobs
//	qali migrate up             apply database migrations with the migration role
//	qali healthcheck            exit 0 when the local instance is ready (container probe)
//	qali reset-password <email> print a single-use password reset token (operator)
//	qali setup-token            print a single-use first-owner setup token (operator)
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/google/uuid"

	"github.com/qali-project/qali/internal/assembly"
	"github.com/qali-project/qali/internal/identity/adapter/httpapi"
	"github.com/qali-project/qali/internal/identity/adapter/postgres"
	"github.com/qali-project/qali/internal/identity/app"
	"github.com/qali-project/qali/internal/platform/clock"
	"github.com/qali-project/qali/internal/platform/config"
	"github.com/qali-project/qali/internal/platform/crypto"
	"github.com/qali-project/qali/internal/platform/db"
	"github.com/qali-project/qali/internal/platform/httpserver"
	"github.com/qali-project/qali/internal/platform/httpserver/openapi"
	"github.com/qali-project/qali/internal/platform/jobs"
	"github.com/qali-project/qali/internal/platform/secret"
	"github.com/qali-project/qali/internal/platform/webui"
	workspacehttp "github.com/qali-project/qali/internal/workspace/adapter/httpapi"
	workspacepg "github.com/qali-project/qali/internal/workspace/adapter/postgres"
	workspaceapp "github.com/qali-project/qali/internal/workspace/app"
)

const shutdownTimeout = 10 * time.Second

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{ReplaceAttr: utcTime}))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := dispatch(ctx, logger, config.OS(), os.Args[1:])
	stop()
	os.Exit(code)
}

// dispatch runs a subcommand and returns the process exit code: 0 success,
// 1 runtime failure, 2 usage or configuration error.
func dispatch(ctx context.Context, logger *slog.Logger, src config.Source, args []string) int {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	var err error
	command := strings.Join(args, " ")
	switch command {
	case "":
		err = run(ctx, logger, src)
	case "migrate up":
		err = migrate(ctx, logger, src)
	case "setup-token":
		err = setupToken(ctx, logger, src, os.Stdout)
	case "healthcheck":
		addr, _ := src.Getenv("QALI_HTTP_ADDR")
		err = healthcheck(ctx, healthcheckURL(addr))
	default:
		if email, ok := strings.CutPrefix(command, "reset-password "); ok && len(args) == 2 {
			err = resetPassword(ctx, logger, src, email, os.Stdout)
			break
		}
		fmt.Fprintln(os.Stderr, "usage: qali [migrate up | healthcheck | setup-token | reset-password <email>]")
		return 2
	}
	var cerr *config.Error
	switch {
	case err == nil:
		return 0
	case errors.As(err, &cerr):
		fmt.Fprintln(os.Stderr, err)
		return 2
	default:
		logger.Error("qali failed", "error", err)
		return 1
	}
}

// utcTime writes log timestamps in UTC (ADR-0004).
func utcTime(groups []string, a slog.Attr) slog.Attr {
	if len(groups) == 0 && a.Key == slog.TimeKey && a.Value.Kind() == slog.KindTime {
		a.Value = slog.TimeValue(a.Value.Time().UTC())
	}
	return a
}

func migrate(ctx context.Context, logger *slog.Logger, src config.Source) error {
	cfg, err := config.LoadMigration(src)
	if err != nil {
		return err
	}
	applied, err := db.Migrate(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	logger.Info("migrations applied", "versions", applied, "latest", db.LatestMigration())
	return nil
}

// deps are the assembled services.
type deps struct {
	store     *db.Store
	identity  *app.Service
	workspace *workspaceapp.Service
}

// services assembles the store and module services from configuration.
// Key material is validated here so a bad deployment fails closed.
func services(ctx context.Context, cfg config.Config) (deps, error) {
	keyring, err := crypto.NewKeyring(1, map[uint32]secret.Value{1: cfg.KEK})
	if err != nil {
		return deps{}, err
	}
	tokens, err := crypto.NewTokens(1, map[uint32]secret.Value{1: cfg.TokenPepper})
	if err != nil {
		return deps{}, err
	}
	passwords, err := crypto.NewPasswords(cfg.PasswordPepper, crypto.DefaultPasswordParams)
	if err != nil {
		return deps{}, err
	}
	store, err := db.Open(ctx, cfg.DatabaseURL, db.Options{})
	if err != nil {
		return deps{}, err
	}
	svc := app.New(app.Config{
		Store: store, Repo: postgres.Repository{}, Passwords: passwords, Tokens: tokens, Keyring: keyring,
		Clock: clock.System{}, NewID: uuid.NewV7, Issuer: "Qali",
	})
	ws := workspaceapp.New(workspaceapp.Config{
		Store: store, Repo: workspacepg.Repository{}, Accounts: svc, Tokens: tokens, Clock: clock.System{}, NewID: uuid.NewV7,
	})
	return deps{store: store, identity: svc, workspace: ws}, nil
}

// operatorID names the local operator in audit events.
func operatorID(src config.Source) string {
	if u, ok := src.Getenv("USER"); ok && u != "" {
		return "local-cli:" + u
	}
	return "local-cli"
}

// setupToken prints the one-time token that the first-owner setup page
// requires (REVIEW-001). Running it needs access to the server, which is
// the proof that the caller operates the installation.
func setupToken(ctx context.Context, logger *slog.Logger, src config.Source, out io.Writer) error {
	cfg, err := config.Load(src)
	if err != nil {
		return err
	}
	d, err := services(ctx, cfg)
	if err != nil {
		return err
	}
	defer d.store.Close()
	token, expires, err := d.identity.IssueSetupToken(ctx, operatorID(src))
	if err != nil {
		return err
	}
	logger.Info("setup token issued", "expires_at", expires.Format(time.RFC3339))
	_, err = fmt.Fprintf(out, "Setup token (single use, expires %s):\n%s\n", expires.Format(time.RFC3339), token.Expose())
	return err
}

// resetPassword is the operator-assisted recovery path (ADR-0012): run
// inside the container, it prints a token valid for 30 minutes.
func resetPassword(ctx context.Context, logger *slog.Logger, src config.Source, email string, out io.Writer) error {
	cfg, err := config.Load(src)
	if err != nil {
		return err
	}
	d, err := services(ctx, cfg)
	if err != nil {
		return err
	}
	defer d.store.Close()
	token, expires, err := d.identity.IssuePasswordReset(ctx, email, operatorID(src))
	if err != nil {
		return err
	}
	logger.Info("password reset token issued", "expires_at", expires.Format(time.RFC3339))
	_, err = fmt.Fprintf(out, "Password reset token (single use, expires %s):\n%s\n", expires.Format(time.RFC3339), token.Expose())
	return err
}

func run(ctx context.Context, logger *slog.Logger, src config.Source) error {
	cfg, err := config.Load(src)
	if err != nil {
		return err
	}
	d, err := services(ctx, cfg)
	if err != nil {
		return err
	}
	store := d.store
	identity := httpapi.New(d.identity, logger)
	workspace := workspacehttp.New(d.workspace, logger, httpapi.WriteSession)
	if err := store.Ready(ctx); err != nil {
		logger.Warn("starting while not ready", "reason", err.Error())
	}
	worker := jobs.NewWorker(store, jobs.NewQueue(clock.System{}, uuid.NewV7), jobs.WorkerOptions{Logger: logger})

	srv := &http.Server{
		Addr: cfg.HTTPAddr,
		Handler: httpserver.NewHandler(httpserver.Options{
			UI:             webui.FS(),
			PublicURL:      cfg.PublicURL,
			TrustedProxies: cfg.TrustedProxies,
			Logger:         logger,
			Ready:          store.Ready,
			API:            assembly.API(identity, workspace),
			APIMiddlewares: []openapi.MiddlewareFunc{identity.Authenticate},
		}),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}
	logger.Info("listening", "addr", cfg.HTTPAddr, "environment", cfg.Environment, "public_url", cfg.PublicURL.String())
	return serve(ctx, srv, worker, store.Close)
}

type httpServer interface {
	ListenAndServe() error
	Shutdown(context.Context) error
}

type runner interface {
	Run(context.Context) error
}

// serve runs HTTP and the worker until ctx ends or HTTP fails, then shuts
// down in order: stop accepting HTTP, drain in-flight jobs, close the pool.
func serve(ctx context.Context, srv httpServer, worker runner, closeDB func()) error {
	workerCtx, stopWorker := context.WithCancel(context.WithoutCancel(ctx))
	workerDone := make(chan error, 1)
	go func() { workerDone <- worker.Run(workerCtx) }()
	httpDone := make(chan error, 1)
	go func() { httpDone <- srv.ListenAndServe() }()

	var result error
	select {
	case err := <-httpDone:
		if !errors.Is(err, http.ErrServerClosed) {
			result = err
		}
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), shutdownTimeout)
		if err := srv.Shutdown(shutdownCtx); err != nil {
			result = err
		}
		cancel()
		if err := <-httpDone; !errors.Is(err, http.ErrServerClosed) && result == nil {
			result = err
		}
	}
	stopWorker()
	if err := <-workerDone; err != nil && result == nil {
		result = err
	}
	closeDB()
	return result
}

// healthcheckURL maps the listen address to a loopback readiness URL.
func healthcheckURL(addr string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil || port == "" {
		host, port = "", "8080"
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	return "http://" + net.JoinHostPort(host, port) + "/health/ready"
}

// healthcheck lets a distroless container probe itself without a shell.
func healthcheck(ctx context.Context, url string) error {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	_ = res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("not ready: HTTP %d", res.StatusCode)
	}
	return nil
}
