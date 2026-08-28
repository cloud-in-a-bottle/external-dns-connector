package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/cloud-in-a-bottle/external-dns-connector/internal/config"
	"github.com/cloud-in-a-bottle/external-dns-connector/internal/dnsops"
	"github.com/cloud-in-a-bottle/external-dns-connector/internal/lifecycle"
	"github.com/cloud-in-a-bottle/external-dns-connector/internal/service"
	"github.com/cloud-in-a-bottle/external-dns-connector/internal/store"
	"github.com/cloud-in-a-bottle/external-dns-connector/internal/web"
)

// serviceEndpoint must match the `endpoint` of the [[services.v2.provides]] entry in
// cloudinabottle.toml — the router proxies service calls to this prefix.
const serviceEndpoint = "/api/dns/"

func main() {
	if err := run(); err != nil {
		log.Fatalf("dns-connector: %v", err)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	st, err := store.Open(cfg.SQLitePath)
	if err != nil {
		return err
	}
	defer st.Close()

	ops := dnsops.New(st)
	ui, err := web.New(st, ops)
	if err != nil {
		return err
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", health)
	// The router probes /health directly on the container, so it is the one route with no identity
	// requirement. Everything else is either owner-only or service-only.
	mux.Handle(serviceEndpoint, http.StripPrefix(strings.TrimSuffix(serviceEndpoint, "/"),
		service.New(st, ops).Handler()))
	mux.Handle("/", ui.Handler())

	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           logRequests(mux),
		ReadHeaderTimeout: 10 * time.Second,
		// Provider operations have their own shorter deadline; this remains the final response bound.
		WriteTimeout: lifecycle.ServerWriteTimeout,
	}

	log.Printf("dns-connector listening on %s (app %s)", cfg.ListenAddr, cfg.AppName)
	shutdownCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return serve(shutdownCtx, srv, lifecycle.ShutdownTimeout)
}

type serverLifecycle interface {
	ListenAndServe() error
	Shutdown(context.Context) error
	Close() error
}

func serve(ctx context.Context, srv serverLifecycle, timeout time.Duration) error {
	serveErr := make(chan error, 1)
	go func() {
		serveErr <- srv.ListenAndServe()
	}()

	select {
	case err := <-serveErr:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	case <-ctx.Done():
	}

	drainCtx, cancel := context.WithTimeout(context.Background(), timeout)
	shutdownErr := srv.Shutdown(drainCtx)
	cancel()

	var closeErr error
	if shutdownErr != nil {
		// Shutdown can time out while handlers are still active. Close releases the listener and those
		// connections so the serving goroutine cannot outlive the store it may still use.
		closeErr = srv.Close()
	}
	listenErr := <-serveErr

	var errs []error
	if shutdownErr != nil {
		errs = append(errs, fmt.Errorf("shut down HTTP server: %w", shutdownErr))
	}
	if closeErr != nil {
		errs = append(errs, fmt.Errorf("close HTTP server after failed shutdown: %w", closeErr))
	}
	if listenErr != nil && !errors.Is(listenErr, http.ErrServerClosed) {
		errs = append(errs, listenErr)
	}
	return errors.Join(errs...)
}

func health(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

func logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		start := time.Now()
		next.ServeHTTP(rec, r)
		// Log the calling app on service requests; DNS changes are worth being able to trace in the
		// container logs as well as in the audit table.
		caller := r.Header.Get("X-OpenHost-Consumer-Name")
		if caller == "" {
			caller = "-"
		}
		log.Printf(
			"%s %s %d %s caller=%s",
			r.Method,
			r.URL.Path,
			rec.status,
			time.Since(start).Round(time.Millisecond),
			caller,
		)
	})
}
