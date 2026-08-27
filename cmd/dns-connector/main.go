package main

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/cloud-in-a-bottle/external-dns-connector/internal/config"
	"github.com/cloud-in-a-bottle/external-dns-connector/internal/dnsops"
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
		// Provider APIs can be slow; the router's own proxy timeout bounds the client side.
		WriteTimeout: 60 * time.Second,
	}

	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-shutdown
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}()

	log.Printf("dns-connector listening on %s (app %s)", cfg.ListenAddr, cfg.AppName)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
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
		log.Printf("%s %s %d %s caller=%s", r.Method, r.URL.Path, rec.status, time.Since(start).Round(time.Millisecond), caller)
	})
}
