package main

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/cloud-in-a-bottle/external-dns-connector/internal/lifecycle"
)

type fakeLifecycle struct {
	listenAndServe func() error
	shutdown       func(context.Context) error
	close          func() error
}

func TestLifecycleTimeoutOrdering(t *testing.T) {
	if lifecycle.ProviderTimeout != 20*time.Second ||
		lifecycle.ServiceRequestTimeout != 25*time.Second ||
		lifecycle.ShutdownTimeout != 9*time.Second ||
		lifecycle.PlatformStopTimeout != 10*time.Second ||
		lifecycle.ServerWriteTimeout != 60*time.Second {
		t.Fatalf(
			"timeouts = provider:%s request:%s write:%s shutdown:%s platform-stop:%s",
			lifecycle.ProviderTimeout,
			lifecycle.ServiceRequestTimeout,
			lifecycle.ServerWriteTimeout,
			lifecycle.ShutdownTimeout,
			lifecycle.PlatformStopTimeout,
		)
	}
	if lifecycle.ProviderTimeout >= lifecycle.ServiceRequestTimeout ||
		lifecycle.ServiceRequestTimeout >= lifecycle.ServerWriteTimeout {
		t.Fatal("normal-operation timeouts must satisfy provider < request < server write")
	}
	if lifecycle.ShutdownTimeout >= lifecycle.PlatformStopTimeout {
		t.Fatal("shutdown timeout must be shorter than the platform stop timeout")
	}
}

func TestRequestBaseContextCancelsWithShutdown(t *testing.T) {
	shutdownCtx, cancelShutdown := context.WithCancel(t.Context())
	requestCtx, cancelRequest := context.WithCancel(requestBaseContext(shutdownCtx)(nil))
	defer cancelRequest()

	if err := requestCtx.Err(); err != nil {
		t.Fatalf("request context starts canceled: %v", err)
	}
	cancelShutdown()
	waitForMainSignal(t, requestCtx.Done())
	if !errors.Is(requestCtx.Err(), context.Canceled) {
		t.Fatalf("request context error = %v, want context canceled", requestCtx.Err())
	}
}

func (f *fakeLifecycle) ListenAndServe() error {
	return f.listenAndServe()
}

func (f *fakeLifecycle) Shutdown(ctx context.Context) error {
	return f.shutdown(ctx)
}

func (f *fakeLifecycle) Close() error {
	return f.close()
}

func TestServeWaitsForShutdownDrain(t *testing.T) {
	listenStarted := make(chan struct{})
	serveStopped := make(chan struct{})
	shutdownStarted := make(chan struct{})
	releaseDrain := make(chan struct{})
	srv := &fakeLifecycle{
		listenAndServe: func() error {
			close(listenStarted)
			<-serveStopped
			return http.ErrServerClosed
		},
		shutdown: func(context.Context) error {
			close(shutdownStarted)
			<-releaseDrain
			close(serveStopped)
			return nil
		},
		close: func() error {
			return errors.New("unexpected forced close")
		},
	}

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- serve(ctx, srv, time.Second) }()
	waitForMainSignal(t, listenStarted)
	cancel()
	waitForMainSignal(t, shutdownStarted)
	assertMainPending(t, done)

	close(releaseDrain)
	if err := receiveMain(t, done); err != nil {
		t.Fatal(err)
	}
}

func TestServePreservesStartupError(t *testing.T) {
	want := errors.New("bind failed")
	shutdownCalled := make(chan struct{}, 1)
	srv := &fakeLifecycle{
		listenAndServe: func() error { return want },
		shutdown: func(context.Context) error {
			shutdownCalled <- struct{}{}
			return nil
		},
		close: func() error { return nil },
	}

	if err := serve(t.Context(), srv, time.Second); !errors.Is(err, want) {
		t.Fatalf("serve returned %v, want startup error", err)
	}
	assertMainPending(t, shutdownCalled)
}

func TestServeReportsShutdownTimeoutAndForceCloses(t *testing.T) {
	listenStarted := make(chan struct{})
	serveStopped := make(chan struct{})
	closeCalled := make(chan struct{})
	srv := &fakeLifecycle{
		listenAndServe: func() error {
			close(listenStarted)
			<-serveStopped
			return http.ErrServerClosed
		},
		shutdown: func(ctx context.Context) error {
			<-ctx.Done()
			return ctx.Err()
		},
		close: func() error {
			close(closeCalled)
			close(serveStopped)
			return nil
		},
	}

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- serve(ctx, srv, 20*time.Millisecond) }()
	waitForMainSignal(t, listenStarted)
	cancel()
	err := receiveMain(t, done)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("serve returned %v, want shutdown deadline exceeded", err)
	}
	waitForMainSignal(t, closeCalled)
}

func receiveMain[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case value := <-ch:
		return value
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for channel")
		var zero T
		return zero
	}
}

func waitForMainSignal(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	receiveMain(t, ch)
}

func assertMainPending[T any](t *testing.T, ch <-chan T) {
	t.Helper()
	select {
	case value := <-ch:
		t.Fatalf("operation completed unexpectedly: %v", value)
	default:
	}
}
