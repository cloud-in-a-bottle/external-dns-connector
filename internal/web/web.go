package web

import (
	"context"
	"embed"
	"html/template"
	"net/http"
	"net/url"

	"github.com/cloud-in-a-bottle/external-dns-connector/internal/auth"
	"github.com/cloud-in-a-bottle/external-dns-connector/internal/dnsops"
	"github.com/cloud-in-a-bottle/external-dns-connector/internal/store"
)

//go:embed templates/*.html
var templateFS embed.FS

type Server struct {
	store             *store.Store
	ops               *dnsops.Ops
	tmpl              map[string]*template.Template
	listProviderZones func(context.Context, store.Account) ([]string, error)
}

func New(s *store.Store, ops *dnsops.Ops) (*Server, error) {
	pages := []string{"zones", "accounts", "records", "audit"}
	tmpl := map[string]*template.Template{}
	for _, name := range pages {
		t, err := template.ParseFS(templateFS, "templates/layout.html", "templates/"+name+".html")
		if err != nil {
			return nil, err
		}
		tmpl[name] = t
	}
	return &Server{
		store:             s,
		ops:               ops,
		tmpl:              tmpl,
		listProviderZones: ops.ListProviderZones,
	}, nil
}

// Handler mounts the owner-facing UI. Every route here requires the owner and explicitly rejects a
// consumer identity, which is what keeps zone and credential configuration out of reach of any
// permission grant — there is simply no service route that touches it.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /{$}", s.ownerOnly(s.handleZones))
	mux.Handle("POST /zones/add", s.ownerOnly(s.handleZoneAdd))
	mux.Handle("POST /zones/delete", s.ownerOnly(s.handleZoneDelete))
	mux.Handle("PUT /api/zones", s.ownerOnly(s.handleZonesReplace))
	mux.Handle("GET /zones/{zone}", s.ownerOnly(s.handleRecords))
	mux.Handle("POST /zones/{zone}/add", s.ownerOnly(s.handleRecordAdd))
	mux.Handle("POST /zones/{zone}/delete", s.ownerOnly(s.handleRecordDelete))
	mux.Handle("GET /accounts", s.ownerOnly(s.handleAccounts))
	mux.Handle("POST /accounts/add", s.ownerOnly(s.handleAccountAdd))
	mux.Handle("POST /accounts/delete", s.ownerOnly(s.handleAccountDelete))
	mux.Handle("GET /audit", s.ownerOnly(s.handleAudit))
	return mux
}

func (s *Server) ownerOnly(h http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !auth.Classify(r).IsOwner() {
			http.Error(w, "this page is only available to the space owner", http.StatusForbidden)
			return
		}
		h(w, r)
	})
}

// page is the data every template receives. Flash messages ride in the query string so a redirect
// after POST can carry them without a session store.
type page struct {
	Title     string
	Nav       string
	Flash     string
	FlashKind string
}

func newPage(r *http.Request, title, nav string) page {
	p := page{Title: title, Nav: nav}
	if msg := r.URL.Query().Get("ok"); msg != "" {
		p.Flash, p.FlashKind = msg, "ok"
	} else if msg := r.URL.Query().Get("err"); msg != "" {
		p.Flash, p.FlashKind = msg, "bad"
	}
	return p
}

func (s *Server) render(w http.ResponseWriter, name string, data any) {
	t, ok := s.tmpl[name]
	if !ok {
		http.Error(w, "unknown template "+name, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := t.ExecuteTemplate(w, "layout", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func redirectOK(w http.ResponseWriter, r *http.Request, path, msg string) {
	http.Redirect(w, r, path+"?ok="+url.QueryEscape(msg), http.StatusSeeOther)
}

func redirectErr(w http.ResponseWriter, r *http.Request, path string, err error) {
	http.Redirect(w, r, path+"?err="+url.QueryEscape(err.Error()), http.StatusSeeOther)
}
