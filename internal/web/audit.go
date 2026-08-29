package web

import (
	"net/http"
)

type auditRow struct {
	When   string
	Actor  string
	Op     string
	Zone   string
	Detail string
	Error  string
	OK     bool
}

type auditPage struct {
	page
	Entries []auditRow
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	entries, err := s.store.AuditEntries(200)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	rows := make([]auditRow, 0, len(entries))
	for _, e := range entries {
		zone := e.Zone
		if zone == "" {
			zone = "—"
		}
		rows = append(rows, auditRow{
			When:   e.TS.Format("2006-01-02 15:04:05"),
			Actor:  e.Actor,
			Op:     e.Op,
			Zone:   zone,
			Detail: truncate(e.Detail, 120),
			Error:  truncate(e.Error, 120),
			OK:     e.OK,
		})
	}
	s.render(w, "audit", auditPage{page: newPage(r, "Activity", "audit"), Entries: rows})
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
