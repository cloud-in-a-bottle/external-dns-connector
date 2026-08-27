package store

import (
	"encoding/json"
	"fmt"
	"time"
)

// AuditEntry records who changed what. Anything that can repoint a domain is worth a trail: when
// mail stops arriving, the first question is which app touched the MX record and when.
type AuditEntry struct {
	ID         int64     `json:"id"`
	TS         time.Time `json:"ts"`
	Actor      string    `json:"actor"`
	ActorAppID string    `json:"actor_app_id"`
	Op         string    `json:"op"`
	Zone       string    `json:"zone"`
	Detail     string    `json:"detail"`
	OK         bool      `json:"ok"`
	Error      string    `json:"error"`
}

func (s *Store) Audit(actor, actorAppID, op, zone string, detail any, opErr error) {
	encoded := ""
	if detail != nil {
		if b, err := json.Marshal(detail); err == nil {
			encoded = string(b)
		}
	}
	errText := ""
	if opErr != nil {
		errText = opErr.Error()
	}
	// A failure to write the audit trail must not fail the operation the user asked for, but it
	// should be visible in the container logs rather than swallowed.
	if _, err := s.db.Exec(
		`INSERT INTO audit_log (ts, actor, actor_app_id, op, zone, detail, ok, error)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		time.Now().UTC().Format(time.RFC3339), actor, actorAppID, op, zone, encoded, opErr == nil, errText,
	); err != nil {
		fmt.Printf("audit write failed for %s/%s: %v\n", actor, op, err)
	}
}

func (s *Store) AuditEntries(limit int) ([]AuditEntry, error) {
	rows, err := s.db.Query(
		`SELECT id, ts, actor, actor_app_id, op, zone, detail, ok, error
		 FROM audit_log ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("list audit entries: %w", err)
	}
	defer rows.Close()

	var out []AuditEntry
	for rows.Next() {
		var (
			e  AuditEntry
			ts string
		)
		if err := rows.Scan(&e.ID, &ts, &e.Actor, &e.ActorAppID, &e.Op, &e.Zone, &e.Detail, &e.OK, &e.Error); err != nil {
			return nil, err
		}
		e.TS, _ = time.Parse(time.RFC3339, ts)
		out = append(out, e)
	}
	return out, rows.Err()
}
