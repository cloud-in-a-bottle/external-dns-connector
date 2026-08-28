package store

import (
	"encoding/json"
	"fmt"
	"time"
)

// auditRetentionLimit bounds persistent mutation history while retaining enough context for diagnosis.
const auditRetentionLimit = 10_000

const auditDetailLimitBytes = 16 * 1024

type auditDetailTruncation struct {
	Truncated     bool `json:"truncated"`
	OriginalBytes int  `json:"original_bytes"`
}

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
	if err := s.writeAudit(actor, actorAppID, op, zone, detail, opErr, auditRetentionLimit); err != nil {
		// A failure to write the audit trail must not fail the operation the user asked for, but it
		// should be visible in the container logs rather than swallowed.
		fmt.Printf("audit write failed for %s/%s: %v\n", actor, op, err)
	}
}

func (s *Store) writeAudit(
	actor, actorAppID, op, zone string,
	detail any,
	opErr error,
	retentionLimit int,
) error {
	if retentionLimit <= 0 {
		return fmt.Errorf("audit retention limit must be positive")
	}
	encoded, err := encodeAuditDetail(detail)
	if err != nil {
		return err
	}
	errText := ""
	if opErr != nil {
		errText = opErr.Error()
	}

	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin audit write: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec(
		`INSERT INTO audit_log (ts, actor, actor_app_id, op, zone, detail, ok, error)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		time.Now().UTC().Format(time.RFC3339), actor, actorAppID, op, zone, encoded, opErr == nil, errText,
	); err != nil {
		return fmt.Errorf("insert audit entry: %w", err)
	}
	if _, err := tx.Exec(
		`DELETE FROM audit_log
		 WHERE id NOT IN (SELECT id FROM audit_log ORDER BY id DESC LIMIT ?)`,
		retentionLimit,
	); err != nil {
		return fmt.Errorf("prune audit entries: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit audit write: %w", err)
	}
	return nil
}

func encodeAuditDetail(detail any) (string, error) {
	if detail == nil {
		return "", nil
	}
	encoded, err := json.Marshal(detail)
	if err != nil {
		return "", fmt.Errorf("encode audit detail: %w", err)
	}
	if len(encoded) <= auditDetailLimitBytes {
		return string(encoded), nil
	}
	marker, err := json.Marshal(auditDetailTruncation{
		Truncated:     true,
		OriginalBytes: len(encoded),
	})
	if err != nil {
		return "", fmt.Errorf("encode audit truncation marker: %w", err)
	}
	return string(marker), nil
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
		if err := rows.Scan(
			&e.ID, &ts, &e.Actor, &e.ActorAppID, &e.Op, &e.Zone, &e.Detail, &e.OK, &e.Error,
		); err != nil {
			return nil, err
		}
		e.TS, err = time.Parse(time.RFC3339, ts)
		if err != nil {
			return nil, fmt.Errorf("parse audit entry %d timestamp: %w", e.ID, err)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
