package store

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/cloud-in-a-bottle/external-dns-connector/internal/records"
)

// Zone binds a DNS zone to the provider account that can manage it. The set of zones is owner-only
// configuration: no consumer app can add, remove, or rebind one.
type Zone struct {
	Zone      string
	AccountID int64
	Label     string
	Provider  string
	CreatedAt time.Time
}

// ZoneBinding is one entry of the owner's declared zone set.
type ZoneBinding struct {
	Zone      string `json:"zone"`
	AccountID int64  `json:"account_id"`
}

// AddZone adds one binding atomically, without replacing any concurrently-added bindings.
func (s *Store) AddZone(binding ZoneBinding) error {
	zone, err := records.ValidateZone(binding.Zone)
	if err != nil {
		return err
	}
	if _, err := s.db.Exec(
		`INSERT INTO zones (zone, account_id, created_at) VALUES (?, ?, ?)`,
		zone,
		binding.AccountID,
		time.Now().UTC().Format(time.RFC3339),
	); err != nil {
		return fmt.Errorf("bind zone %q to account %d: %w", zone, binding.AccountID, err)
	}
	return nil
}

// DeleteZone removes one binding atomically. Removing an absent binding remains a successful no-op.
func (s *Store) DeleteZone(name string) error {
	zone, err := records.ValidateZone(name)
	if err != nil {
		return err
	}
	if _, err := s.db.Exec(`DELETE FROM zones WHERE zone = ?`, zone); err != nil {
		return fmt.Errorf("delete zone %q: %w", zone, err)
	}
	return nil
}

// ReplaceZones sets the complete zone list in one transaction, which is what the single owner-only
// zone route exposes. Replacing wholesale keeps the stored set exactly what the owner last declared,
// with no partially-applied intermediate state.
func (s *Store) ReplaceZones(bindings []ZoneBinding) error {
	normalized := make([]ZoneBinding, 0, len(bindings))
	seen := map[string]bool{}
	for _, binding := range bindings {
		zone, err := records.ValidateZone(binding.Zone)
		if err != nil {
			return err
		}
		if seen[zone] {
			return fmt.Errorf("zone %q listed more than once", zone)
		}
		seen[zone] = true
		normalized = append(normalized, ZoneBinding{Zone: zone, AccountID: binding.AccountID})
	}

	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin zone replace: %w", err)
	}
	defer tx.Rollback()

	if _, err := tx.Exec(`DELETE FROM zones`); err != nil {
		return fmt.Errorf("clear zones: %w", err)
	}
	now := time.Now().UTC().Format(time.RFC3339)
	for _, binding := range normalized {
		if _, err := tx.Exec(
			`INSERT INTO zones (zone, account_id, created_at) VALUES (?, ?, ?)`,
			binding.Zone,
			binding.AccountID,
			now,
		); err != nil {
			return fmt.Errorf("bind zone %q to account %d: %w", binding.Zone, binding.AccountID, err)
		}
	}
	return tx.Commit()
}

func (s *Store) Zones() ([]Zone, error) {
	rows, err := s.db.Query(`
		SELECT z.zone, z.account_id, a.label, a.provider, z.created_at
		FROM zones z JOIN provider_accounts a ON a.id = z.account_id
		ORDER BY z.zone`)
	if err != nil {
		return nil, fmt.Errorf("list zones: %w", err)
	}
	defer rows.Close()

	var out []Zone
	for rows.Next() {
		var (
			z         Zone
			createdAt string
		)
		if err := rows.Scan(&z.Zone, &z.AccountID, &z.Label, &z.Provider, &createdAt); err != nil {
			return nil, err
		}
		z.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
		out = append(out, z)
	}
	return out, rows.Err()
}

func (s *Store) Zone(name string) (Zone, error) {
	want := records.NormalizeZone(name)
	row := s.db.QueryRow(`
		SELECT z.zone, z.account_id, a.label, a.provider, z.created_at
		FROM zones z JOIN provider_accounts a ON a.id = z.account_id
		WHERE z.zone = ?`, want)
	var (
		z         Zone
		createdAt string
	)
	if err := row.Scan(&z.Zone, &z.AccountID, &z.Label, &z.Provider, &createdAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Zone{}, fmt.Errorf("zone %q: %w", name, ErrNotFound)
		}
		return Zone{}, fmt.Errorf("read zone %q: %w", name, err)
	}
	z.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	return z, nil
}
