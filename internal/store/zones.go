package store

import (
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

// ReplaceZones sets the complete zone list in one transaction, which is what the single owner-only
// zone route exposes. Replacing wholesale keeps the stored set exactly what the owner last declared,
// with no partially-applied intermediate state.
func (s *Store) ReplaceZones(bindings []ZoneBinding) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin zone replace: %w", err)
	}
	defer tx.Rollback()

	if _, err := tx.Exec(`DELETE FROM zones`); err != nil {
		return fmt.Errorf("clear zones: %w", err)
	}
	now := time.Now().UTC().Format(time.RFC3339)
	seen := map[string]bool{}
	for _, b := range bindings {
		zone := records.NormalizeZone(b.Zone)
		if zone == "" {
			return errors.New("zone name is empty")
		}
		if seen[zone] {
			return fmt.Errorf("zone %q listed more than once", zone)
		}
		seen[zone] = true
		if _, err := tx.Exec(
			`INSERT INTO zones (zone, account_id, created_at) VALUES (?, ?, ?)`, zone, b.AccountID, now,
		); err != nil {
			return fmt.Errorf("bind zone %q to account %d: %w", zone, b.AccountID, err)
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
	zones, err := s.Zones()
	if err != nil {
		return Zone{}, err
	}
	want := records.NormalizeZone(name)
	for _, z := range zones {
		if z.Zone == want {
			return z, nil
		}
	}
	return Zone{}, fmt.Errorf("zone %q: %w", name, ErrNotFound)
}
