// Package mock implements the libdns interfaces against a sqlite table, so the whole record path —
// service API, permission checks, owner UI — is exercisable without credentials for a real registrar.
package mock

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/libdns/libdns"
)

// mu serializes every mock operation. A Provider is rebuilt per call, so a mutex on the struct would
// not actually serialize anything; the fake is cheap enough that one package-wide lock is fine.
var mu sync.Mutex

// Provider is a fake DNS provider. AccountID scopes its records so two mock accounts don't share a
// zone; it is filled in from the credentials blob like any other provider's fields.
type Provider struct {
	AccountID string `json:"account_id"`

	db *sql.DB
}

// SetDB supplies the backing handle. The registry calls this after unmarshalling the credentials,
// since a JSON blob cannot carry a database connection.
func (p *Provider) SetDB(db *sql.DB) { p.db = db }

func (p *Provider) key() (int64, error) {
	if p.db == nil {
		return 0, fmt.Errorf("mock provider has no database handle")
	}
	var id int64
	if _, err := fmt.Sscan(p.AccountID, &id); err != nil {
		return 0, fmt.Errorf("mock provider has invalid account_id %q", p.AccountID)
	}
	return id, nil
}

func (p *Provider) GetRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	id, err := p.key()
	if err != nil {
		return nil, err
	}
	mu.Lock()
	defer mu.Unlock()
	return p.get(ctx, id, norm(zone))
}

func (p *Provider) get(ctx context.Context, id int64, zone string) ([]libdns.Record, error) {
	rows, err := p.db.QueryContext(ctx,
		`SELECT name, type, ttl, data FROM mock_records WHERE account_id = ? AND zone = ? ORDER BY name, type, data`,
		id, zone)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []libdns.Record
	for rows.Next() {
		var (
			name, rrtype, data string
			ttl                int
		)
		if err := rows.Scan(&name, &rrtype, &ttl, &data); err != nil {
			return nil, err
		}
		rec, err := libdns.RR{Name: name, Type: rrtype, TTL: time.Duration(ttl) * time.Second, Data: data}.Parse()
		if err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

func (p *Provider) AppendRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	id, err := p.key()
	if err != nil {
		return nil, err
	}
	mu.Lock()
	defer mu.Unlock()
	z := norm(zone)
	for _, r := range recs {
		if err := p.insert(ctx, id, z, r); err != nil {
			return nil, err
		}
	}
	return recs, nil
}

// SetRecords implements the RRset semantics libdns specifies: for each (name, type) in the input, the
// input records become the only members of that RRset. Records with other names or types are left
// alone.
func (p *Provider) SetRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	id, err := p.key()
	if err != nil {
		return nil, err
	}
	mu.Lock()
	defer mu.Unlock()
	z := norm(zone)

	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	cleared := map[string]bool{}
	for _, r := range recs {
		rr := r.RR()
		k := rr.Name + "\x00" + rr.Type
		if !cleared[k] {
			if _, err := tx.ExecContext(ctx,
				`DELETE FROM mock_records WHERE account_id = ? AND zone = ? AND name = ? AND type = ?`,
				id, z, rr.Name, rr.Type); err != nil {
				return nil, err
			}
			cleared[k] = true
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO mock_records (account_id, zone, name, type, ttl, data) VALUES (?, ?, ?, ?, ?, ?)`,
			id, z, rr.Name, rr.Type, int(rr.TTL/time.Second), rr.Data); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return recs, nil
}

// DeleteRecords removes records that exactly match the input. Per libdns, an empty Type, TTL, or Data
// acts as a wildcard for that field; Name is always required.
func (p *Provider) DeleteRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	id, err := p.key()
	if err != nil {
		return nil, err
	}
	mu.Lock()
	defer mu.Unlock()
	z := norm(zone)

	var deleted []libdns.Record
	for _, r := range recs {
		rr := r.RR()
		query := `DELETE FROM mock_records WHERE account_id = ? AND zone = ? AND name = ?`
		args := []any{id, z, rr.Name}
		if rr.Type != "" {
			query += ` AND type = ?`
			args = append(args, rr.Type)
		}
		if rr.Data != "" {
			query += ` AND data = ?`
			args = append(args, rr.Data)
		}
		if rr.TTL != 0 {
			query += ` AND ttl = ?`
			args = append(args, int(rr.TTL/time.Second))
		}
		res, err := p.db.ExecContext(ctx, query, args...)
		if err != nil {
			return nil, err
		}
		if n, _ := res.RowsAffected(); n > 0 {
			deleted = append(deleted, r)
		}
	}
	return deleted, nil
}

func (p *Provider) ListZones(ctx context.Context) ([]libdns.Zone, error) {
	id, err := p.key()
	if err != nil {
		return nil, err
	}
	mu.Lock()
	defer mu.Unlock()
	rows, err := p.db.QueryContext(ctx,
		`SELECT DISTINCT zone FROM mock_records WHERE account_id = ? ORDER BY zone`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []libdns.Zone
	for rows.Next() {
		var z string
		if err := rows.Scan(&z); err != nil {
			return nil, err
		}
		out = append(out, libdns.Zone{Name: z + "."})
	}
	return out, rows.Err()
}

func (p *Provider) insert(ctx context.Context, id int64, zone string, r libdns.Record) error {
	rr := r.RR()
	_, err := p.db.ExecContext(ctx,
		`INSERT INTO mock_records (account_id, zone, name, type, ttl, data) VALUES (?, ?, ?, ?, ?, ?)`,
		id, zone, rr.Name, rr.Type, int(rr.TTL/time.Second), rr.Data)
	return err
}

func norm(zone string) string {
	return strings.ToLower(strings.TrimSuffix(zone, "."))
}
