package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

var ErrNotFound = errors.New("not found")

// Account is one set of credentials for one DNS provider. Credentials are stored as the JSON form of
// that provider's libdns Provider struct, so adding a provider needs no schema change.
type Account struct {
	ID          int64
	Provider    string
	Label       string
	Credentials json.RawMessage
	CreatedAt   time.Time
}

func (s *Store) CreateAccount(provider, label string, creds json.RawMessage) (int64, error) {
	res, err := s.db.Exec(
		`INSERT INTO provider_accounts (provider, label, credentials, created_at) VALUES (?, ?, ?, ?)`,
		provider, label, string(creds), time.Now().UTC().Format(time.RFC3339),
	)
	if err != nil {
		return 0, fmt.Errorf("create account %q: %w", label, err)
	}
	return res.LastInsertId()
}

func (s *Store) UpdateAccountCredentials(id int64, creds json.RawMessage) error {
	res, err := s.db.Exec(`UPDATE provider_accounts SET credentials = ? WHERE id = ?`, string(creds), id)
	if err != nil {
		return fmt.Errorf("update account %d: %w", id, err)
	}
	return expectOneRow(res, id)
}

func (s *Store) DeleteAccount(id int64) error {
	res, err := s.db.Exec(`DELETE FROM provider_accounts WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete account %d: %w", id, err)
	}
	return expectOneRow(res, id)
}

func (s *Store) Account(id int64) (Account, error) {
	row := s.db.QueryRow(
		`SELECT id, provider, label, credentials, created_at FROM provider_accounts WHERE id = ?`, id)
	a, err := scanAccount(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Account{}, fmt.Errorf("account %d: %w", id, ErrNotFound)
	}
	return a, err
}

func (s *Store) Accounts() ([]Account, error) {
	rows, err := s.db.Query(
		`SELECT id, provider, label, credentials, created_at FROM provider_accounts ORDER BY label`)
	if err != nil {
		return nil, fmt.Errorf("list accounts: %w", err)
	}
	defer rows.Close()

	var out []Account
	for rows.Next() {
		a, err := scanAccount(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

type scanner interface {
	Scan(dest ...any) error
}

func scanAccount(sc scanner) (Account, error) {
	var (
		a         Account
		creds     string
		createdAt string
	)
	if err := sc.Scan(&a.ID, &a.Provider, &a.Label, &creds, &createdAt); err != nil {
		return Account{}, err
	}
	a.Credentials = json.RawMessage(creds)
	a.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	return a, nil
}

func expectOneRow(res sql.Result, id int64) error {
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("id %d: %w", id, ErrNotFound)
	}
	return nil
}
