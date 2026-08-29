package store

import (
	"path/filepath"
	"testing"
)

func TestReadersRejectMalformedPersistedTimestamps(t *testing.T) {
	tests := []struct {
		name    string
		corrupt func(*testing.T, *Store)
		read    func(*Store) error
	}{
		{
			name: "account",
			corrupt: func(t *testing.T, store *Store) {
				id := createTimestampTestAccount(t, store)
				mustExec(t, store, `UPDATE provider_accounts SET created_at = 'invalid' WHERE id = ?`, id)
			},
			read: func(store *Store) error {
				_, err := store.Accounts()
				return err
			},
		},
		{
			name: "account lookup",
			corrupt: func(t *testing.T, store *Store) {
				id := createTimestampTestAccount(t, store)
				mustExec(t, store, `UPDATE provider_accounts SET created_at = 'invalid' WHERE id = ?`, id)
			},
			read: func(store *Store) error {
				var id int64
				if err := store.DB().QueryRow(`SELECT id FROM provider_accounts LIMIT 1`).Scan(&id); err != nil {
					return err
				}
				_, err := store.Account(id)
				return err
			},
		},
		{
			name: "zone list",
			corrupt: func(t *testing.T, store *Store) {
				id := createTimestampTestAccount(t, store)
				if err := store.AddZone(ZoneBinding{Zone: "example.com", AccountID: id}); err != nil {
					t.Fatal(err)
				}
				mustExec(t, store, `UPDATE zones SET created_at = 'invalid' WHERE zone = 'example.com'`)
			},
			read: func(store *Store) error {
				_, err := store.Zones()
				return err
			},
		},
		{
			name: "zone lookup",
			corrupt: func(t *testing.T, store *Store) {
				id := createTimestampTestAccount(t, store)
				if err := store.AddZone(ZoneBinding{Zone: "example.com", AccountID: id}); err != nil {
					t.Fatal(err)
				}
				mustExec(t, store, `UPDATE zones SET created_at = 'invalid' WHERE zone = 'example.com'`)
			},
			read: func(store *Store) error {
				_, err := store.Zone("example.com")
				return err
			},
		},
		{
			name: "audit",
			corrupt: func(t *testing.T, store *Store) {
				store.Audit("owner", "", "test", "", nil, nil)
				mustExec(t, store, `UPDATE audit_log SET ts = 'invalid'`)
			},
			read: func(store *Store) error {
				_, err := store.AuditEntries(10)
				return err
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store, err := Open(filepath.Join(t.TempDir(), "test.db"))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = store.Close() })
			test.corrupt(t, store)
			if err := test.read(store); err == nil {
				t.Fatal("reader accepted a malformed timestamp")
			}
		})
	}
}

func createTimestampTestAccount(t *testing.T, store *Store) int64 {
	t.Helper()
	id, err := store.CreateAccount("mock", "timestamp-test", nil)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func mustExec(t *testing.T, store *Store, query string, args ...any) {
	t.Helper()
	if _, err := store.DB().Exec(query, args...); err != nil {
		t.Fatal(err)
	}
}
