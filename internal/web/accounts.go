package web

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/cloud-in-a-bottle/external-dns-connector/internal/dnsprov"
	"github.com/cloud-in-a-bottle/external-dns-connector/internal/store"
)

type accountRow struct {
	ID            int64
	Label         string
	Provider      string
	ProviderLabel string
	Zones         []string
}

type accountsPage struct {
	page
	Accounts  []accountRow
	Providers []dnsprov.Entry
	Selected  dnsprov.Entry
}

func (s *Server) handleAccounts(w http.ResponseWriter, r *http.Request) {
	accounts, err := s.store.Accounts()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	zones, err := s.store.Zones()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	byAccount := map[int64][]string{}
	for _, z := range zones {
		byAccount[z.AccountID] = append(byAccount[z.AccountID], z.Zone)
	}

	rows := make([]accountRow, 0, len(accounts))
	for _, a := range accounts {
		label := a.Provider
		if e, err := dnsprov.Lookup(a.Provider); err == nil {
			label = e.Label
		}
		rows = append(rows, accountRow{
			ID: a.ID, Label: a.Label, Provider: a.Provider, ProviderLabel: label, Zones: byAccount[a.ID],
		})
	}

	all := dnsprov.All()
	if len(all) == 0 {
		http.Error(w, "no production DNS providers are registered", http.StatusInternalServerError)
		return
	}
	selected := all[0]
	if key := r.URL.Query().Get("provider"); key != "" {
		key = strings.ToLower(strings.TrimSpace(key))
		for _, e := range all {
			if e.Key == key {
				selected = e
				break
			}
		}
	}

	s.render(w, "accounts", accountsPage{
		page:      newPage(r, "Providers", "accounts"),
		Accounts:  rows,
		Providers: all,
		Selected:  selected,
	})
}

func (s *Server) handleAccountAdd(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		redirectErr(w, r, "/accounts", err)
		return
	}
	entry, err := dnsprov.Lookup(r.FormValue("provider"))
	if err != nil {
		redirectErr(w, r, "/accounts", err)
		return
	}
	label := r.FormValue("label")
	if label == "" {
		redirectErr(w, r, "/accounts", errors.New("give this account a name"))
		return
	}

	values := map[string]string{}
	for _, f := range entry.Fields {
		values[f.Key] = r.FormValue(f.Key)
	}
	creds, err := entry.CredentialsFromForm(values, nil)
	if err != nil {
		redirectErr(w, r, "/accounts?provider="+entry.Key, err)
		return
	}

	id, err := s.store.CreateAccount(entry.Key, label, creds)
	if err != nil {
		redirectErr(w, r, "/accounts?provider="+entry.Key, err)
		return
	}
	// The mock is scoped by its own row id, which only exists once the row is inserted.
	if entry.Key == dnsprov.MockKey {
		if err := s.store.UpdateAccountCredentials(id, dnsprov.MockCredentials(id)); err != nil {
			redirectErr(w, r, "/accounts", err)
			return
		}
	}
	s.store.Audit("owner", "", "account_add", "", map[string]string{"provider": entry.Key, "label": label}, nil)
	redirectOK(w, r, "/accounts", "Saved "+label)
}

func (s *Server) handleAccountDelete(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.FormValue("id"), 10, 64)
	if err != nil {
		redirectErr(w, r, "/accounts", err)
		return
	}
	if err := s.ops.DeleteAccount(r.Context(), id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			redirectErr(w, r, "/accounts", errors.New("that account no longer exists"))
			return
		}
		redirectErr(w, r, "/accounts", err)
		return
	}
	s.store.Audit("owner", "", "account_delete", "", map[string]int64{"id": id}, nil)
	redirectOK(w, r, "/accounts", "Deleted")
}
