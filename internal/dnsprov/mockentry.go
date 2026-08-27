package dnsprov

import (
	"encoding/json"
	"strconv"

	"github.com/cloud-in-a-bottle/external-dns-connector/internal/dnsprov/mock"
)

// MockKey is the registry key of the built-in fake provider. It is always registered: it cannot
// affect real DNS, and having it available means the record editor and the service API can be tried
// out — and tested end to end — before any registrar credentials exist.
const MockKey = "mock"

func init() {
	register(Entry{
		Key: MockKey, Label: "Mock (testing only)",
		// No credentials: the mock is scoped by the account's own row id, which is assigned on save.
		Fields: nil,
		New: func(deps Deps, creds json.RawMessage) (any, error) {
			p := &mock.Provider{}
			if len(creds) > 0 {
				if err := json.Unmarshal(creds, p); err != nil {
					return nil, err
				}
			}
			p.SetDB(deps.DB)
			return p, nil
		},
	})
}

// MockCredentials builds the credentials blob for a mock account. The account id is only known after
// the row is inserted, so the caller saves the account first and then stores this.
func MockCredentials(accountID int64) json.RawMessage {
	b, err := json.Marshal(mock.Provider{AccountID: strconv.FormatInt(accountID, 10)})
	if err != nil {
		panic(err) // marshalling a struct of one string cannot fail
	}
	return b
}
