package store

import (
	"path/filepath"
	"testing"
)

func newZoneStore(t *testing.T) (*Store, int64) {
	t.Helper()
	st, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	accountID, err := st.CreateAccount("test", "test-account", nil)
	if err != nil {
		t.Fatal(err)
	}
	return st, accountID
}

func TestAddZoneValidatesAndNormalizesName(t *testing.T) {
	tests := []struct {
		name  string
		zone  string
		valid bool
		want  string
	}{
		{name: "mixed case and trailing dot", zone: "Example.COM.", valid: true, want: "example.com"},
		{name: "empty label", zone: "bad..example", valid: false},
		{name: "multiple trailing dots", zone: "example.com..", valid: false},
		{name: "reserved wildcard", zone: "*", valid: false},
		{name: "invalid character", zone: "bad_name.example", valid: false},
		{name: "leading hyphen", zone: "-bad.example", valid: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			st, accountID := newZoneStore(t)
			err := st.AddZone(ZoneBinding{Zone: tt.zone, AccountID: accountID})
			if !tt.valid {
				if err == nil {
					t.Fatal("AddZone accepted invalid zone")
				}
				zones, listErr := st.Zones()
				if listErr != nil {
					t.Fatal(listErr)
				}
				if len(zones) != 0 {
					t.Fatalf("rejected AddZone persisted %+v", zones)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			zones, err := st.Zones()
			if err != nil {
				t.Fatal(err)
			}
			if len(zones) != 1 || zones[0].Zone != tt.want {
				t.Fatalf("stored zones = %+v, want %q", zones, tt.want)
			}
		})
	}
}

func TestReplaceZonesRejectsInvalidNameWithoutChangingStoredSet(t *testing.T) {
	invalid := []string{"bad..example", "example.com..", "*", "bad_name.example", "bad-.example"}
	for _, zone := range invalid {
		t.Run(zone, func(t *testing.T) {
			st, accountID := newZoneStore(t)
			if err := st.AddZone(ZoneBinding{Zone: "original.example", AccountID: accountID}); err != nil {
				t.Fatal(err)
			}
			err := st.ReplaceZones([]ZoneBinding{{Zone: zone, AccountID: accountID}})
			if err == nil {
				t.Fatal("ReplaceZones accepted invalid zone")
			}
			zones, err := st.Zones()
			if err != nil {
				t.Fatal(err)
			}
			if len(zones) != 1 || zones[0].Zone != "original.example" {
				t.Fatalf("rejected ReplaceZones changed stored set: %+v", zones)
			}
		})
	}
}

func TestDeleteZoneValidatesNameAndAcceptsNormalizedInput(t *testing.T) {
	st, accountID := newZoneStore(t)
	if err := st.AddZone(ZoneBinding{Zone: "example.com", AccountID: accountID}); err != nil {
		t.Fatal(err)
	}
	for _, zone := range []string{"", "example.com..", "*", "bad_name.example"} {
		if err := st.DeleteZone(zone); err == nil {
			t.Errorf("DeleteZone(%q) accepted invalid zone", zone)
		}
	}
	zones, err := st.Zones()
	if err != nil {
		t.Fatal(err)
	}
	if len(zones) != 1 || zones[0].Zone != "example.com" {
		t.Fatalf("invalid deletes changed stored set: %+v", zones)
	}
	if err := st.DeleteZone("Example.COM."); err != nil {
		t.Fatal(err)
	}
	zones, err = st.Zones()
	if err != nil {
		t.Fatal(err)
	}
	if len(zones) != 0 {
		t.Fatalf("normalized delete left zones: %+v", zones)
	}
}
