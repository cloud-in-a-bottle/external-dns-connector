package store

import (
	"fmt"
	"path/filepath"
	"testing"
)

type auditTestDetail struct {
	Sequence int `json:"sequence"`
}

func TestAuditPrunesOldestEntries(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	const retentionLimit = 3
	for sequence := 1; sequence <= 5; sequence++ {
		if err := st.writeAudit(
			"owner",
			"",
			fmt.Sprintf("mutation-%d", sequence),
			"example.com",
			auditTestDetail{Sequence: sequence},
			nil,
			retentionLimit,
		); err != nil {
			t.Fatal(err)
		}
	}

	entries, err := st.AuditEntries(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != retentionLimit {
		t.Fatalf("retained %d audit entries, want %d: %+v", len(entries), retentionLimit, entries)
	}
	for index, wantSequence := range []int{5, 4, 3} {
		wantOp := fmt.Sprintf("mutation-%d", wantSequence)
		if entries[index].Op != wantOp {
			t.Errorf("entry %d operation = %q, want %q", index, entries[index].Op, wantOp)
		}
	}
}
