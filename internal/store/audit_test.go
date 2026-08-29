package store

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

type auditTestDetail struct {
	Sequence int `json:"sequence"`
}

func TestAuditDetailIsBounded(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	boundary := strings.Repeat("a", auditDetailLimitBytes-2)
	if err := st.writeAudit("owner", "", "boundary", "example.com", boundary, nil, 10); err != nil {
		t.Fatal(err)
	}
	overLimit := strings.Repeat("b", auditDetailLimitBytes-1)
	if err := st.writeAudit("owner", "", "over", "example.com", overLimit, nil, 10); err != nil {
		t.Fatal(err)
	}

	entries, err := st.AuditEntries(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("got %d entries, want 2", len(entries))
	}
	if got := entries[1].Detail; len(got) != auditDetailLimitBytes || got != `"`+boundary+`"` {
		t.Fatalf("boundary detail was changed or has length %d", len(got))
	}
	if len(entries[0].Detail) > auditDetailLimitBytes || !json.Valid([]byte(entries[0].Detail)) {
		t.Fatalf("truncation marker is not bounded valid JSON: %q", entries[0].Detail)
	}
	var marker auditDetailTruncation
	if err := json.Unmarshal([]byte(entries[0].Detail), &marker); err != nil {
		t.Fatal(err)
	}
	wantBytes := auditDetailLimitBytes + 1
	if !marker.Truncated || marker.OriginalBytes != wantBytes {
		t.Fatalf("truncation marker = %+v, want original byte count %d", marker, wantBytes)
	}
}

func TestProductionAuditRetentionRemainsTenThousandRows(t *testing.T) {
	if auditRetentionLimit != 10_000 {
		t.Fatalf("auditRetentionLimit = %d, want 10000", auditRetentionLimit)
	}
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
