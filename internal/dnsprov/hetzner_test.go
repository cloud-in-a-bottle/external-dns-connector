package dnsprov

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hetznercloud/hcloud-go/v2/hcloud"
	"github.com/libdns/libdns"

	"github.com/cloud-in-a-bottle/external-dns-connector/internal/records"
)

func TestHetznerTXTConversionRoundTrips(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		encoded string
	}{
		{name: "plain", value: "plain", encoded: `"plain"`},
		{name: "quote and backslash", value: `quote " and backslash \`,
			encoded: `"quote \" and backslash \\"`},
		{name: "boundary quotes", value: `"literal boundary quotes"`,
			encoded: `"\"literal boundary quotes\""`},
		{name: "newline", value: "line one\nline two", encoded: `"line one\010line two"`},
		{name: "unicode", value: "snowman: ☃", encoded: `"snowman: \226\152\131"`},
		{name: "empty", value: "", encoded: `""`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := libdns.RR{
				Name: "MiXeD",
				Type: "txt",
				TTL:  60 * time.Second,
				Data: tt.value,
			}
			normalized, encoded, ttl, err := libDNSRecordToHetzner("EXAMPLE.COM.", input, true)
			if err != nil {
				t.Fatal(err)
			}
			if encoded != tt.encoded {
				t.Fatalf("encoded TXT = %q, want %q", encoded, tt.encoded)
			}
			if ttl != 60 {
				t.Fatalf("TTL = %d, want 60", ttl)
			}
			assertRRs(t, []libdns.Record{normalized}, []libdns.RR{{
				Name: "mixed", Type: "TXT", TTL: time.Minute, Data: tt.value,
			}})

			decoded, err := hetznerRecordToLibDNS("MiXeD", "txt", ttl, encoded)
			if err != nil {
				t.Fatal(err)
			}
			assertRRs(t, []libdns.Record{decoded}, []libdns.RR{{
				Name: "mixed", Type: "TXT", TTL: time.Minute, Data: tt.value,
			}})
		})
	}
}

func TestDecodeHetznerTXTZoneFileValues(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  string
	}{
		{name: "plain API value", value: "plain", want: "plain"},
		{name: "quoted", value: `"plain"`, want: "plain"},
		{
			name:  "quote and backslash",
			value: `"escaped \"quote\" and \\ backslash"`,
			want:  `escaped "quote" and \ backslash`,
		},
		{name: "decimal is base ten", value: `"\065"`, want: "A"},
		{name: "decimal newline", value: `"before\010after"`, want: "before\nafter"},
		{name: "arbitrary escape", value: `"\q"`, want: "q"},
		{name: "unicode octets", value: `"\226\152\131"`, want: "☃"},
		{name: "empty", value: `""`, want: ""},
		{name: "literal boundary quotes", value: `"\"literal\""`, want: `"literal"`},
		{name: "split character strings", value: `"split" " value"`, want: "split value"},
		{name: "plain legacy escapes pass through", value: `legacy\065`, want: `legacy\065`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := decodeHetznerTXT(tt.value)
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Errorf("decoded TXT = %q, want %q", got, tt.want)
			}
		})
	}

	for _, malformed := range []string{`"unterminated`, `"valid" trailing`, `"\999"`, `"dangling\`} {
		if _, err := decodeHetznerTXT(malformed); err == nil {
			t.Errorf("decodeHetznerTXT(%q) should fail", malformed)
		}
	}
}

func TestHetznerTXTEncodingChunksLongValuesAt255Bytes(t *testing.T) {
	value := "v=DKIM1; p=" + strings.Repeat("A", 600)
	data := []byte(value)
	want := `"` + string(data[:255]) + `" "` + string(data[255:510]) +
		`" "` + string(data[510:]) + `"`
	encoded := encodeHetznerTXT(value)
	if encoded != want {
		t.Fatalf("long TXT encoding has incorrect chunk boundaries")
	}
	decoded, err := decodeHetznerTXT(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if decoded != value {
		t.Fatalf("long TXT round trip changed %d-byte value", len(data))
	}
}

func TestHetznerTXTCodecPreservesEveryByteValue(t *testing.T) {
	data := make([]byte, 256)
	for i := range data {
		data[i] = byte(i)
	}
	encoded := encodeHetznerTXT(string(data))
	decoded, err := decodeHetznerTXT(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if decoded != string(data) {
		t.Fatal("TXT codec did not preserve every byte value")
	}
}

func TestGetRecordsFetchesAllRRSetsAndPreservesTXT(t *testing.T) {
	p := newScriptedHetznerProvider(t, []hcloudRequest{
		{
			method: http.MethodGet,
			path:   "/zones/example.com",
			response: `{
				"zone": {"id": 42, "name": "example.com", "ttl": 120, "record_count": 5}
			}`,
		},
		{
			method: http.MethodGet,
			path:   "/zones/example.com/rrsets?page=1&per_page=50",
			response: `{
				"rrsets": [
					{
						"zone": 42,
						"name": "WWW",
						"type": "a",
						"ttl": null,
						"records": [{"value": "192.0.2.1"}]
					},
					{
						"zone": 42,
						"name": "Text",
						"type": "TXT",
						"ttl": 300,
						"records": [
							{"value": "\"plain\""},
							{"value": "\"escaped \\\"quote\\\" and \\\\ backslash\""},
							{"value": "\"\\\"boundary\\\"\""}
						]
					}
				],
				"meta": {"pagination": {"page": 1, "next_page": 2}}
			}`,
		},
		{
			method: http.MethodGet,
			path:   "/zones/example.com/rrsets?page=2&per_page=50",
			response: `{
				"rrsets": [{
					"zone": 42,
					"name": "@",
					"type": "MX",
					"ttl": null,
					"records": [{"value": "10 mail.example.com."}]
				}],
				"meta": {"pagination": {"page": 2}}
			}`,
		},
	})

	got, err := p.GetRecords(t.Context(), "EXAMPLE.COM.")
	if err != nil {
		t.Fatal(err)
	}
	want := []libdns.RR{
		{Name: "www", Type: "A", TTL: 120 * time.Second, Data: "192.0.2.1"},
		{Name: "text", Type: "TXT", TTL: 300 * time.Second, Data: "plain"},
		{
			Name: "text", Type: "TXT", TTL: 300 * time.Second,
			Data: `escaped "quote" and \ backslash`,
		},
		{Name: "text", Type: "TXT", TTL: 300 * time.Second, Data: `"boundary"`},
		{Name: "@", Type: "MX", TTL: 120 * time.Second, Data: "10 mail.example.com."},
	}
	assertRRs(t, got, want)
	if _, ok := got[0].(libdns.Address); !ok {
		t.Errorf("A record has type %T, want libdns.Address", got[0])
	}
	if _, ok := got[1].(libdns.TXT); !ok {
		t.Errorf("TXT record has type %T, want libdns.TXT", got[1])
	}
	if _, ok := got[4].(libdns.MX); !ok {
		t.Errorf("MX record has type %T, want libdns.MX", got[4])
	}
}

func TestSetRecordsReplacesExistingValuesBeforeTTLWithoutDelete(t *testing.T) {
	p := newScriptedHetznerProvider(t, []hcloudRequest{
		{
			method: http.MethodGet,
			path:   "/zones/example.com/rrsets/www/TXT",
			response: `{
				"rrset": {
					"zone": 42,
					"name": "www",
					"type": "TXT",
					"ttl": 60,
					"records": [
						{"value":"\"plain\"","comment":"keep this"},
						{"value":"\"removed\"","comment":"do not copy"}
					]
				}
			}`,
		},
		{
			method: http.MethodPost,
			path:   "/zones/example.com/rrsets/www/TXT/actions/set_records",
			body: `{
				"records": [
					{"value": "\"plain\"", "comment": "keep this"},
					{"value": "\"\\\"boundary\\\"\""}
				]
			}`,
			response: runningAction(10),
		},
		waitForAction(10),
		{
			method:   http.MethodPost,
			path:     "/zones/example.com/rrsets/www/TXT/actions/change_ttl",
			body:     `{"ttl":300}`,
			response: runningAction(11),
		},
		waitForAction(11),
	})

	input := []libdns.Record{
		libdns.RR{Name: "WWW", Type: "txt", TTL: 300 * time.Second, Data: "plain"},
		libdns.RR{Name: "www", Type: "TXT", TTL: 300 * time.Second, Data: `"boundary"`},
	}
	got, err := p.SetRecords(t.Context(), "EXAMPLE.COM.", input)
	if err != nil {
		t.Fatal(err)
	}
	assertRRs(t, got, []libdns.RR{
		{Name: "www", Type: "TXT", TTL: 300 * time.Second, Data: "plain"},
		{Name: "www", Type: "TXT", TTL: 300 * time.Second, Data: `"boundary"`},
	})
}

func TestSetRecordsTTLOnlyChangePreservesAllComments(t *testing.T) {
	p := newScriptedHetznerProvider(t, []hcloudRequest{
		{
			method: http.MethodGet,
			path:   "/zones/example.com/rrsets/txt/TXT",
			response: `{
				"rrset": {
					"zone": 42,
					"name": "txt",
					"type": "TXT",
					"ttl": 60,
					"records": [
						{"value":"\"one\"","comment":"first"},
						{"value":"\"two\"","comment":"second"}
					]
				}
			}`,
		},
		{
			method: http.MethodPost,
			path:   "/zones/example.com/rrsets/txt/TXT/actions/set_records",
			body: `{
				"records": [
					{"value":"\"one\"","comment":"first"},
					{"value":"\"two\"","comment":"second"}
				]
			}`,
			response: runningAction(30),
		},
		waitForAction(30),
		{
			method:   http.MethodPost,
			path:     "/zones/example.com/rrsets/txt/TXT/actions/change_ttl",
			body:     `{"ttl":300}`,
			response: runningAction(31),
		},
		waitForAction(31),
	})

	got, err := p.SetRecords(t.Context(), "example.com.", []libdns.Record{
		libdns.TXT{Name: "txt", TTL: 300 * time.Second, Text: "one"},
		libdns.TXT{Name: "txt", TTL: 300 * time.Second, Text: "two"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("set returned %d records, want 2", len(got))
	}
}

func TestSetRecordsCreatesMissingRRSet(t *testing.T) {
	p := newScriptedHetznerProvider(t, []hcloudRequest{
		{
			method:   http.MethodGet,
			path:     "/zones/example.com/rrsets/new/A",
			status:   http.StatusNotFound,
			response: `{"error":{"code":"not_found","message":"not found"}}`,
		},
		{
			method: http.MethodPost,
			path:   "/zones/example.com/rrsets",
			body: `{
				"name": "new",
				"type": "A",
				"ttl": 60,
				"records": [{"value": "192.0.2.2"}]
			}`,
			response: `{
				"rrset": {"zone": 42, "name": "new", "type": "A"},
				"action": {"id": 12, "status": "running"}
			}`,
		},
		waitForAction(12),
	})

	input := []libdns.Record{
		libdns.RR{Name: "NEW", Type: "a", TTL: time.Minute, Data: "192.0.2.2"},
	}
	got, err := p.SetRecords(t.Context(), "example.com.", input)
	if err != nil {
		t.Fatal(err)
	}
	assertRRs(t, got, []libdns.RR{{
		Name: "new", Type: "A", TTL: time.Minute, Data: "192.0.2.2",
	}})
}

func TestSetRecordsReturnsKnownValuesWhenTTLUpdateFails(t *testing.T) {
	p := newScriptedHetznerProvider(t, []hcloudRequest{
		{
			method:   http.MethodGet,
			path:     "/zones/example.com/rrsets/www/A",
			response: `{"rrset":{"zone":42,"name":"www","type":"A","ttl":60}}`,
		},
		{
			method:   http.MethodPost,
			path:     "/zones/example.com/rrsets/www/A/actions/set_records",
			body:     `{"records":[{"value":"192.0.2.3"}]}`,
			response: runningAction(13),
		},
		waitForAction(13),
		{
			method:   http.MethodPost,
			path:     "/zones/example.com/rrsets/www/A/actions/change_ttl",
			body:     `{"ttl":300}`,
			response: runningAction(14),
		},
		failedAction(14, "invalid_ttl", "TTL update failed"),
	})

	input := []libdns.Record{
		libdns.RR{Name: "www", Type: "A", TTL: 300 * time.Second, Data: "192.0.2.3"},
	}
	got, err := p.SetRecords(t.Context(), "example.com.", input)
	if err == nil || !strings.Contains(err.Error(), "TTL") {
		t.Fatalf("SetRecords error = %v, want TTL failure", err)
	}
	assertRRs(t, got, []libdns.RR{{
		Name: "www", Type: "A", TTL: 60 * time.Second, Data: "192.0.2.3",
	}})
}

func TestSetRecordsPartialResultUsesKnownZoneDefaultOnly(t *testing.T) {
	tests := []struct {
		name      string
		cacheTTL  bool
		wantCount int
	}{
		{name: "unknown default", wantCount: 0},
		{name: "cached default", cacheTTL: true, wantCount: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := newScriptedHetznerProvider(t, []hcloudRequest{
				{
					method: http.MethodGet,
					path:   "/zones/example.com/rrsets/www/A",
					response: `{
						"rrset":{"zone":42,"name":"www","type":"A","ttl":null}
					}`,
				},
				{
					method:   http.MethodPost,
					path:     "/zones/example.com/rrsets/www/A/actions/set_records",
					body:     `{"records":[{"value":"192.0.2.4"}]}`,
					response: runningAction(40),
				},
				waitForAction(40),
				{
					method:   http.MethodPost,
					path:     "/zones/example.com/rrsets/www/A/actions/change_ttl",
					body:     `{"ttl":300}`,
					response: runningAction(41),
				},
				failedAction(41, "invalid_ttl", "TTL update failed"),
			})
			if tt.cacheTTL {
				p.zoneTTLs.Store("example.com", 120)
			}

			got, err := p.SetRecords(t.Context(), "example.com.", []libdns.Record{
				libdns.RR{Name: "www", Type: "A", TTL: 300 * time.Second, Data: "192.0.2.4"},
			})
			if err == nil {
				t.Fatal("SetRecords should report the TTL failure")
			}
			if len(got) != tt.wantCount {
				t.Fatalf("partial records = %d, want %d", len(got), tt.wantCount)
			}
			if tt.cacheTTL {
				assertRRs(t, got, []libdns.RR{{
					Name: "www", Type: "A", TTL: 120 * time.Second, Data: "192.0.2.4",
				}})
			}
		})
	}
}

func TestAppendAndDeleteGroupValuesByRRSet(t *testing.T) {
	t.Run("append", func(t *testing.T) {
		p := newScriptedHetznerProvider(t, []hcloudRequest{
			{
				method: http.MethodPost,
				path:   "/zones/example.com/rrsets/txt/TXT/actions/add_records",
				body: `{
					"records": [{"value":"\"one\""},{"value":"\"two\""}],
					"ttl": 60
				}`,
				response: runningAction(20),
			},
			waitForAction(20),
		})
		input := txtRecords("one", "two")
		got, err := p.AppendRecords(t.Context(), "example.com.", input)
		if err != nil {
			t.Fatal(err)
		}
		assertRRs(t, got, recordsAsRRs(input))
	})

	t.Run("delete", func(t *testing.T) {
		p := newScriptedHetznerProvider(t, []hcloudRequest{
			{
				method: http.MethodPost,
				path:   "/zones/example.com/rrsets/txt/TXT/actions/remove_records",
				body: `{
					"records": [{"value":"\"one\""},{"value":"\"two\""}]
				}`,
				response: runningAction(21),
			},
			waitForAction(21),
		})
		input := txtRecords("one", "two")
		got, err := p.DeleteRecordsExact(t.Context(), "example.com.", input)
		if err != nil {
			t.Fatal(err)
		}
		assertRRs(t, got, recordsAsRRs(input))
	})
}

func TestDeleteRecordsChecksCurrentValueAndTTL(t *testing.T) {
	p := newScriptedHetznerProvider(t, []hcloudRequest{
		{
			method: http.MethodGet,
			path:   "/zones/example.com/rrsets/txt/TXT",
			response: `{
				"rrset": {
					"zone":42,
					"name":"txt",
					"type":"TXT",
					"ttl":60,
					"records":[
						{"value":"\"one\"","comment":"first"},
						{"value":"\"two\"","comment":"second"}
					]
				}
			}`,
		},
		{
			method: http.MethodPost,
			path:   "/zones/example.com/rrsets/txt/TXT/actions/remove_records",
			body: `{
				"records":[{"value":"\"two\"","comment":"second"}]
			}`,
			response: runningAction(50),
		},
		waitForAction(50),
	})

	got, err := p.DeleteRecords(t.Context(), "example.com.", []libdns.Record{
		libdns.TXT{Name: "txt", TTL: 300 * time.Second, Text: "one"},
		libdns.TXT{Name: "txt", TTL: 0, Text: "two"},
		libdns.TXT{Name: "txt", TTL: 60 * time.Second, Text: "missing"},
	})
	if err != nil {
		t.Fatal(err)
	}
	assertRRs(t, got, []libdns.RR{{
		Name: "txt", Type: "TXT", TTL: 60 * time.Second, Data: "two",
	}})
}

func TestDeleteRecordsResolvesZoneDefaultTTL(t *testing.T) {
	p := newScriptedHetznerProvider(t, []hcloudRequest{
		{
			method: http.MethodGet,
			path:   "/zones/example.com/rrsets/txt/TXT",
			response: `{
				"rrset": {
					"zone":42,
					"name":"txt",
					"type":"TXT",
					"ttl":null,
					"records":[{"value":"\"one\""}]
				}
			}`,
		},
		{
			method:   http.MethodGet,
			path:     "/zones/example.com",
			response: `{"zone":{"id":42,"name":"example.com","ttl":120}}`,
		},
		{
			method:   http.MethodPost,
			path:     "/zones/example.com/rrsets/txt/TXT/actions/remove_records",
			body:     `{"records":[{"value":"\"one\""}]}`,
			response: runningAction(51),
		},
		waitForAction(51),
	})

	got, err := p.DeleteRecords(t.Context(), "example.com.", []libdns.Record{
		libdns.TXT{Name: "txt", TTL: 120 * time.Second, Text: "one"},
	})
	if err != nil {
		t.Fatal(err)
	}
	assertRRs(t, got, []libdns.RR{{
		Name: "txt", Type: "TXT", TTL: 120 * time.Second, Data: "one",
	}})
}

func TestDeleteRecordsRejectsBroadWildcardsBeforeRequests(t *testing.T) {
	tests := []libdns.Record{
		libdns.RR{Name: "txt", Type: "", TTL: time.Minute, Data: "one"},
		libdns.RR{Name: "txt", Type: "TXT", TTL: time.Minute, Data: ""},
	}
	for _, record := range tests {
		p := newScriptedHetznerProvider(t, nil)
		if _, err := p.DeleteRecords(t.Context(), "example.com.", []libdns.Record{record}); err == nil {
			t.Errorf("DeleteRecords(%+v) should reject wildcard fields", record.RR())
		}
	}
}

func TestMutationActionsWithEmptyErrorDetailsStillFail(t *testing.T) {
	tests := []struct {
		name     string
		requests []hcloudRequest
		call     func(*hetznerProvider) ([]libdns.Record, error)
	}{
		{
			name: "append",
			requests: []hcloudRequest{
				{
					method:   http.MethodPost,
					path:     "/zones/example.com/rrsets/txt/TXT/actions/add_records",
					body:     `{"records":[{"value":"\"one\""}],"ttl":60}`,
					response: runningAction(60),
				},
				failedAction(60, "", ""),
			},
			call: func(p *hetznerProvider) ([]libdns.Record, error) {
				return p.AppendRecords(t.Context(), "example.com.", txtRecords("one"))
			},
		},
		{
			name: "set existing",
			requests: []hcloudRequest{
				{
					method: http.MethodGet,
					path:   "/zones/example.com/rrsets/txt/TXT",
					response: `{
						"rrset":{"zone":42,"name":"txt","type":"TXT","ttl":60}
					}`,
				},
				{
					method:   http.MethodPost,
					path:     "/zones/example.com/rrsets/txt/TXT/actions/set_records",
					body:     `{"records":[{"value":"\"one\""}]}`,
					response: runningAction(61),
				},
				failedAction(61, "", ""),
			},
			call: func(p *hetznerProvider) ([]libdns.Record, error) {
				return p.SetRecords(t.Context(), "example.com.", txtRecords("one"))
			},
		},
		{
			name: "create",
			requests: []hcloudRequest{
				{
					method:   http.MethodGet,
					path:     "/zones/example.com/rrsets/txt/TXT",
					status:   http.StatusNotFound,
					response: `{"error":{"code":"not_found","message":"not found"}}`,
				},
				{
					method: http.MethodPost,
					path:   "/zones/example.com/rrsets",
					body: `{
						"name":"txt",
						"type":"TXT",
						"ttl":60,
						"records":[{"value":"\"one\""}]
					}`,
					response: `{
						"rrset":{"zone":42,"name":"txt","type":"TXT"},
						"action":{"id":62,"status":"running"}
					}`,
				},
				failedAction(62, "", ""),
			},
			call: func(p *hetznerProvider) ([]libdns.Record, error) {
				return p.SetRecords(t.Context(), "example.com.", txtRecords("one"))
			},
		},
		{
			name: "delete",
			requests: []hcloudRequest{
				{
					method:   http.MethodPost,
					path:     "/zones/example.com/rrsets/txt/TXT/actions/remove_records",
					body:     `{"records":[{"value":"\"one\""}]}`,
					response: runningAction(63),
				},
				failedAction(63, "", ""),
			},
			call: func(p *hetznerProvider) ([]libdns.Record, error) {
				return p.DeleteRecordsExact(t.Context(), "example.com.", txtRecords("one"))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := newScriptedHetznerProvider(t, tt.requests)
			got, err := tt.call(p)
			if err == nil || !strings.Contains(err.Error(), "failed without error details") {
				t.Fatalf("operation error = %v, want empty-detail action failure", err)
			}
			if len(got) != 0 {
				t.Errorf("failed action returned %d records", len(got))
			}
		})
	}
}

func TestWaitForActionRejectsMissingAndUnknownStates(t *testing.T) {
	p := newScriptedHetznerProvider(t, nil)
	for _, action := range []*hcloud.Action{
		nil,
		{Status: hcloud.ActionStatusSuccess},
		{ID: 1},
		{ID: 2, Status: "unexpected"},
	} {
		if err := p.waitForAction(t.Context(), action); err == nil {
			t.Errorf("waitForAction(%+v) should fail", action)
		}
	}

	p = newScriptedHetznerProvider(t, []hcloudRequest{{
		method:   http.MethodGet,
		path:     "/actions/3",
		status:   http.StatusNotFound,
		response: `{"error":{"code":"not_found","message":"not found"}}`,
	}})
	if err := p.waitForAction(t.Context(), &hcloud.Action{
		ID: 3, Status: hcloud.ActionStatusRunning,
	}); err == nil || !strings.Contains(err.Error(), "disappeared") {
		t.Fatalf("missing polled action returned %v", err)
	}
	p = newScriptedHetznerProvider(t, []hcloudRequest{{
		method:   http.MethodGet,
		path:     "/actions/5",
		response: `{"action":{"status":"success"}}`,
	}})
	if err := p.waitForAction(t.Context(), &hcloud.Action{
		ID: 5, Status: hcloud.ActionStatusRunning,
	}); err == nil || !strings.Contains(err.Error(), "received action 0") {
		t.Fatalf("ID-less polled action returned %v", err)
	}

	p = newScriptedHetznerProvider(t, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := p.waitForAction(ctx, &hcloud.Action{
		ID: 4, Status: hcloud.ActionStatusRunning,
	}); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled action poll returned %v, want context.Canceled", err)
	}
}

func TestProviderRejectsOversizedRRsetBeforeRequests(t *testing.T) {
	input := make([]libdns.Record, 0, 51)
	for i := range 51 {
		input = append(input, libdns.TXT{
			Name: "txt", TTL: time.Minute, Text: "value-" + strconv.Itoa(i),
		})
	}
	for _, operation := range []struct {
		name string
		call func(*hetznerProvider) error
	}{
		{
			name: "set",
			call: func(p *hetznerProvider) error {
				_, err := p.SetRecords(t.Context(), "example.com.", input)
				return err
			},
		},
		{
			name: "append",
			call: func(p *hetznerProvider) error {
				_, err := p.AppendRecords(t.Context(), "example.com.", input)
				return err
			},
		},
	} {
		t.Run(operation.name, func(t *testing.T) {
			p := newScriptedHetznerProvider(t, nil)
			if err := operation.call(p); err == nil || !strings.Contains(err.Error(), "50") {
				t.Fatalf("oversized RRset returned %v", err)
			}
		})
	}
}

func TestProviderRejectsOutOfRangeTTLBeforeRequests(t *testing.T) {
	input := []libdns.Record{libdns.TXT{
		Name: "txt",
		TTL:  time.Duration(records.MaxTTLSeconds+1) * time.Second,
		Text: "value",
	}}
	for _, operation := range []struct {
		name string
		call func(*hetznerProvider) error
	}{
		{
			name: "set",
			call: func(p *hetznerProvider) error {
				_, err := p.SetRecords(t.Context(), "example.com.", input)
				return err
			},
		},
		{
			name: "append",
			call: func(p *hetznerProvider) error {
				_, err := p.AppendRecords(t.Context(), "example.com.", input)
				return err
			},
		},
	} {
		t.Run(operation.name, func(t *testing.T) {
			p := newScriptedHetznerProvider(t, nil)
			if err := operation.call(p); err == nil || !strings.Contains(err.Error(), "ttl") {
				t.Fatalf("out-of-range TTL returned %v", err)
			}
		})
	}
}

func TestListZonesUsesAllPages(t *testing.T) {
	p := newScriptedHetznerProvider(t, []hcloudRequest{
		{
			method: http.MethodGet,
			path:   "/zones?page=1&per_page=50",
			response: `{
				"zones": [{"id":1,"name":"EXAMPLE.COM"}],
				"meta": {"pagination": {"page": 1, "next_page": 2}}
			}`,
		},
		{
			method: http.MethodGet,
			path:   "/zones?page=2&per_page=50",
			response: `{
				"zones": [{"id":2,"name":"other.example."}],
				"meta": {"pagination": {"page": 2}}
			}`,
		},
	})

	got, err := p.ListZones(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	want := []libdns.Zone{{Name: "example.com"}, {Name: "other.example"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("zones = %+v, want %+v", got, want)
	}
}

func TestHetznerProviderUsesCallerContext(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(server.Close)
	p := testHetznerProvider(server.URL)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := p.ListZones(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("ListZones error = %v, want context.Canceled", err)
	}
	if requests.Load() != 0 {
		t.Errorf("canceled operation made %d HTTP requests", requests.Load())
	}
}

func TestActionPollUsesCallerContext(t *testing.T) {
	started := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		close(started)
		<-r.Context().Done()
	}))
	t.Cleanup(server.Close)
	p := testHetznerProvider(server.URL)
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- p.waitForAction(ctx, &hcloud.Action{
			ID: 70, Status: hcloud.ActionStatusRunning,
		})
	}()

	select {
	case <-started:
		cancel()
	case <-time.After(time.Second):
		cancel()
		t.Fatal("action poll did not reach the HTTP server")
	}
	if err := <-errCh; !errors.Is(err, context.Canceled) {
		t.Fatalf("action poll returned %v, want context.Canceled", err)
	}
}

func TestHetznerProviderClientConstructionIsInjectable(t *testing.T) {
	client := hcloud.NewClient(hcloud.WithToken("injected"))
	var gotToken string
	p, err := newHetznerProviderWithFactory(
		json.RawMessage(`{"api_token":"configured"}`),
		func(token string) *hcloud.Client {
			gotToken = token
			return client
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if gotToken != "configured" || p.client != client {
		t.Errorf("factory got token %q and client %p; want configured and %p", gotToken, p.client, client)
	}
}

type hcloudRequest struct {
	method   string
	path     string
	body     string
	status   int
	response string
}

func newScriptedHetznerProvider(t *testing.T, expected []hcloudRequest) *hetznerProvider {
	t.Helper()
	var mu sync.Mutex
	next := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		if next >= len(expected) {
			mu.Unlock()
			t.Errorf("unexpected hcloud request %s %s", r.Method, r.URL.RequestURI())
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		want := expected[next]
		next++
		mu.Unlock()

		if r.Method != want.method || r.URL.RequestURI() != want.path {
			t.Errorf("hcloud request = %s %s, want %s %s", r.Method, r.URL.RequestURI(),
				want.method, want.path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
			t.Errorf("Authorization = %q, want bearer test token", got)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read hcloud request body: %v", err)
		}
		assertJSONBody(t, body, want.body)

		w.Header().Set("Content-Type", "application/json")
		status := want.status
		if status == 0 {
			status = http.StatusOK
		}
		w.WriteHeader(status)
		if _, err := io.WriteString(w, want.response); err != nil {
			t.Errorf("write hcloud response: %v", err)
		}
	}))
	t.Cleanup(func() {
		server.Close()
		mu.Lock()
		defer mu.Unlock()
		if next != len(expected) {
			t.Errorf("received %d hcloud requests, want %d", next, len(expected))
		}
	})
	return testHetznerProvider(server.URL)
}

func testHetznerProvider(endpoint string) *hetznerProvider {
	client := hcloud.NewClient(
		hcloud.WithEndpoint(endpoint),
		hcloud.WithToken("test-token"),
		hcloud.WithRetryOpts(hcloud.RetryOpts{MaxRetries: 0}),
	)
	return &hetznerProvider{APIToken: "test-token", client: client, actionPollInterval: 0}
}

func runningAction(id int) string {
	return `{"action":{"id":` + strconv.Itoa(id) + `,"status":"running"}}`
}

func waitForAction(id int) hcloudRequest {
	idText := strconv.Itoa(id)
	return hcloudRequest{
		method: http.MethodGet,
		path:   "/actions/" + idText,
		response: `{"action":{"id":` + idText +
			`,"status":"success","progress":100}}`,
	}
}

func failedAction(id int, code, message string) hcloudRequest {
	idText := strconv.Itoa(id)
	action := map[string]any{"id": id, "status": "error"}
	if code != "" || message != "" {
		action["error"] = map[string]string{"code": code, "message": message}
	}
	response, err := json.Marshal(map[string]any{
		"action": action,
	})
	if err != nil {
		panic(err)
	}
	return hcloudRequest{
		method:   http.MethodGet,
		path:     "/actions/" + idText,
		response: string(response),
	}
}

func assertJSONBody(t *testing.T, got []byte, want string) {
	t.Helper()
	if strings.TrimSpace(want) == "" {
		if strings.TrimSpace(string(got)) != "" {
			t.Errorf("request body = %s, want empty", got)
		}
		return
	}
	var gotValue, wantValue any
	if err := json.Unmarshal(got, &gotValue); err != nil {
		t.Errorf("request body is not JSON: %v: %s", err, got)
		return
	}
	if err := json.Unmarshal([]byte(want), &wantValue); err != nil {
		t.Fatalf("invalid expected JSON: %v: %s", err, want)
	}
	if !reflect.DeepEqual(gotValue, wantValue) {
		t.Errorf("request JSON = %s, want %s", got, want)
	}
}

func txtRecords(values ...string) []libdns.Record {
	result := make([]libdns.Record, 0, len(values))
	for _, value := range values {
		result = append(result, libdns.TXT{Name: "txt", TTL: time.Minute, Text: value})
	}
	return result
}

func recordsAsRRs(input []libdns.Record) []libdns.RR {
	result := make([]libdns.RR, 0, len(input))
	for _, record := range input {
		result = append(result, record.RR())
	}
	return result
}

func assertRRs(t *testing.T, got []libdns.Record, want []libdns.RR) {
	t.Helper()
	if gotRRs := recordsAsRRs(got); !reflect.DeepEqual(gotRRs, want) {
		t.Errorf("records = %+v, want %+v", gotRRs, want)
	}
}
