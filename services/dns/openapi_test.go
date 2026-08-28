package dns_test

import (
	"encoding/json"
	"slices"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
)

const jsonContentType = "application/json"

type contractGetRequest struct {
	Zone string `json:"zone,omitempty"`
}

type contractGetRequestWithUnknownField struct {
	Unexpected bool `json:"unexpected"`
}

type contractRecord struct {
	Name string `json:"name"`
	Type string `json:"type"`
	TTL  int64  `json:"ttl"`
	Data string `json:"data"`
}

type contractRecordWithoutTTL struct {
	Name string `json:"name"`
	Type string `json:"type"`
	Data string `json:"data"`
}

type contractRecordWithNullTTL struct {
	Name string `json:"name"`
	Type string `json:"type"`
	TTL  *int64 `json:"ttl"`
	Data string `json:"data"`
}

type contractRecordWithStringTTL struct {
	Name string `json:"name"`
	Type string `json:"type"`
	TTL  string `json:"ttl"`
	Data string `json:"data"`
}

type contractRecordWithFloatTTL struct {
	Name string  `json:"name"`
	Type string  `json:"type"`
	TTL  float64 `json:"ttl"`
	Data string  `json:"data"`
}

type contractZoneResult struct {
	Zone    string           `json:"zone"`
	OK      bool             `json:"ok"`
	Records []contractRecord `json:"records"`
}

type contractResultsResponse struct {
	OK      bool                 `json:"ok"`
	Results []contractZoneResult `json:"results"`
}

type contractDeleteTarget struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

type contractExactDeleteTarget struct {
	Name string  `json:"name"`
	Type string  `json:"type"`
	TTL  int64   `json:"ttl"`
	Data *string `json:"data"`
}

type contractDeleteTargetWithNullTTL struct {
	Name string `json:"name"`
	Type string `json:"type"`
	TTL  *int64 `json:"ttl"`
}

type contractDeleteTargetWithStringTTL struct {
	Name string `json:"name"`
	Type string `json:"type"`
	TTL  string `json:"ttl"`
}

type contractDeleteTargetWithFloatTTL struct {
	Name string  `json:"name"`
	Type string  `json:"type"`
	TTL  float64 `json:"ttl"`
}

type contractGrant struct {
	Name   string `json:"name"`
	Type   string `json:"type"`
	Access string `json:"access"`
}

type contractGrantWithUnknownField struct {
	Name   string `json:"name"`
	Type   string `json:"type"`
	Access string `json:"access"`
	Extra  bool   `json:"extra"`
}

type contractZonesResponse struct {
	Zones []string `json:"zones"`
}

type contractRequiredGrant struct {
	Grant contractGrant `json:"grant"`
	Scope string        `json:"scope"`
}

type contractPermissionRequired struct {
	Error         string                `json:"error"`
	Message       string                `json:"message"`
	RequiredGrant contractRequiredGrant `json:"required_grant"`
}

type contractError struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}

func TestOpenAPIDocumentIsValid(t *testing.T) {
	loadDocument(t)
}

func TestGetBodyIsRequiredAndClosed(t *testing.T) {
	doc := loadDocument(t)
	operation := doc.Paths.Find("/records/get").Post
	if operation.RequestBody == nil || operation.RequestBody.Value == nil {
		t.Fatal("records/get has no request body")
	}
	if !operation.RequestBody.Value.Required {
		t.Fatal("records/get request body is optional")
	}

	schema := operation.RequestBody.Value.Content.Get(jsonContentType).Schema.Value
	assertAccepts(t, schema, contractGetRequest{})
	assertRejects(t, schema, contractGetRequestWithUnknownField{Unexpected: true})
}

func TestReadAndMutationRecordTypes(t *testing.T) {
	doc := loadDocument(t)
	readRecord := componentSchema(t, doc, "ReadRecord")
	readType := propertySchema(t, readRecord, "type")
	if readType.Type == nil || !readType.Type.Is("string") {
		t.Fatalf("ReadRecord.type is %v, want string", readType.Type)
	}
	if len(readType.Enum) != 0 {
		t.Fatalf("ReadRecord.type is restricted to %v", readType.Enum)
	}

	resultsSchema := doc.Components.Responses["Results"].Value.Content.Get(jsonContentType).Schema.Value
	assertAccepts(t, resultsSchema, contractResultsResponse{
		OK: true,
		Results: []contractZoneResult{{
			Zone: "example.com",
			OK:   true,
			Records: []contractRecord{{
				Name: "@", Type: "SOA", TTL: 300, Data: "ns1.example.com. hostmaster.example.com. 1 2 3 4 5",
			}},
		}},
	})

	writableTypes := []string{"A", "AAAA", "CAA", "CNAME", "MX", "NS", "SRV", "TXT"}
	for _, schemaName := range []string{"WriteRecord", "DeleteTarget"} {
		t.Run(schemaName, func(t *testing.T) {
			rrtype := propertySchema(t, componentSchema(t, doc, schemaName), "type")
			if got := enumStrings(t, rrtype); !slices.Equal(got, writableTypes) {
				t.Fatalf("%s.type enum = %v, want %v", schemaName, got, writableTypes)
			}
		})
	}

	writeRecord := componentSchema(t, doc, "WriteRecord")
	assertAccepts(t, writeRecord, contractRecord{Name: "www", Type: "A", TTL: 300, Data: "192.0.2.1"})
	assertRejects(t, writeRecord, contractRecord{Name: "@", Type: "SOA", TTL: 300, Data: "soa data"})
}

func TestWriteRecordTTLContract(t *testing.T) {
	schema := componentSchema(t, loadDocument(t), "WriteRecord")
	for _, ttl := range []int64{1, 4294967295} {
		assertAccepts(t, schema, contractRecord{Name: "www", Type: "A", TTL: ttl, Data: "192.0.2.1"})
	}
	for _, ttl := range []int64{-1, 0, 4294967296} {
		assertRejects(t, schema, contractRecord{Name: "www", Type: "A", TTL: ttl, Data: "192.0.2.1"})
	}
	assertRejects(t, schema, contractRecordWithoutTTL{Name: "www", Type: "A", Data: "192.0.2.1"})
	assertRejects(t, schema, contractRecordWithNullTTL{
		Name: "www", Type: "A", TTL: nil, Data: "192.0.2.1",
	})
	assertRejects(t, schema, contractRecordWithStringTTL{
		Name: "www", Type: "A", TTL: "60", Data: "192.0.2.1",
	})
	assertRejects(t, schema, contractRecordWithFloatTTL{
		Name: "www", Type: "A", TTL: 1.5, Data: "192.0.2.1",
	})
}

func TestDeleteTargetDataContract(t *testing.T) {
	doc := loadDocument(t)
	schema := componentSchema(t, doc, "DeleteTarget")
	assertAccepts(t, schema, contractDeleteTarget{Name: "_acme-challenge", Type: "TXT"})

	value := "token"
	assertAccepts(t, schema, contractExactDeleteTarget{
		Name: "_acme-challenge", Type: "TXT", TTL: 999, Data: &value,
	})
	for _, invalid := range []*string{stringPointer(""), stringPointer(" \t\n"), nil} {
		assertRejects(t, schema, contractExactDeleteTarget{
			Name: "_acme-challenge", Type: "TXT", TTL: 60, Data: invalid,
		})
	}
}

func TestDeleteTargetTTLContract(t *testing.T) {
	schema := componentSchema(t, loadDocument(t), "DeleteTarget")
	assertAccepts(t, schema, contractDeleteTarget{Name: "_acme-challenge", Type: "TXT"})
	for _, ttl := range []int64{1, 4294967295} {
		assertAccepts(t, schema, contractExactDeleteTarget{
			Name: "_acme-challenge", Type: "TXT", TTL: ttl, Data: stringPointer("token"),
		})
	}
	for _, ttl := range []int64{-1, 0, 4294967296} {
		assertRejects(t, schema, contractExactDeleteTarget{
			Name: "_acme-challenge", Type: "TXT", TTL: ttl, Data: stringPointer("token"),
		})
	}
	assertRejects(t, schema, contractDeleteTargetWithNullTTL{
		Name: "_acme-challenge", Type: "TXT", TTL: nil,
	})
	assertRejects(t, schema, contractDeleteTargetWithStringTTL{
		Name: "_acme-challenge", Type: "TXT", TTL: "60",
	})
	assertRejects(t, schema, contractDeleteTargetWithFloatTTL{
		Name: "_acme-challenge", Type: "TXT", TTL: 1.5,
	})
}

func TestZonesResponseAllowsAnEmptyList(t *testing.T) {
	doc := loadDocument(t)
	response := doc.Paths.Find("/zones").Post.Responses.Value("200").Value
	schema := response.Content.Get(jsonContentType).Schema.Value
	assertAccepts(t, schema, contractZonesResponse{Zones: []string{}})
}

func TestGrantSchemaIsClosedAndRejectsWildcardFragmentsInType(t *testing.T) {
	schema := componentSchema(t, loadDocument(t), "Grant")
	assertAccepts(t, schema, contractGrant{Name: "home", Type: "txt", Access: "r"})
	assertRejects(t, schema, contractGrant{Name: "home", Type: "A**", Access: "r"})
	assertRejects(t, schema, contractGrantWithUnknownField{
		Name: "home", Type: "A", Access: "r", Extra: true,
	})
}

func TestForbiddenResponseShapes(t *testing.T) {
	doc := loadDocument(t)
	schema := doc.Components.Responses["Forbidden"].Value.Content.Get(jsonContentType).Schema.Value

	assertAccepts(t, schema, contractPermissionRequired{
		Error:   "permission_required",
		Message: "grant required",
		RequiredGrant: contractRequiredGrant{
			Grant: contractGrant{Name: "www", Type: "A", Access: "rw"},
			Scope: "global",
		},
	})
	assertRejects(t, schema, contractError{Error: "permission_required", Message: "grant required"})
	assertAccepts(t, schema, contractError{
		Error: "not_a_service_call", Message: "this endpoint requires a service consumer",
	})
}

func TestInternalErrorsAreDocumented(t *testing.T) {
	doc := loadDocument(t)
	paths := []string{"/zones", "/records/get", "/records/set", "/records/append", "/records/delete"}
	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			operation := doc.Paths.Find(path).Post
			response := operation.Responses.Value("500")
			if response == nil || response.Value == nil {
				t.Fatalf("POST %s does not document a 500 response", path)
			}
			assertAccepts(t, response.Value.Content.Get(jsonContentType).Schema.Value, contractError{
				Error: "internal_error", Message: "storage failed",
			})
		})
	}
}

func loadDocument(t *testing.T) *openapi3.T {
	t.Helper()
	doc, err := openapi3.NewLoader().LoadFromFile("openapi.yaml")
	if err != nil {
		t.Fatalf("load OpenAPI document: %v", err)
	}
	if err := doc.Validate(t.Context()); err != nil {
		t.Fatalf("validate OpenAPI document: %v", err)
	}
	return doc
}

func componentSchema(t *testing.T, doc *openapi3.T, name string) *openapi3.Schema {
	t.Helper()
	ref := doc.Components.Schemas[name]
	if ref == nil || ref.Value == nil {
		t.Fatalf("component schema %q is missing", name)
	}
	return ref.Value
}

func propertySchema(t *testing.T, schema *openapi3.Schema, name string) *openapi3.Schema {
	t.Helper()
	ref := schema.Properties[name]
	if ref == nil || ref.Value == nil {
		t.Fatalf("schema property %q is missing", name)
	}
	return ref.Value
}

func enumStrings(t *testing.T, schema *openapi3.Schema) []string {
	t.Helper()
	values := make([]string, 0, len(schema.Enum))
	for _, value := range schema.Enum {
		text, ok := value.(string)
		if !ok {
			t.Fatalf("enum value %v is not a string", value)
		}
		values = append(values, text)
	}
	return values
}

func assertAccepts(t *testing.T, schema *openapi3.Schema, value any) {
	t.Helper()
	if err := schema.VisitJSON(jsonValue(t, value)); err != nil {
		t.Fatalf("schema rejected valid value: %v", err)
	}
}

func assertRejects(t *testing.T, schema *openapi3.Schema, value any) {
	t.Helper()
	if err := schema.VisitJSON(jsonValue(t, value)); err == nil {
		t.Fatal("schema accepted invalid value")
	}
}

func jsonValue(t *testing.T, value any) any {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var decoded any
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	return decoded
}

func stringPointer(value string) *string {
	return &value
}
