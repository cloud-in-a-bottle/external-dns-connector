package dnsprov

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/hetznercloud/hcloud-go/v2/hcloud"
	"github.com/libdns/libdns"

	"github.com/cloud-in-a-bottle/external-dns-connector/internal/records"
)

const (
	hetznerApplication         = "github.com/cloud-in-a-bottle/external-dns-connector"
	hetznerActionPollInterval  = 500 * time.Millisecond
	dnsCharacterStringMaxBytes = 255
)

type hetznerProvider struct {
	APIToken string `json:"api_token,omitempty"`

	client             *hcloud.Client
	actionPollInterval time.Duration
	zoneTTLs           sync.Map
	rawRecordsMu       sync.RWMutex
	rawRecords         map[hetznerRawRecordKey][]hcloud.ZoneRRSetRecord
}

type hetznerClientFactory func(token string) *hcloud.Client

func newHetznerProvider(_ Deps, credentials json.RawMessage) (any, error) {
	return newHetznerProviderWithFactory(credentials, func(token string) *hcloud.Client {
		return hcloud.NewClient(
			hcloud.WithToken(token),
			hcloud.WithApplication(hetznerApplication, ""),
		)
	})
}

func newHetznerProviderWithFactory(
	credentials json.RawMessage,
	newClient hetznerClientFactory,
) (*hetznerProvider, error) {
	p := new(hetznerProvider)
	if len(credentials) > 0 {
		if err := json.Unmarshal(credentials, p); err != nil {
			return nil, err
		}
	}
	if strings.TrimSpace(p.APIToken) == "" {
		return nil, fmt.Errorf("API token is required")
	}
	if newClient == nil {
		return nil, fmt.Errorf("hcloud client factory is required")
	}
	p.client = newClient(p.APIToken)
	if p.client == nil {
		return nil, fmt.Errorf("construct hcloud client")
	}
	p.actionPollInterval = hetznerActionPollInterval
	return p, nil
}

func (p *hetznerProvider) GetRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	zone, err := records.ValidateZone(zone)
	if err != nil {
		return nil, err
	}
	hcloudZone, _, err := p.client.Zone.GetByName(ctx, zone)
	if err != nil {
		return nil, fmt.Errorf("get Hetzner zone %s: %w", zone, err)
	}
	if hcloudZone == nil {
		return nil, fmt.Errorf("Hetzner zone %s not found", zone)
	}
	p.zoneTTLs.Store(zone, hcloudZone.TTL)

	sets, err := p.client.Zone.AllRRSets(ctx, &hcloud.Zone{Name: zone})
	if err != nil {
		return nil, fmt.Errorf("list Hetzner RRsets for %s: %w", zone, err)
	}
	result := make([]libdns.Record, 0, hcloudZone.RecordCount)
	rawRecords := make(map[hetznerRawRecordKey][]hcloud.ZoneRRSetRecord)
	for _, set := range sets {
		ttl := hcloudZone.TTL
		if set.TTL != nil {
			ttl = *set.TTL
		}
		for _, value := range set.Records {
			record, err := hetznerRecordToLibDNS(set.Name, set.Type, ttl, value.Value)
			if err != nil {
				return nil, fmt.Errorf("parse Hetzner RRset %s/%s: %w", set.Name, set.Type, err)
			}
			result = append(result, record)
			key := newHetznerRawRecordKey(zone, record)
			rawRecords[key] = append(rawRecords[key], value)
		}
	}
	p.replaceRawRecords(zone, rawRecords)
	return result, nil
}

func (p *hetznerProvider) AppendRecords(
	ctx context.Context,
	zone string,
	recordsToAppend []libdns.Record,
) ([]libdns.Record, error) {
	zone, sets, err := groupHetznerRecords(zone, recordsToAppend, true)
	if err != nil {
		return nil, err
	}

	var appended []libdns.Record
	for _, set := range sets {
		target := set.target(zone)
		ttl := set.ttl
		action, _, err := p.client.Zone.AddRRSetRecords(ctx, target, hcloud.ZoneRRSetAddRecordsOpts{
			Records: set.values,
			TTL:     &ttl,
		})
		if err != nil {
			return appended, fmt.Errorf("append Hetzner RRset %s/%s: %w", set.name, set.rrtype, err)
		}
		if err := p.waitForAction(ctx, action); err != nil {
			return appended, fmt.Errorf("wait for Hetzner RRset %s/%s append: %w", set.name, set.rrtype, err)
		}
		appended = append(appended, set.records...)
	}
	return appended, nil
}

func (p *hetznerProvider) SetRecords(
	ctx context.Context,
	zone string,
	recordsToSet []libdns.Record,
) ([]libdns.Record, error) {
	zone, sets, err := groupHetznerRecords(zone, recordsToSet, true)
	if err != nil {
		return nil, err
	}

	var applied []libdns.Record
	for _, set := range sets {
		target := set.target(zone)
		existing, _, err := p.client.Zone.GetRRSetByNameAndType(ctx, target.Zone, set.name, set.rrtype)
		if err != nil {
			return applied, fmt.Errorf("get Hetzner RRset %s/%s: %w", set.name, set.rrtype, err)
		}
		if existing == nil {
			created, _, err := p.client.Zone.CreateRRSet(ctx, target.Zone, hcloud.ZoneRRSetCreateOpts{
				Name:    set.name,
				Type:    set.rrtype,
				TTL:     &set.ttl,
				Records: set.values,
			})
			if err != nil {
				return applied, fmt.Errorf("create Hetzner RRset %s/%s: %w", set.name, set.rrtype, err)
			}
			if err := p.waitForAction(ctx, created.Action); err != nil {
				return applied, fmt.Errorf(
					"wait for Hetzner RRset %s/%s creation: %w",
					set.name,
					set.rrtype,
					err,
				)
			}
			applied = append(applied, set.records...)
			continue
		}
		if err := set.preserveComments(existing); err != nil {
			return applied, fmt.Errorf("preserve Hetzner RRset %s/%s comments: %w",
				set.name, set.rrtype, err)
		}
		action, _, err := p.client.Zone.SetRRSetRecords(ctx, target, hcloud.ZoneRRSetSetRecordsOpts{
			Records: set.values,
		})
		if err != nil {
			return applied, fmt.Errorf("set Hetzner RRset %s/%s values: %w", set.name, set.rrtype, err)
		}
		if err := p.waitForAction(ctx, action); err != nil {
			return applied, fmt.Errorf(
				"wait for Hetzner RRset %s/%s value change: %w",
				set.name,
				set.rrtype,
				err,
			)
		}

		ttlAction, _, err := p.client.Zone.ChangeRRSetTTL(ctx, target, hcloud.ZoneRRSetChangeTTLOpts{
			TTL: &set.ttl,
		})
		if err != nil {
			return applied, fmt.Errorf("set Hetzner RRset %s/%s TTL: %w", set.name, set.rrtype, err)
		}
		if err := p.waitForAction(ctx, ttlAction); err != nil {
			return applied, fmt.Errorf(
				"wait for Hetzner RRset %s/%s TTL change: %w",
				set.name,
				set.rrtype,
				err,
			)
		}
		applied = append(applied, set.records...)
	}
	return applied, nil
}

func (p *hetznerProvider) DeleteRecords(
	ctx context.Context,
	zone string,
	recordsToDelete []libdns.Record,
) ([]libdns.Record, error) {
	for i, record := range recordsToDelete {
		if record == nil {
			return nil, fmt.Errorf("record %d is nil", i)
		}
		rr := record.RR()
		if strings.TrimSpace(rr.Type) == "" || rr.Data == "" {
			return nil, fmt.Errorf(
				"record %d uses unsupported libdns wildcard delete fields",
				i,
			)
		}
	}
	zone, sets, err := groupHetznerDeleteRecords(zone, recordsToDelete)
	if err != nil {
		return nil, err
	}
	matched, err := p.matchDeleteRecords(ctx, zone, sets)
	if err != nil {
		return nil, err
	}
	return p.removeHetznerRecords(ctx, zone, matched)
}

// DeleteRecordsExact is the planner-only path for records matched by this instance's fresh read.
func (p *hetznerProvider) DeleteRecordsExact(
	ctx context.Context,
	zone string,
	recordsToDelete []libdns.Record,
) ([]libdns.Record, error) {
	zone, sets, err := groupHetznerDeleteRecords(zone, recordsToDelete)
	if err != nil {
		return nil, err
	}
	if err := p.useRawRecordsForExactDelete(zone, sets); err != nil {
		return nil, err
	}
	return p.removeHetznerRecords(ctx, zone, sets)
}

func (p *hetznerProvider) matchDeleteRecords(
	ctx context.Context,
	zone string,
	requested []*hetznerRRSet,
) ([]*hetznerRRSet, error) {
	matched := make([]*hetznerRRSet, 0, len(requested))
	for _, set := range requested {
		existing, _, err := p.client.Zone.GetRRSetByNameAndType(
			ctx,
			&hcloud.Zone{Name: zone},
			set.name,
			set.rrtype,
		)
		if err != nil {
			return nil, fmt.Errorf("get Hetzner RRset %s/%s for delete: %w",
				set.name, set.rrtype, err)
		}
		if existing == nil {
			continue
		}
		ttl, err := p.resolveRRsetTTL(ctx, zone, existing)
		if err != nil {
			return nil, fmt.Errorf("resolve Hetzner RRset %s/%s TTL: %w",
				set.name, set.rrtype, err)
		}

		existingByValue := make(map[string][]hcloud.ZoneRRSetRecord, len(existing.Records))
		for _, record := range existing.Records {
			value, err := logicalHetznerValue(set.rrtype, record.Value)
			if err != nil {
				return nil, fmt.Errorf("decode Hetzner RRset %s/%s value: %w",
					set.name, set.rrtype, err)
			}
			existingByValue[value] = append(existingByValue[value], record)
		}

		matches := &hetznerRRSet{name: set.name, rrtype: set.rrtype}
		matchedValues := make(map[string]bool)
		for _, requestedRecord := range set.records {
			rr := requestedRecord.RR()
			if rr.TTL != 0 && rr.TTL != time.Duration(ttl)*time.Second {
				continue
			}
			if matchedValues[rr.Data] {
				continue
			}
			for _, existingRecord := range existingByValue[rr.Data] {
				matchedRecord, err := hetznerRecordToLibDNS(
					set.name,
					set.rrtype,
					ttl,
					existingRecord.Value,
				)
				if err != nil {
					return nil, err
				}
				matches.values = append(matches.values, existingRecord)
				matches.records = append(matches.records, matchedRecord)
			}
			matchedValues[rr.Data] = true
		}
		if len(matches.records) > 0 {
			matched = append(matched, matches)
		}
	}
	return matched, nil
}

func (p *hetznerProvider) resolveRRsetTTL(
	ctx context.Context,
	zone string,
	set *hcloud.ZoneRRSet,
) (int, error) {
	if ttl, ok := p.knownRRsetTTL(zone, set); ok {
		return ttl, nil
	}
	hcloudZone, _, err := p.client.Zone.GetByName(ctx, zone)
	if err != nil {
		return 0, err
	}
	if hcloudZone == nil {
		return 0, fmt.Errorf("Hetzner zone %s not found", zone)
	}
	p.zoneTTLs.Store(zone, hcloudZone.TTL)
	return hcloudZone.TTL, nil
}

func (p *hetznerProvider) removeHetznerRecords(
	ctx context.Context,
	zone string,
	sets []*hetznerRRSet,
) ([]libdns.Record, error) {
	var deleted []libdns.Record
	for _, set := range sets {
		action, _, err := p.client.Zone.RemoveRRSetRecords(
			ctx,
			set.target(zone),
			hcloud.ZoneRRSetRemoveRecordsOpts{Records: set.values},
		)
		if err != nil {
			if hcloud.IsError(err, hcloud.ErrorCodeNotFound) {
				continue
			}
			return deleted, fmt.Errorf("delete from Hetzner RRset %s/%s: %w", set.name, set.rrtype, err)
		}
		if err := p.waitForAction(ctx, action); err != nil {
			return deleted, fmt.Errorf("wait for Hetzner RRset %s/%s delete: %w", set.name, set.rrtype, err)
		}
		deleted = append(deleted, set.records...)
	}
	return deleted, nil
}

func (p *hetznerProvider) ListZones(ctx context.Context) ([]libdns.Zone, error) {
	zones, err := p.client.Zone.All(ctx)
	if err != nil {
		return nil, fmt.Errorf("list Hetzner zones: %w", err)
	}
	result := make([]libdns.Zone, 0, len(zones))
	for _, zone := range zones {
		result = append(result, libdns.Zone{Name: records.NormalizeZone(zone.Name)})
	}
	return result, nil
}

func (p *hetznerProvider) waitForAction(ctx context.Context, action *hcloud.Action) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if action == nil {
			return fmt.Errorf("Hetzner API returned no action")
		}
		if action.ID <= 0 {
			return fmt.Errorf("Hetzner API returned an action without an ID")
		}
		switch action.Status {
		case hcloud.ActionStatusSuccess:
			return nil
		case hcloud.ActionStatusError:
			if action.ErrorCode == "" && action.ErrorMessage == "" {
				return fmt.Errorf("Hetzner action %d failed without error details", action.ID)
			}
			return fmt.Errorf(
				"Hetzner action %d failed: code=%q message=%q",
				action.ID,
				action.ErrorCode,
				action.ErrorMessage,
			)
		case hcloud.ActionStatusRunning:
			actionID := action.ID
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(p.actionPollInterval):
			}
			updated, _, err := p.client.Action.GetByID(ctx, actionID)
			if err != nil {
				return fmt.Errorf("poll Hetzner action %d: %w", actionID, err)
			}
			if updated == nil {
				return fmt.Errorf("Hetzner action %d disappeared while polling", actionID)
			}
			if updated.ID != actionID {
				return fmt.Errorf("polled Hetzner action %d but received action %d",
					actionID, updated.ID)
			}
			action = updated
		default:
			return fmt.Errorf("Hetzner action %d has unknown status %q", action.ID, action.Status)
		}
	}
}

type hetznerRRSet struct {
	name    string
	rrtype  hcloud.ZoneRRSetType
	ttl     int
	values  []hcloud.ZoneRRSetRecord
	records []libdns.Record
}

type hetznerRRSetKey struct {
	name   string
	rrtype hcloud.ZoneRRSetType
}

type hetznerRawRecordKey struct {
	zone   string
	name   string
	rrtype string
	ttl    time.Duration
	data   string
}

func (s *hetznerRRSet) target(zone string) *hcloud.ZoneRRSet {
	return &hcloud.ZoneRRSet{
		Zone: &hcloud.Zone{Name: zone},
		Name: s.name,
		Type: s.rrtype,
	}
}

func (s *hetznerRRSet) preserveComments(existing *hcloud.ZoneRRSet) error {
	comments := make(map[string]string, len(existing.Records))
	for _, record := range existing.Records {
		value, err := logicalHetznerValue(s.rrtype, record.Value)
		if err != nil {
			return err
		}
		comments[value] = record.Comment
	}
	for i, record := range s.records {
		if comment, ok := comments[record.RR().Data]; ok {
			s.values[i].Comment = comment
		}
	}
	return nil
}

func (p *hetznerProvider) knownRRsetTTL(zone string, set *hcloud.ZoneRRSet) (int, bool) {
	if set.TTL != nil {
		return *set.TTL, true
	}
	stored, ok := p.zoneTTLs.Load(zone)
	if !ok {
		return 0, false
	}
	ttl, ok := stored.(int)
	return ttl, ok
}

func logicalHetznerValue(rrtype hcloud.ZoneRRSetType, value string) (string, error) {
	if strings.EqualFold(string(rrtype), "TXT") {
		return decodeHetznerTXT(value)
	}
	return value, nil
}

func newHetznerRawRecordKey(zone string, record libdns.Record) hetznerRawRecordKey {
	rr := record.RR()
	return hetznerRawRecordKey{
		zone: zone, name: rr.Name, rrtype: rr.Type, ttl: rr.TTL, data: rr.Data,
	}
}

func (p *hetznerProvider) replaceRawRecords(
	zone string,
	replacement map[hetznerRawRecordKey][]hcloud.ZoneRRSetRecord,
) {
	p.rawRecordsMu.Lock()
	defer p.rawRecordsMu.Unlock()
	if p.rawRecords == nil {
		p.rawRecords = make(map[hetznerRawRecordKey][]hcloud.ZoneRRSetRecord)
	}
	for key := range p.rawRecords {
		if key.zone == zone {
			delete(p.rawRecords, key)
		}
	}
	for key, values := range replacement {
		p.rawRecords[key] = append([]hcloud.ZoneRRSetRecord(nil), values...)
	}
}

func (p *hetznerProvider) useRawRecordsForExactDelete(
	zone string,
	sets []*hetznerRRSet,
) error {
	p.rawRecordsMu.RLock()
	defer p.rawRecordsMu.RUnlock()
	used := make(map[hetznerRawRecordKey]int)
	for _, set := range sets {
		rawValues := make([]hcloud.ZoneRRSetRecord, 0, len(set.records))
		for _, record := range set.records {
			key := newHetznerRawRecordKey(zone, record)
			index := used[key]
			values := p.rawRecords[key]
			if index >= len(values) {
				return fmt.Errorf("no raw Hetzner value for exact delete of %s/%s",
					set.name, set.rrtype)
			}
			rawValues = append(rawValues, values[index])
			used[key]++
		}
		set.values = rawValues
	}
	return nil
}

func groupHetznerRecords(
	zone string,
	input []libdns.Record,
	requireTTL bool,
) (string, []*hetznerRRSet, error) {
	zone, err := records.ValidateZone(zone)
	if err != nil {
		return "", nil, err
	}
	byKey := make(map[hetznerRRSetKey]*hetznerRRSet)
	sets := make([]*hetznerRRSet, 0)
	for i, record := range input {
		normalized, value, ttl, err := libDNSRecordToHetzner(zone, record, requireTTL)
		if err != nil {
			return "", nil, fmt.Errorf("record %d: %w", i, err)
		}
		rr := normalized.RR()
		key := hetznerRRSetKey{name: rr.Name, rrtype: hcloud.ZoneRRSetType(rr.Type)}
		set, ok := byKey[key]
		if !ok {
			set = &hetznerRRSet{name: key.name, rrtype: key.rrtype, ttl: ttl}
			byKey[key] = set
			sets = append(sets, set)
		} else if requireTTL && set.ttl != ttl {
			return "", nil, fmt.Errorf(
				"Hetzner RRset %s/%s has conflicting TTLs %d and %d seconds",
				set.name,
				set.rrtype,
				set.ttl,
				ttl,
			)
		}
		set.values = append(set.values, hcloud.ZoneRRSetRecord{Value: value})
		set.records = append(set.records, normalized)
		if requireTTL && len(set.records) > records.MaxRRSetMembers {
			return "", nil, fmt.Errorf(
				"Hetzner RRset %s/%s has more than %d members",
				set.name,
				set.rrtype,
				records.MaxRRSetMembers,
			)
		}
	}
	return zone, sets, nil
}

func groupHetznerDeleteRecords(
	zone string,
	input []libdns.Record,
) (string, []*hetznerRRSet, error) {
	zone, err := records.ValidateZone(zone)
	if err != nil {
		return "", nil, err
	}
	byKey := make(map[hetznerRRSetKey]*hetznerRRSet)
	sets := make([]*hetznerRRSet, 0)
	for i, record := range input {
		if record == nil {
			return "", nil, fmt.Errorf("record %d is nil", i)
		}
		rr := record.RR()
		name, err := records.NormalizeName(rr.Name, zone)
		if err != nil {
			return "", nil, fmt.Errorf("record %d: %w", i, err)
		}
		rrtype, err := records.NormalizeType(rr.Type)
		if err != nil {
			return "", nil, fmt.Errorf("record %d: %w", i, err)
		}
		normalized := libdns.RR{
			Name: name, Type: rrtype, TTL: rr.TTL, Data: rr.Data,
		}
		key := hetznerRRSetKey{name: name, rrtype: hcloud.ZoneRRSetType(rrtype)}
		set, ok := byKey[key]
		if !ok {
			set = &hetznerRRSet{name: name, rrtype: key.rrtype}
			byKey[key] = set
			sets = append(sets, set)
		}
		set.records = append(set.records, normalized)
	}
	return zone, sets, nil
}

func libDNSRecordToHetzner(
	zone string,
	record libdns.Record,
	requireTTL bool,
) (libdns.Record, string, int, error) {
	if record == nil {
		return nil, "", 0, fmt.Errorf("record is nil")
	}
	rr := record.RR()
	name, err := records.NormalizeName(rr.Name, zone)
	if err != nil {
		return nil, "", 0, err
	}
	rrtype, err := records.NormalizeType(rr.Type)
	if err != nil {
		return nil, "", 0, err
	}

	ttl := 0
	if requireTTL {
		seconds := int64(rr.TTL / time.Second)
		if seconds < records.MinTTLSeconds || seconds > records.MaxTTLSeconds {
			return nil, "", 0, fmt.Errorf(
				"record %s/%s ttl must be between %d and %d seconds",
				name,
				rrtype,
				records.MinTTLSeconds,
				records.MaxTTLSeconds,
			)
		}
		ttl = int(seconds)
		if int64(ttl) != seconds {
			return nil, "", 0, fmt.Errorf("record %s/%s ttl does not fit an int", name, rrtype)
		}
		rr.TTL = time.Duration(seconds) * time.Second
	}
	rr.Name = name
	rr.Type = rrtype
	normalized, err := rr.Parse()
	if err != nil {
		return nil, "", 0, fmt.Errorf("record %s/%s has invalid data %q: %w", name, rrtype, rr.Data, err)
	}
	parsed := normalized.RR()
	if parsed.Name != name || parsed.Type != rrtype {
		return nil, "", 0, fmt.Errorf(
			"record %s/%s changed to %s/%s while parsing",
			name,
			rrtype,
			parsed.Name,
			parsed.Type,
		)
	}

	value := parsed.Data
	if rrtype == "TXT" {
		value = encodeHetznerTXT(value)
	}
	return normalized, value, ttl, nil
}

func hetznerRecordToLibDNS(
	name string,
	rrtype hcloud.ZoneRRSetType,
	ttl int,
	value string,
) (libdns.Record, error) {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" {
		name = records.Apex
	}
	typeName := strings.ToUpper(strings.TrimSpace(string(rrtype)))
	if typeName == "" {
		return nil, fmt.Errorf("record type is empty")
	}
	if ttl < 0 || int64(ttl) > records.MaxTTLSeconds {
		return nil, fmt.Errorf("ttl %d is outside the Hetzner range", ttl)
	}
	if typeName == "TXT" {
		var err error
		value, err = decodeHetznerTXT(value)
		if err != nil {
			return nil, err
		}
	}
	raw := libdns.RR{
		Name: name,
		Type: typeName,
		TTL:  time.Duration(ttl) * time.Second,
		Data: value,
	}
	parsed, err := raw.Parse()
	if err != nil {
		return raw, nil
	}
	parsedRR := parsed.RR()
	if parsedRR.Name != raw.Name || parsedRR.Type != raw.Type ||
		parsedRR.Data != raw.Data || parsedRR.TTL != raw.TTL {
		return raw, nil
	}
	return parsed, nil
}

func decodeHetznerTXT(value string) (string, error) {
	if value == "" || value[0] != '"' {
		return value, nil
	}

	var decoded strings.Builder
	position := 0
	for {
		if position >= len(value) || value[position] != '"' {
			return "", fmt.Errorf("invalid TXT zone-file value %q", value)
		}
		position++
		for {
			if position >= len(value) {
				return "", fmt.Errorf("invalid TXT zone-file value %q", value)
			}
			character := value[position]
			position++
			switch character {
			case '"':
				goto stringComplete
			case '\\':
				if position >= len(value) {
					return "", fmt.Errorf("invalid TXT zone-file value %q", value)
				}
				if position+2 < len(value) && isDecimalDigit(value[position]) &&
					isDecimalDigit(value[position+1]) && isDecimalDigit(value[position+2]) {
					decimal := int(value[position]-'0')*100 +
						int(value[position+1]-'0')*10 + int(value[position+2]-'0')
					if decimal > 255 {
						return "", fmt.Errorf("TXT decimal escape %d exceeds 255", decimal)
					}
					decoded.WriteByte(byte(decimal))
					position += 3
					continue
				}
				decoded.WriteByte(value[position])
				position++
			default:
				decoded.WriteByte(character)
			}
		}

	stringComplete:
		for position < len(value) && isZoneWhitespace(value[position]) {
			position++
		}
		if position == len(value) {
			return decoded.String(), nil
		}
	}
}

func encodeHetznerTXT(value string) string {
	if value == "" {
		return `""`
	}

	data := []byte(value)
	var encoded strings.Builder
	for offset := 0; offset < len(data); offset += dnsCharacterStringMaxBytes {
		end := min(offset+dnsCharacterStringMaxBytes, len(data))
		if offset > 0 {
			encoded.WriteByte(' ')
		}
		encoded.WriteByte('"')
		for _, character := range data[offset:end] {
			switch {
			case character == '"' || character == '\\':
				encoded.WriteByte('\\')
				encoded.WriteByte(character)
			case character < 0x20 || character > 0x7e:
				encoded.WriteByte('\\')
				encoded.WriteByte('0' + character/100)
				encoded.WriteByte('0' + character/10%10)
				encoded.WriteByte('0' + character%10)
			default:
				encoded.WriteByte(character)
			}
		}
		encoded.WriteByte('"')
	}
	return encoded.String()
}

func isDecimalDigit(character byte) bool {
	return character >= '0' && character <= '9'
}

func isZoneWhitespace(character byte) bool {
	return character == ' ' || character == '\t' || character == '\r' || character == '\n'
}

var (
	_ libdns.RecordGetter   = (*hetznerProvider)(nil)
	_ libdns.RecordAppender = (*hetznerProvider)(nil)
	_ libdns.RecordSetter   = (*hetznerProvider)(nil)
	_ libdns.RecordDeleter  = (*hetznerProvider)(nil)
	_ libdns.ZoneLister     = (*hetznerProvider)(nil)
)
