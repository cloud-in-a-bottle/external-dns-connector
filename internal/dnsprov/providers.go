package dnsprov

func secret(key, label, help string) Field {
	return Field{Key: key, Label: label, Required: true, Secret: true, Help: help}
}

func init() {
	register(Entry{
		Key: "hetzner", Label: "Hetzner",
		DocURL: "https://docs.hetzner.cloud/#getting-started",
		SourceURL: "https://github.com/hetznercloud/hcloud-go/blob/" +
			"7a591b7c57103f451f85e797f8818b38f0c3d1aa/hcloud/zone_rrset.go",
		Fields: []Field{secret("api_token", "API token", "")},
		New:    newHetznerProvider,
	})
}
