package config

import (
	"fmt"
	"os"
)

type Config struct {
	AppName    string
	AppID      string
	AppToken   string
	RouterURL  string
	ZoneDomain string
	SQLitePath string
	ListenAddr string
}

// Load reads the environment OpenHost injects. Anything the app genuinely needs is required: falling
// back to a default would turn a deploy misconfiguration into confusing runtime behavior later.
func Load() (Config, error) {
	sqlitePath, err := required("OPENHOST_SQLITE_MAIN")
	if err != nil {
		return Config{}, err
	}
	appName, err := required("OPENHOST_APP_NAME")
	if err != nil {
		return Config{}, err
	}
	listen := os.Getenv("LISTEN_ADDR")
	if listen == "" {
		listen = ":8080"
	}
	return Config{
		AppName:    appName,
		AppID:      os.Getenv("OPENHOST_APP_ID"),
		AppToken:   os.Getenv("OPENHOST_APP_TOKEN"),
		RouterURL:  os.Getenv("OPENHOST_ROUTER_URL"),
		ZoneDomain: os.Getenv("OPENHOST_ZONE_DOMAIN"),
		SQLitePath: sqlitePath,
		ListenAddr: listen,
	}, nil
}

func required(key string) (string, error) {
	v := os.Getenv(key)
	if v == "" {
		return "", fmt.Errorf("required environment variable %s is not set", key)
	}
	return v, nil
}
