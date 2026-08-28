package lifecycle

import "time"

const (
	ProviderTimeout       = 20 * time.Second
	ServiceRequestTimeout = 25 * time.Second
	ShutdownTimeout       = 30 * time.Second
	ServerWriteTimeout    = 60 * time.Second
)
