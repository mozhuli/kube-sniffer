package config

import (
	"time"
)

var (
	Devices        string        = "eth0"
	Filter         string        = "tcp and port 80"
	SnapshotLength int32         = 60
	Promiscuous    bool          = false
	Timeout        time.Duration = -1 * time.Second
	File           string
)
