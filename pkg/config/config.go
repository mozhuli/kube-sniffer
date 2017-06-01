package config

import (
	"io/ioutil"
	"time"

	"gopkg.in/yaml.v2"
)

var (
	// SniffInterfaces is the interfaces which kube-sniffer sniffs on (default: cali*)
	SniffInterfaces string
	// SniffFilter filter the packet to sniff
	SniffFilter string
	// ElasticsearchEndpoint is elasticsearch endpoint
	ElasticsearchEndpoint string
	// Timeout of sniffer report (default: -1s)
	Timeout time.Duration
	// SniffLength is the length of sniffing packet (default: 44)
	SniffLength int
	// Promiscuous open promiscuous mode
	Promiscuous bool
	// Debug enable debug output
	Debug bool
)

// Config is the internal representation of the yaml that determines how
// the app start
type Config struct {
	SniffInterfaces       string `yaml:"interfaces"`
	SniffFilter           string `yaml:"filter"`
	ElasticsearchEndpoint string `yaml:"endpoint"`
	Timeout               int    `yaml:"timeout"`
	SniffLength           int    `yaml:"length"`
	Promiscuous           bool   `yaml:"promiscuous"`
	Debug                 bool   `yaml:"debug"`
}

// ReadConfig reads from a file with the given name and returns a config or
// an error if the file was unable to be parsed.
func ReadConfig(filepath string) (*Config, error) {
	data, err := ioutil.ReadFile(filepath)
	if err != nil {
		return nil, err
	}
	config := Config{}
	err = yaml.Unmarshal(data, &config)
	if err != nil {
		return nil, err
	}
	return &config, err
}
