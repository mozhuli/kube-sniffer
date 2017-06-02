package main

import (
	"os"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/mozhuli/kube-sniffer/pkg/config"
	"github.com/urfave/cli"
)

const (
	defaultTimeout = -1 * time.Second
)

// VERSION is the version of kube-sniffer
var VERSION string

func main() {
	app := cli.NewApp()
	app.Name = "kube-sniffer"
	app.Usage = "kube-sniffer sniff --interfaces cali* --filter \"tcp[13] == 0x12\" --endpoint localhost:9200"
	app.Version = VERSION

	app.Commands = []cli.Command{
		listInterfacesCommand,
		sniffCommand,
	}

	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:   "config-file, c",
			EnvVar: "SNIFFER_CONFIG_FILE",
			Value:  "/etc/kube-sniffer.yaml",
			Usage:  "config file for kube-sniffer",
		},
		cli.StringFlag{
			Name:   "interfaces, i",
			EnvVar: "SNIffER_INTERFACES",
			Value:  "cali*",
			Usage:  "the interfaces to use,Regular expression can be used eg. cali*",
		},
		cli.StringFlag{
			Name:   "endpoint, e",
			EnvVar: "ES-ENDPOINT",
			Usage:  "elasticsearch endpoint",
		},
		cli.BoolFlag{
			Name:   "promiscuous, p",
			EnvVar: "SNIFFER_PROMISCUOUS",
			Usage:  "Enable promiscuous mode",
		},
		cli.StringFlag{
			Name:   "filter, f",
			EnvVar: "SNIFFER_FILTER",
			Value:  "tcp[13] == 0x12",
			Usage:  "the BPF syntax parameters to sniff on",
		},
		cli.IntFlag{
			Name:   "length, l",
			EnvVar: "SNIFFER_LENGTH",
			Value:  54,
			Usage:  "length of sniffing packet",
		},

		cli.DurationFlag{
			Name:  "timeout, t",
			Value: defaultTimeout,
			Usage: "Timeout of sniffer report",
		},
		cli.BoolFlag{
			Name:  "debug",
			Usage: "Enable debug output",
		},
	}

	app.Before = func(context *cli.Context) error {
		configFile := context.GlobalString("config-file")
		c, err := config.ReadConfig(configFile)
		if err != nil {
			logrus.Infof("Falied to load config file:%v", err)
			config.SniffInterfaces = context.GlobalString("interfaces")
			config.SniffFilter = context.GlobalString("filter")
			config.ElasticsearchEndpoint = context.GlobalString("endpoint")
			config.SniffLength = context.GlobalInt("length")
			config.Timeout = context.GlobalDuration("timeout")
			config.Promiscuous = context.GlobalBool("promiscuous")
			config.Debug = context.GlobalBool("debug")
		} else {
			if context.IsSet("interfaces") {
				config.SniffInterfaces = context.String("interfaces")
			} else if c.SniffInterfaces != "" {
				config.SniffInterfaces = c.SniffInterfaces
			} else {
				config.SniffInterfaces = context.GlobalString("interfaces")
			}

			if context.IsSet("filter") {
				config.SniffFilter = context.String("filter")
			} else if c.SniffFilter != "" {
				config.SniffFilter = c.SniffFilter
			} else {
				config.SniffFilter = context.GlobalString("filter")
			}

			if context.IsSet("endpoint") {
				config.ElasticsearchEndpoint = context.String("endpoint")
			} else if c.SniffFilter != "" {
				config.ElasticsearchEndpoint = c.ElasticsearchEndpoint
			} else {
				config.ElasticsearchEndpoint = context.GlobalString("endpoint")
			}

			if context.IsSet("length") {
				config.SniffLength = context.GlobalInt("length")
			} else if c.SniffLength != 0 {
				config.SniffLength = c.SniffLength
			} else {
				config.SniffLength = context.GlobalInt("length")
			}

			if context.IsSet("timeout") {
				config.Timeout = context.Duration("timeout")
			} else if c.Timeout != 0 {
				config.Timeout = time.Duration(c.Timeout) * time.Second
			} else {
				config.Timeout = context.GlobalDuration("timeout")
			}

			if context.IsSet("promiscuous") {
				config.Promiscuous = context.GlobalBool("promiscuous")
			} else {
				config.Promiscuous = c.Promiscuous
			}

			if context.IsSet("debug") {
				config.Debug = context.GlobalBool("debug")
			} else {
				config.Debug = c.Debug
			}
		}
		if config.Debug {
			logrus.SetLevel(logrus.DebugLevel)
		}
		return nil
	}
	if err := app.Run(os.Args); err != nil {
		logrus.Fatal(err)
	}
}
