package main

import (
	"fmt"
	"os"

	"github.com/Sirupsen/logrus"
	"github.com/mozhuli/kube-sniffer/pkg/config"
	"github.com/mozhuli/kube-sniffer/pkg/sniffer"
	"gopkg.in/urfave/cli.v2"
)

var VERSION string

func main() {
	app := &cli.App{
		Name:      "kube-sniffer",
		Version:   VERSION,
		UsageText: "kube-sniffer --interfaces eth0 --filter \"tcp and port 80\"",
		Authors: []*cli.Author{
			{
				Name:  "mozhuli",
				Email: "weidonglee27@gmail.com"},
		},
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:        "interfaces",
				Aliases:     []string{"i"},
				EnvVars:     []string{"SNIffER_INTERFACES"},
				Value:       "cali*",
				Usage:       "the interfaces to use,Regular expression can be used eg. cali*",
				Destination: &config.Devices,
			},
			&cli.StringFlag{
				Name:        "file",
				EnvVars:     []string{"SNIFFER_FILE"},
				Value:       "topo.log",
				Usage:       "Logging the sniffer info",
				Destination: &config.File,
			},
			&cli.BoolFlag{
				Name:        "promiscuous",
				Aliases:     []string{"p"},
				EnvVars:     []string{"SNIFFER_PROMISCUOUS"},
				Value:       false,
				Usage:       "Enable promiscuous mode",
				Destination: &config.Promiscuous,
			},
			&cli.StringFlag{
				Name:        "filter",
				EnvVars:     []string{"SNIFFER_FILTER"},
				Value:       "net 192.168.0.0/16",
				Usage:       "the BPF syntax parameters to sniff on",
				Destination: &config.Filter,
			},
		},
		Action: func(c *cli.Context) error {
			fmt.Printf("Capturing on Interfaces %v\n", c.String("interfaces"))
			fmt.Printf("Promiscuous mode: %v\n", c.String("promiscuous"))
			devices := sniffer.ListSniffInterfaces()
			sniffer.Sniffs(devices)
			return nil
		},
		Commands: []*cli.Command{
			{
				Name:        "list-interfaces",
				Aliases:     []string{"l"},
				Usage:       "kube-sniffer list-interfaces",
				Description: "list sniffed interfaces",
				Action: func(c *cli.Context) error {
					fmt.Println("listing sniffed interfaces:  ")
					devices := sniffer.ListSniffInterfaces()
					fmt.Println(devices)
					return nil
				},
			},
		},
	}
	if err := app.Run(os.Args); err != nil {
		logrus.Fatal(err)
	}
}
