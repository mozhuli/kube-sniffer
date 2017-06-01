package main

import (
	"fmt"

	//"github.com/Sirupsen/logrus"
	"github.com/mozhuli/kube-sniffer/pkg/sniffer"
	"github.com/urfave/cli"
)

var sniffCommand = cli.Command{
	Name:  "sniff",
	Usage: "sniff --interfaces cali* --filter \"tcp and port 80\" --endpoint localhost:9200",
	Action: func(context *cli.Context) error {
		fmt.Printf("Capturing on Interfaces %v\n", context.String("interfaces"))
		fmt.Printf("Promiscuous mode: %v\n", context.String("promiscuous"))
		devices := sniffer.ListSniffInterfaces()
		fmt.Println(devices)
		sniffer.Sniffs(devices)
		return nil
	},
}
