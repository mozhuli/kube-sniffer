package main

import (
	"fmt"

	//"github.com/Sirupsen/logrus"
	"github.com/mozhuli/kube-sniffer/pkg/sniffer"
	"github.com/urfave/cli"
)

var listInterfacesCommand = cli.Command{
	Name:  "list",
	Usage: "list interfaces",
	Action: func(context *cli.Context) error {
		fmt.Println("listing interfaces:  ")
		sniffer.ListInterfaces()
		return nil
	},
}
