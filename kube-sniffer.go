package main

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"gopkg.in/urfave/cli.v2"
)

var (
	device       string = "eth0"
	filter       string = "tcp and port 443"
	snapshot_len int32  = 65535
	promiscuous  bool   = false
	err          error
	timeout      time.Duration = -1 * time.Second
	handle       *pcap.Handle
	sniffdump    string
)

func main() {
	app := &cli.App{
		Name:      "kube-sniff",
		Version:   "1.0",
		UsageText: "kube-sniff --interface eth0 --sniff \"tcp and port 80\"",
		Authors: []*cli.Author{
			{
				Name:  "mozhuli",
				Email: "mozhuli@gmail.com"},
		},
		Flags: []cli.Flag{

			&cli.StringFlag{
				Name:        "interface",
				Aliases:     []string{"i"},
				Value:       "eth0",
				Usage:       "the interface to use",
				Destination: &device,
			},
			&cli.StringFlag{
				Name:    "file",
				Aliases: []string{"f"},
				//Value:       "sniffdump",
				Usage:       "To log create a pcap with sniff dump",
				Destination: &sniffdump,
			},
			&cli.BoolFlag{
				Name:    "promiscuous",
				Aliases: []string{"p"},
				//Value:       "false",
				Usage:       "To enable promiscuous mode",
				Destination: &promiscuous,
			},
			&cli.StringFlag{
				Name:        "sniff",
				Aliases:     []string{"s"},
				Value:       "tcp and port 443",
				Usage:       "the BPF syntax parameters to sniff on",
				Destination: &filter,
			},
		},
		Action: func(c *cli.Context) error {
			fmt.Printf("Capturing on Interface %v\n", c.String("interface"))
			fmt.Printf("Promiscuous mode: %v\n", c.String("promiscuous"))
			sniff(device, filter, sniffdump)
			return nil
		},
		Commands: []*cli.Command{
			{
				Name:        "list-interfaces",
				Aliases:     []string{"l"},
				Usage:       "sniff list-interfaces/sniff l",
				Description: "list interfaces",
				Action: func(c *cli.Context) error {
					fmt.Printf("listing interfaces:  ")
					list_int()
					return nil
				},
			},
		},
	}
	app.Run(os.Args)
}

func sniff(device string, filter string, sniffdump string) string {

	// Open device
	handle, err = pcap.OpenLive(device, snapshot_len, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// Set filter
	err = handle.SetBPFFilter(filter)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Capturing: ", filter)

	// Process packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		fmt.Println(packet)
		//if capture to pcap file enable then file_cap(packet) etc
	}
	return device
}

func list_int() {
	var devices []pcap.Interface
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(devices)
}

func file_cap() {
}
