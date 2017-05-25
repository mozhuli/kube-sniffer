package sniffer

import (
	"fmt"
	"log"
	"os"
	"runtime"
	"strings"
	"sync"

	"github.com/Sirupsen/logrus"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/mozhuli/kube-sniffer/pkg/config"
)

var (
	wg            sync.WaitGroup
	numGoroutines int
)

func Sniffs(devices []string) {
	runtime.GOMAXPROCS(runtime.NumCPU())
	numGoroutines = len(devices)
	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go sniff(devices[i])
	}
	wg.Wait()
}

func sniff(device string) {
	defer wg.Done()
	// Open device
	handle, err := pcap.OpenLive(device, config.SnapshotLength, config.Promiscuous, config.Timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()
	// Set filter
	err = handle.SetBPFFilter(config.Filter)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Capturing: ", config.Filter)
	// Process packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		logTcpHandShakeInfo(packet)
	}
}

func ListSniffInterfaces() []string {
	//var devices []pcap.Interface
	var sniffDevices []string
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}
	for _, device := range devices {
		if strings.HasPrefix(device.Name, "cali") {
			fmt.Println(device.Name)
			sniffDevices = append(sniffDevices, device.Name)
		}
	}
	return sniffDevices
}

func file_cap() {
}

func logTcpHandShakeInfo(packet gopacket.Packet) {
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		if tcp.SYN && tcp.ACK {
			ipLayer := packet.Layer(layers.LayerTypeIPv4)
			ip, _ := ipLayer.(*layers.IPv4)
			info := fmt.Sprintf("srcIP:%s dstIP:%s srcPort:%d dstPort:%d\n", ip.DstIP, ip.SrcIP, tcp.DstPort, tcp.SrcPort)
			f, err := os.OpenFile(config.File, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0666)
			if err != nil {
				logrus.Fatal(err)
			}
			defer f.Close()
			f.WriteString(info)
		}
	}
}
