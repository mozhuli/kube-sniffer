package sniffer

import (
	"fmt"
	"runtime"
	"strings"
	"sync"

	"github.com/Sirupsen/logrus"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/mozhuli/kube-sniffer/pkg/config"
	"gopkg.in/olivere/elastic.v5"
	"gopkg.in/sohlich/elogrus.v2"
)

var (
	wg            sync.WaitGroup
	numGoroutines int
)

var log = logrus.New()

func Sniffs(devices []string) {
	// init es hook
	//log := logrus.New()
	client, err := elastic.NewClient(elastic.SetURL("http://10.168.214.195:9200"))
	if err != nil {
		log.Panic(err)
	}
	hook, err := elogrus.NewElasticHook(client, "localhost", logrus.DebugLevel, "topo")
	if err != nil {
		log.Panic(err)
	}
	log.Hooks.Add(hook)

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
	handle, err := pcap.OpenLive(device, int32(config.SniffLength), config.Promiscuous, config.Timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()
	// Set filter
	err = handle.SetBPFFilter(config.SniffFilter)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Capturing: ", config.SniffFilter)
	// Process packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		logTcpHandShakeInfo(packet, device)
	}
}

func ListInterfaces() {
	var devices []pcap.Interface
	devices, err := pcap.FindAllDevs()
	if err != nil {
		logrus.Fatal(err)
	}
	// Print device information
	fmt.Println("Devices found:")
	for _, device := range devices {
		fmt.Println("\nName: ", device.Name)
		fmt.Println("Description: ", device.Description)
		fmt.Println("Devices addresses: ", device.Description)
		for _, address := range device.Addresses {
			fmt.Println("- IP address: ", address.IP)
			fmt.Println("- Subnet mask: ", address.Netmask)
		}
	}
}

func ListSniffInterfaces() []string {
	//var devices []pcap.Interface
	var sniffDevices []string
	devices, err := pcap.FindAllDevs()
	if err != nil {
		logrus.Fatal(err)
	}
	for _, device := range devices {
		if strings.HasPrefix(device.Name, "cali") {
			fmt.Println(device.Name)
			sniffDevices = append(sniffDevices, device.Name)
		}
	}
	return sniffDevices
}

func logTcpHandShakeInfo(packet gopacket.Packet, device string) {
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	tcp, _ := tcpLayer.(*layers.TCP)
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	ip, _ := ipLayer.(*layers.IPv4)
	//info := fmt.Sprintf("srcIP:%s dstIP:%s srcPort:%d dstPort:%d\n", ip.DstIP, ip.SrcIP, tcp.DstPort, tcp.SrcPort)
	log.WithFields(logrus.Fields{
		"interface": device,
		"srcIP":     ip.DstIP,
		"dstIP":     ip.SrcIP,
		"srcPort":   tcp.DstPort,
		"dstPort":   tcp.SrcPort,
	}).Info("")
}
