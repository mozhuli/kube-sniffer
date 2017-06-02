package sniffer

import (
	"fmt"
	"runtime"
	"strings"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/mozhuli/kube-sniffer/pkg/config"
	"github.com/mozhuli/kube-sniffer/pkg/sets"
	"gopkg.in/olivere/elastic.v5"
	"gopkg.in/sohlich/elogrus.v2"
)

var log = logrus.New()

type Sniffer struct {
	deviceSets sets.String
}

func New() *Sniffer {
	devices := ListSniffInterfaces()
	deviceSets := sets.StringKeySet(devices)
	return &Sniffer{
		deviceSets: deviceSets,
	}
}

func initLogHook() {
	// init es hook
	client, err := elastic.NewClient(elastic.SetURL("http://10.168.214.195:9200"))
	if err != nil {
		log.Panic(err)
	}
	hook, err := elogrus.NewElasticHook(client, "localhost", logrus.DebugLevel, "topo")
	if err != nil {
		log.Panic(err)
	}
	log.Hooks.Add(hook)
}

func (s *Sniffer) WatchDevices() {
	for {
		devices := ListSniffInterfaces()
		liveDevices := sets.StringKeySet(devices)
		// Get del devices
		delDevices := s.deviceSets.Difference(liveDevices)
		del := delDevices.List()
		for _, name := range del {
			s.deviceSets.Delete(name)
		}
		// Get add devices
		addDevices := liveDevices.Difference(s.deviceSets)
		add := addDevices.List()
		for _, name := range add {
			s.deviceSets.Insert(name)
			go s.sniff(name)
		}
		time.Sleep(3 * time.Second)
	}
}

func (s *Sniffer) Start() {
	for device, _ := range s.deviceSets {
		go s.sniff(device)
	}
}

func Sniffs() {
	initLogHook()
	sniffer := New()
	fmt.Println(len(sniffer.deviceSets))
	sniffer.Start()
	fmt.Println("2")
	runtime.GOMAXPROCS(runtime.NumCPU())
	sniffer.WatchDevices()
}

func (s *Sniffer) sniff(device string) {
	defer logrus.Infof("sniff on %s existed", device)
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

func ListSniffInterfaces() map[string]struct{} {
	sniffDevices := make(map[string]struct{})
	devices, err := pcap.FindAllDevs()
	if err != nil {
		logrus.Fatal(err)
	}
	for _, device := range devices {
		if strings.HasPrefix(device.Name, "cali") {
			sniffDevices[device.Name] = struct{}{}
		}
	}
	return sniffDevices
}

func logTcpHandShakeInfo(packet gopacket.Packet, device string) {
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	tcp, _ := tcpLayer.(*layers.TCP)
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	ip, _ := ipLayer.(*layers.IPv4)
	log.WithFields(logrus.Fields{
		"interface": device,
		"srcIP":     ip.DstIP,
		"dstIP":     ip.SrcIP,
		"srcPort":   tcp.DstPort,
		"dstPort":   tcp.SrcPort,
	}).Info("logging to elasticsearch")
}
