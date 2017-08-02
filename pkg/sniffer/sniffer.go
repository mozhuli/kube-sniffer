package sniffer

import (
	"fmt"
	"os"
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

// Sniffer is the internal representation of the sets of sniffed interfaces
type Sniffer struct {
	deviceSets sets.String
}

// New init the sniffer
func New() *Sniffer {
	devices := ListSniffInterfaces()
	deviceSets := sets.StringKeySet(devices)
	return &Sniffer{
		deviceSets: deviceSets,
	}
}

func getHostname() string {
	hostname, _ := os.Hostname()
	return hostname
}

func initLogHook() {
	// init es hook
	client, err := elastic.NewClient(elastic.SetURL("http://10.10.101.145:9200"))
	if err != nil {
		log.Panic(err)
	}
	logrus.Info("Inited es client")
	hostname := getHostname()
	hook, err := elogrus.NewElasticHook(client, hostname, logrus.DebugLevel, "topo")
	if err != nil {
		log.Panic(err)
	}
	log.Hooks.Add(hook)
	logrus.Info("Added log hook")
}

// WatchDevices watch the sniffed interfaces.
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

// Start sniffing interfaces.
func (s *Sniffer) Start() {
	for device := range s.deviceSets {
		go s.sniff(device)
	}
}

// Sniffs init and sniff
func Sniffs() {
	initLogHook()
	sniffer := New()
	logrus.Infof("%d interfaces need to be sniffed", len(sniffer.deviceSets))
	sniffer.Start()
	runtime.GOMAXPROCS(runtime.NumCPU())
	sniffer.WatchDevices()
}

func (s *Sniffer) sniff(device string) {
	defer logrus.Infof("Sniff on %s existed", device)
	// Open device
	handle, err := pcap.OpenLive(device, int32(config.SniffLength), config.Promiscuous, config.Timeout)
	if err != nil {
		logrus.Warningf("Failed open device %s: %v", device, err)
		return
	}
	defer handle.Close()
	// Set filter
	err = handle.SetBPFFilter(config.SniffFilter)
	if err != nil {
		logrus.Warningf("Failed set BPF fliter: %v", err)
		return
	}
	logrus.Infof("Capturing packet %s on device %s", config.SniffFilter, device)
	// Process packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		logTCPHandShakeInfo(packet, device)
	}
}

// ListInterfaces list the host interfaces
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

// ListSniffInterfaces list the interfaces which to be sniffed
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

func logTCPHandShakeInfo(packet gopacket.Packet, device string) {
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	tcp, _ := tcpLayer.(*layers.TCP)
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	ip, _ := ipLayer.(*layers.IPv4)
	log.WithFields(logrus.Fields{
		"interface": device,
		"link":      ip.DstIP.String() + "_" + ip.SrcIP.String(),
		"srcIP":     ip.DstIP,
		"dstIP":     ip.SrcIP,
		"srcPort":   tcp.DstPort,
		"dstPort":   tcp.SrcPort,
	}).Info("logging to elasticsearch")
}
