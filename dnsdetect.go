package main

import (
	"fmt"

	"log"
	"net"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/pborman/getopt"
)

//Custom Structure
type Query_ struct {
	id               uint16
	total_count      int
	latest_timestamp time.Time
}

var (
	handle   *pcap.Handle
	err      error
	reqBuff  map[uint16]*Query_
	respBuff map[uint16][]*layers.DNS
	myIP     net.IP
)

func packethandle(packet gopacket.Packet) {
	dnsLayer := packet.Layer(layers.LayerTypeDNS)
	dnsPacket := dnsLayer.(*layers.DNS)
	dnsID := dnsPacket.ID
	//If packet is not IPv4 don't process
	//support for IPv4
	if dnsPacket.Questions[0].Type != layers.DNSTypeA {
		return
	}
	//Check if packet is Query or Response
	if !dnsPacket.QR {
		if _, ret_val := reqBuff[dnsID]; !ret_val {
			reqBuff[dnsID] = &Query_{
				id:               dnsID,
				total_count:      1,
				latest_timestamp: packet.Metadata().Timestamp}
		} else {
			reqBuff[dnsID].total_count = reqBuff[dnsID].total_count + 1
			reqBuff[dnsID].latest_timestamp = packet.Metadata().Timestamp
		}
	} else {
		respBuff[dnsID] = append(respBuff[dnsID], dnsPacket)
		if len(respBuff[dnsID]) > reqBuff[dnsID].total_count {
			//If the length of list for a particular TXID is greater than the number of responses
			//Alert raised!!
			fmt.Printf("%v DNS poisoning attempt\nTXID %v Request %v\n", packet.Metadata().Timestamp.Format("2006-01-02 15:04:05.32536"), dnsID, string(dnsPacket.Questions[0].Name))
			for i, dns_packet_ := range respBuff[dnsID] {
				var ip_list []string
				for _, answer := range dns_packet_.Answers {
					if answer.Type == layers.DNSTypeA {
						ip_list = append(ip_list, (answer.IP).String())
					}
				}
				fmt.Printf("Answer%v %v\n", i+1, ip_list)
			}
			delete(respBuff, dnsID)
			delete(reqBuff, dnsID)
		}
	}
}
func main() {
	inter_faces, _ := pcap.FindAllDevs()
	int_face := inter_faces[0]
	myIP = int_face.Addresses[0].IP
	reqBuff = make(map[uint16]*Query_)
	respBuff = make(map[uint16][]*layers.DNS)
	//This part is to read the values from the command-line flags
	inter_face := getopt.String('i', int_face.Name, "interface to connect")
	pcap_file := getopt.String('r', "", "Read pcap file")
	getopt.Parse()
	//Checking if '-r' flag is set. If set use the string along with
	//the flag as the input to open a .pcap file
	//If '-r' is not set use the value from '-i' flag to read from Live Server
	//If '-i' is not provided use the default connection to read packets
	if getopt.IsSet('r') {
		handle, err = pcap.OpenOffline(*pcap_file)
		if err != nil {
			log.Fatal(err)
		}
		defer handle.Close()
		fmt.Printf("dnsdetect reading from file %s\n", *pcap_file)
	} else {
		handle, err = pcap.OpenLive(*inter_face, 1024, true, pcap.BlockForever)
		if err != nil {
			log.Fatal(err)
		}
		defer handle.Close()
		fmt.Printf("dnsdetect listening on interface [%s]\n", *inter_face)
	}
	//check if there are any non-parameteric values in command-line
	if len(getopt.Args()) > 0 {
		filter_input_array := getopt.Args()
		filter_input := strings.Join(filter_input_array, " ")
		handle.SetBPFFilter(filter_input)
	} else {
		handle.SetBPFFilter("udp and port 53")
	}
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		//Clearing the buffer maintained for requests and responses based
		for id_, query_ := range reqBuff {
			delta_time := (packet.Metadata().Timestamp).Sub(query_.latest_timestamp)
			if delta_time.Seconds() > 5 {
				delete(reqBuff, id_)
				delete(respBuff, id_)
			}
		}
		dnsLayer := packet.Layer(layers.LayerTypeDNS)
		if dnsLayer != nil {
			packethandle(packet)
		}
	}
}
