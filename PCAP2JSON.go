package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	pcapFile string = "testdc.pcap"
	handle   *pcap.Handle
	err      error
	eth      layers.Ethernet
	ip4      layers.IPv4
	ip6      layers.IPv6
	tcp      layers.TCP
	udp      layers.UDP
	dns      layers.DNS
	SrcIP    string
	DstIP    string
)

type DnsMsg struct {
	Timestamp       string
	SourceIP        string
	DestinationIP   string
	DnsQuery        string
	DnsAnswer       []string
	DnsAnswerTTL    []string
	NumberOfAnswers string
	DnsResponseCode string
	DnsOpCode       string
}

func sendToElastic(dnsMsg DnsMsg, wg *sync.WaitGroup) {
	defer wg.Done()
	var jsonMsg, jsonErr = json.Marshal(dnsMsg)
	if jsonErr != nil {
		fmt.Println(jsonErr)
	}
	file, err := os.OpenFile("rb.json", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println("failed creating file: %s", err)
	}
	datawriter := bufio.NewWriter(file)
	for n, line := range bytes.Split(jsonMsg, []byte{'\n'}) {
		n++
		if n < len(jsonMsg) {
			_, _ = datawriter.WriteString(string(line) + "\n")
		}
	}
	datawriter.Flush()
	file.Close()
}

func main() {
	var payload gopacket.Payload
	wg := new(sync.WaitGroup)
	// Open file instead of device
	handle, err = pcap.OpenOffline(pcapFile)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// Loop through packets in file
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for packet := range packetSource.Packets() {
		parser := gopacket.NewDecodingLayerParser(
			layers.LayerTypeEthernet, &eth, &ip4, &ip6, &tcp, &udp, &dns, &payload)
		decodedLayers := make([]gopacket.LayerType, 0, 10)

		err := parser.DecodeLayers(packet.Data(), &decodedLayers)
		if err != nil {
			//fmt.Println("Trouble decoding layers: ", err)
		}

		applicationLayer := packet.ApplicationLayer()
		applicationLayer.LayerContents()
		if strings.Contains(string(applicationLayer.Payload()), "HTTP") {

		}
		for _, typ := range decodedLayers {
			switch typ {
			case layers.LayerTypeIPv4:
				SrcIP = ip4.SrcIP.String()
				DstIP = ip4.DstIP.String()
			case layers.LayerTypeTCP:
				SrcIP = ip4.SrcIP.String()
				DstIP = ip4.DstIP.String()
			case layers.LayerTypeTLS:
				SrcIP = ip4.SrcIP.String()
				DstIP = ip4.DstIP.String()
			case layers.applicationLayer:
				SrcIP = ip4.SrcIP.String()
				DstIP = ip4.DstIP.String()

			case layers.LayerTypeIPv6:
				SrcIP = ip6.SrcIP.String()
				DstIP = ip6.DstIP.String()

			case layers.LayerTypeDNS:
				dnsOpCode := int(dns.OpCode)
				dnsResponseCode := int(dns.ResponseCode)
				dnsANCount := int(dns.ANCount)

				if (dnsANCount == 0 && dnsResponseCode > 0) || (dnsANCount > 0) {
					for _, dnsQuestion := range dns.Questions {
						t := time.Now()
						timestamp := t.Format(time.RFC3339)

						// Add a document to the index
						d := DnsMsg{Timestamp: timestamp, SourceIP: SrcIP,
							DestinationIP:   DstIP,
							DnsQuery:        string(dnsQuestion.Name),
							DnsOpCode:       strconv.Itoa(dnsOpCode),
							DnsResponseCode: strconv.Itoa(dnsResponseCode),
							NumberOfAnswers: strconv.Itoa(dnsANCount)}
						if dnsANCount > 0 {
							for _, dnsAnswer := range dns.Answers {
								d.DnsAnswerTTL = append(d.DnsAnswerTTL, fmt.Sprint(dnsAnswer.TTL))
								if dnsAnswer.IP.String() != "<nil>" {
									//fmt.Println("    DNS Answer: ", dnsAnswer.IP.String())
									d.DnsAnswer = append(d.DnsAnswer, dnsAnswer.IP.String())
								}
							}

						}

						wg.Add(1)
						sendToElastic(d, wg)

					}
				}

			}

		}
	}

}
