package flowprobe

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// Flow represents an aggregated network flow of TCP traffic
type IPv4Flow struct {
	IPv4FlowKey
	FlowMetadata
}

type FlowMetadata struct {
	FlowStartMilliseconds uint64
	FlowEndMilliseconds   uint64
	TotalBytes            uint64
	TotalPackets          uint64
}

func (f IPv4Flow) String() string {
	srcIPBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(srcIPBytes, f.SourceIPv4Address)
	srcIP := net.IP(srcIPBytes)

	dstIPBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(dstIPBytes, f.DestinationIPv4Address)
	dstIP := net.IP(dstIPBytes)

	startTime := time.Unix(0, int64(f.FlowStartMilliseconds)*1000000)
	endTime := time.Unix(0, int64(f.FlowEndMilliseconds)*1000000)

	return fmt.Sprintf("%v:%v -> %v:%v %v from %v to %v, bytes=%v packets=%v", srcIP, f.SourcePort, dstIP, f.DestinationPort, f.Protocol, startTime, endTime, f.TotalBytes, f.TotalPackets)
}

// IPv4FlowKey represents the unique 5-tuple flow key used for tracking a flow
// The key must be "comparable" so it can be used as a map key
type IPv4FlowKey struct {
	SourceIPv4Address      uint32
	DestinationIPv4Address uint32
	SourcePort             uint16
	DestinationPort        uint16
	Protocol               uint8
}

// Hash returns a 32bit hash of the flow key
func (fk *IPv4FlowKey) Hash() uint32 {
	//TODO determine if a better hash function should be used
	return fk.SourceIPv4Address + fk.DestinationIPv4Address + uint32(fk.SourcePort) + uint32(fk.DestinationPort) + uint32(fk.Protocol)
}

// GetPacketIPv4FlowKey returns the unique flow key of a packet, assuming it's IPv4 or IPv6
func GetPacketIPv4FlowKey(linkLayer gopacket.LinkLayer, networkLayer gopacket.NetworkLayer, transportLayer gopacket.TransportLayer) (IPv4FlowKey, error) {
	var key IPv4FlowKey

	var srcIP, dstIP net.IP
	var srcPort, dstPort uint16
	var protocol uint8

	// TODO make sure network layer is IPv4
	if networkLayer.LayerType() != layers.LayerTypeIPv4 {
		return key, fmt.Errorf("Network layer type not IPv4")
	}
	ipv4Layer := networkLayer.(*layers.IPv4)
	srcIP = ipv4Layer.SrcIP
	dstIP = ipv4Layer.DstIP
	protocol = uint8(ipv4Layer.Protocol)

	switch transportLayerType := transportLayer.LayerType(); transportLayerType {
	case layers.LayerTypeTCP:
		tcpLayer := transportLayer.(*layers.TCP)
		srcPort = uint16(tcpLayer.SrcPort)
		dstPort = uint16(tcpLayer.DstPort)
	case layers.LayerTypeUDP:
		udpLayer := transportLayer.(*layers.UDP)
		srcPort = uint16(udpLayer.SrcPort)
		dstPort = uint16(udpLayer.DstPort)
	default:
		fmt.Println("unsupported transport layer")
		return key, fmt.Errorf("Unsupported transport layer: %s", transportLayerType)
	}

	key = IPv4FlowKey{
		SourceIPv4Address:      binary.BigEndian.Uint32(srcIP),
		DestinationIPv4Address: binary.BigEndian.Uint32(dstIP),
		SourcePort:             srcPort,
		DestinationPort:        dstPort,
		Protocol:               protocol,
	}

	return key, nil
}
