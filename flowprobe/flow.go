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
type Flow struct {
	FlowKey
	FlowStartMilliseconds uint64
	FlowEndMilliseconds   uint64
	TotalBytes            uint64
	TotalPackets          uint64
}

func (t Flow) String() string {
	srcIPBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(srcIPBytes, t.SourceIPv4Address)
	srcIP := net.IP(srcIPBytes)

	dstIPBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(dstIPBytes, t.DestinationIPv4Address)
	dstIP := net.IP(dstIPBytes)

	startTime := time.Unix(0, int64(t.FlowStartMilliseconds)*1000000)
	endTime := time.Unix(0, int64(t.FlowEndMilliseconds)*1000000)

	return fmt.Sprintf("%v:%v -> %v:%v %v from %v to %v, bytes=%v packets=%v", srcIP, t.SourcePort, dstIP, t.DestinationPort, t.Protocol, startTime, endTime, t.TotalBytes, t.TotalPackets)
}

// FlowKey represents the unique 5-tuple flow key used for tracking a flow
// The key must be "comparable" so it can be used as a map key
type FlowKey struct {
	SourceIPv4Address      uint32
	DestinationIPv4Address uint32
	SourcePort             uint16
	DestinationPort        uint16
	Protocol               uint8
}

// GetPacketFlowKey returns the unique flow key of a packet, assuming it's IPv4 or IPv6
func GetPacketFlowKey(packet gopacket.Packet) (FlowKey, error) {
	var key FlowKey

	var srcIP, dstIP net.IP
	var srcPort, dstPort uint16
	var protocol uint8

	networkLayer := packet.NetworkLayer()
	if networkLayer == nil {
		return key, fmt.Errorf("No network layer in packet")
	}
	switch networkLayerType := networkLayer.LayerType(); networkLayerType {
	case layers.LayerTypeIPv4:
		ipv4Layer := networkLayer.(*layers.IPv4)
		srcIP = ipv4Layer.SrcIP
		dstIP = ipv4Layer.DstIP
		protocol = uint8(ipv4Layer.Protocol)
	case layers.LayerTypeIPv6:
		fmt.Println("not implemented")
		return key, fmt.Errorf("Not implemented IPv6")
	default:
		fmt.Println("unsupported network layer")
		return key, fmt.Errorf("Unsupported network layer: %s", networkLayerType)
	}

	transportLayer := packet.TransportLayer()
	if transportLayer == nil {
		return key, fmt.Errorf("No transport layer in packet")
	}
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

	key = FlowKey{
		SourceIPv4Address:      binary.BigEndian.Uint32(srcIP),
		DestinationIPv4Address: binary.BigEndian.Uint32(dstIP),
		SourcePort:             srcPort,
		DestinationPort:        dstPort,
		Protocol:               protocol,
	}

	return key, nil
}
