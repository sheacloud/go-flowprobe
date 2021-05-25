package flow

import (
	"errors"
	"fmt"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"k8s.io/klog"
)

type FlowType int

const (
	Initiator FlowType = iota
	Responder
	Unknown
)

var serverPorts = []uint16{443, 53, 22, 80, 8443, 8080}

// Flow represents an aggregated network flow of TCP traffic
type Flow struct {
	NetworkType          gopacket.LayerType
	TransportType        gopacket.LayerType
	NetworkSourceAddress net.IP
	NetworkDestAddress   net.IP
	TransportSourcePort  uint16
	TransportDestPort    uint16
	Protocol             layers.IPProtocol
	Type                 FlowType
	FlowMetadata
}

func (f *Flow) GuessType() {
	if f.ReverseTotalPackets == 0 {
		f.Type = Unknown
		return
	}
	for _, sPort := range serverPorts {
		if sPort == f.TransportDestPort {
			f.Type = Initiator
			break
		} else if sPort == f.TransportSourcePort {
			f.Type = Responder
			break
		}
	}

	return
}

func FlowFromLayers(networkLayer gopacket.NetworkLayer, transportLayer gopacket.TransportLayer) (Flow, error) {
	flow := Flow{
		NetworkType: networkLayer.LayerType(),
		Type:        Unknown,
	}

	switch networkLayer.LayerType() {
	case layers.LayerTypeIPv4:
		ipv4 := networkLayer.(*layers.IPv4)

		//IPv4 maps the SrcIP and DstIP to the underlying packet data []byte, which in the case of zero-copy is located on a ring buffer which gets overridden with new packets
		//So we copy the data into a new []byte
		flow.NetworkSourceAddress = make([]byte, 4)
		flow.NetworkDestAddress = make([]byte, 4)
		copy(flow.NetworkSourceAddress, ipv4.SrcIP)
		copy(flow.NetworkDestAddress, ipv4.DstIP)
		flow.Protocol = ipv4.Protocol
	case layers.LayerTypeIPv6:
		ipv6 := networkLayer.(*layers.IPv6)

		flow.NetworkSourceAddress = make([]byte, 4)
		flow.NetworkDestAddress = make([]byte, 4)
		copy(flow.NetworkSourceAddress, ipv6.SrcIP)
		copy(flow.NetworkDestAddress, ipv6.DstIP)
		flow.Protocol = ipv6.NextHeader
	default:
		return flow, errors.New("Network layer not of IPv4 or IPv6 type")
	}

	if transportLayer != nil {
		flow.TransportType = transportLayer.LayerType()

		switch transportLayer.LayerType() {
		case layers.LayerTypeTCP:
			tcp := transportLayer.(*layers.TCP)
			flow.TransportSourcePort = uint16(tcp.SrcPort)
			flow.TransportDestPort = uint16(tcp.DstPort)

			if tcp.SYN && !tcp.ACK {
				flow.Type = Initiator
			} else if tcp.SYN && tcp.ACK {
				flow.Type = Responder
			}
		case layers.LayerTypeUDP:
			udp := transportLayer.(*layers.UDP)
			flow.TransportSourcePort = uint16(udp.SrcPort)
			flow.TransportDestPort = uint16(udp.DstPort)
		default:
			flow.TransportSourcePort = 0
			flow.TransportDestPort = 0
		}
	}

	return flow, nil
}

type FlowMetadata struct {
	FlowStartMilliseconds uint64
	FlowEndMilliseconds   uint64
	TotalBytes            uint64
	TotalPackets          uint64
	ReverseTotalBytes     uint64
	ReverseTotalPackets   uint64
}

// FlowKey represents the unique 5-tuple flow key used for tracking a flow
// The key must be "comparable" so it can be used as a map key
type FlowKey struct {
	NetworkSourceEndpoint   gopacket.Endpoint
	NetworkDestEndpoint     gopacket.Endpoint
	TransportSourceEndpoint gopacket.Endpoint
	TransportDestEndpoint   gopacket.Endpoint
	Protocol                layers.IPProtocol
}

func (fk *FlowKey) String() string {
	return fmt.Sprintf("%s:%s --%v--> %s:%s", fk.NetworkSourceEndpoint.String(), fk.TransportSourceEndpoint.String(), fk.Protocol, fk.NetworkDestEndpoint.String(), fk.TransportDestEndpoint.String())
}

// Hash returns a 32bit hash of the flow key
func (fk *FlowKey) Hash() uint64 {
	var hash uint64 = 0
	networkFlow, _ := gopacket.FlowFromEndpoints(fk.NetworkSourceEndpoint, fk.NetworkDestEndpoint)
	hash += networkFlow.FastHash()

	transportFlow, _ := gopacket.FlowFromEndpoints(fk.TransportSourceEndpoint, fk.TransportDestEndpoint)
	hash += transportFlow.FastHash()

	return hash
}

func (fk *FlowKey) Reverse() FlowKey {
	return FlowKey{
		NetworkSourceEndpoint:   fk.NetworkDestEndpoint,
		NetworkDestEndpoint:     fk.NetworkSourceEndpoint,
		TransportSourceEndpoint: fk.TransportDestEndpoint,
		TransportDestEndpoint:   fk.TransportSourceEndpoint,
		Protocol:                fk.Protocol,
	}
}

// GetPacketFlowKey returns the unique flow key of a packet
func GetPacketFlowKey(networkLayer gopacket.NetworkLayer, transportLayer gopacket.TransportLayer) (FlowKey, error) {
	var key FlowKey

	if networkLayer == nil {
		klog.Error("Cannot create packet flow key where network layer is nil")
		return key, errors.New("Network Layer nil")
	}

	var protocol layers.IPProtocol
	switch networkLayer.LayerType() {
	case layers.LayerTypeIPv4:
		protocol = networkLayer.(*layers.IPv4).Protocol
	case layers.LayerTypeIPv6:
		protocol = networkLayer.(*layers.IPv6).NextHeader
	default:
		return key, errors.New("Network layer isn't IPv4 or IPv6")
	}

	key = FlowKey{
		NetworkSourceEndpoint: networkLayer.NetworkFlow().Src(),
		NetworkDestEndpoint:   networkLayer.NetworkFlow().Dst(),
		Protocol:              protocol,
	}

	if transportLayer != nil {
		key.TransportSourceEndpoint = transportLayer.TransportFlow().Src()
		key.TransportDestEndpoint = transportLayer.TransportFlow().Dst()
	} else {
		key.TransportSourceEndpoint = gopacket.NewEndpoint(layers.EndpointTCPPort, []byte{0, 0})
		key.TransportDestEndpoint = gopacket.NewEndpoint(layers.EndpointTCPPort, []byte{0, 0})
	}
	return key, nil
}
