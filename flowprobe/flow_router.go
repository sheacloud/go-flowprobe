package flowprobe

import (
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// FlowRouter reads from a packet stream and routes it to a FlowTracker based on it's keys
type FlowRouter struct {
	FlowTrackerHashTable map[uint32]*FlowTracker
	PacketStream         chan gopacket.Packet
	StopChannel          chan bool
	numFlowTrackers      uint32
}

func (fr *FlowRouter) route(packet gopacket.Packet) {
	networkLayer := packet.NetworkLayer()
	// Can't track the flow if there is no network layer
	if networkLayer == nil {
		return
	}
	switch networkLayerType := networkLayer.LayerType(); networkLayerType {
	case layers.LayerTypeIPv4:
		key, err := GetPacketIPv4FlowKey(packet)
		if err != nil {
			fmt.Printf("Could not get flow key for packet: %s\n", err)
			return
		}
		flowTrackerIndex := key.Hash() % fr.numFlowTrackers
		fr.FlowTrackerHashTable[flowTrackerIndex].TrackIPv4Packet(key, packet)
	case layers.LayerTypeIPv6:
		fmt.Println("IPv6 not implemented yet")
	default:
		fmt.Println("Unsupported network layer")
	}
}

// Start the flow router
func (fr *FlowRouter) Start() {
	for _, flowTracker := range fr.FlowTrackerHashTable {
		flowTracker.Start()
	}

	go func() {
		var packet gopacket.Packet
	InfiniteLoop:
		for {
			select {
			case <-fr.StopChannel:
				break InfiniteLoop
			case packet = <-fr.PacketStream:
				// process packet
				fr.route(packet)
			}
		}
		fmt.Println("FlowRouter stopped")
	}()
}

// Stop the flow router
func (fr *FlowRouter) Stop() {
	fr.StopChannel <- true
}

// NewFlowRouter instantiates a FlowRouter
func NewFlowRouter(packetStream chan gopacket.Packet, numFlowTrackers uint32, ipv4OutputChannel chan IPv4Flow) *FlowRouter {
	flowTrackerHashTable := make(map[uint32]*FlowTracker)
	var i uint32
	for i = 0; i < numFlowTrackers; i++ {
		flowTrackerHashTable[uint32(i)] = NewFlowTracker(ipv4OutputChannel)
	}

	return &FlowRouter{
		PacketStream:         packetStream,
		FlowTrackerHashTable: flowTrackerHashTable,
		StopChannel:          make(chan bool),
		numFlowTrackers:      numFlowTrackers,
	}
}
