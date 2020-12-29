package flowprobe

import (
	"fmt"

	"github.com/google/gopacket"
)

// FlowRouter reads from a packet stream and routes it to a FlowTracker based on it's keys
type FlowRouter struct {
	FlowTrackerHashTable map[uint32]*FlowTracker
	PacketStream         chan gopacket.Packet
	StopChannel          chan bool
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
				flowKey, err := GetPacketFlowKey(packet)
				if err != nil {
					fmt.Printf("Could not get flow key for packet: %s\n", err)
				} else {
					fr.FlowTrackerHashTable[0].TrackPacket(flowKey, packet)
				}
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
func NewFlowRouter(packetStream chan gopacket.Packet, numFlowTrackers int, outputChannel chan Flow) *FlowRouter {
	flowTrackerHashTable := make(map[uint32]*FlowTracker)
	for i := 0; i < numFlowTrackers; i++ {
		flowTrackerHashTable[uint32(i)] = NewFlowTracker(outputChannel)
	}

	return &FlowRouter{
		PacketStream:         packetStream,
		FlowTrackerHashTable: flowTrackerHashTable,
		StopChannel:          make(chan bool),
	}
}
