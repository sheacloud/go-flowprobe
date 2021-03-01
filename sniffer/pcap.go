package sniffer

import (
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/sheacloud/go-flowprobe/flow"
	"github.com/sheacloud/go-flowprobe/tracker"
)

type PCAPFlowSniffer struct {
	FlowTracker  *tracker.FlowTracker
	PacketSource chan gopacket.Packet
	StopChannel  chan bool
}

// Start the flow router
func (fr *PCAPFlowSniffer) Start() {
	fr.FlowTracker.Start()

	go func() {
		var eth layers.Ethernet
		var ip4 layers.IPv4
		var tcp layers.TCP
		var udp layers.UDP
		var icmpv4 layers.ICMPv4
		var networkLayer gopacket.NetworkLayer
		var transportLayer gopacket.TransportLayer
		parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip4, &tcp, &udp, &icmpv4)
		decoded := []gopacket.LayerType{}
	InfiniteLoop:
		for {
			select {
			case <-fr.StopChannel:
				break InfiniteLoop
			case packet := <-fr.PacketSource:
				// TODO don't block forever waiting for a packet, or else we'll never get the channel stop message if no packets are arriving. OptPollTimeout might be the solution
				data := packet.Data()

				parser.DecodeLayers(data, &decoded)

				isIPv4 := false
				networkLayer = nil
				transportLayer = nil
				for _, layerType := range decoded {
					switch layerType {
					case layers.LayerTypeIPv4:
						isIPv4 = true
						networkLayer = &ip4
					case layers.LayerTypeTCP:
						transportLayer = &tcp
					case layers.LayerTypeUDP:
						transportLayer = &udp
					}
				}
				if isIPv4 {
					FlowKey, err := flow.GetPacketFlowKey(networkLayer, transportLayer)
					if err != nil {
						continue
					}
					fr.FlowTracker.TrackFlow(FlowKey, networkLayer, transportLayer, packet.Metadata().CaptureInfo)
				}
			}
		}
		fmt.Println("PCAPFlowSniffer stopped")
	}()
}

// Stop the flow router
func (fr *PCAPFlowSniffer) Stop() {
	fr.StopChannel <- true
}

// NewPCAPFlowSniffer instantiates a PCAPFlowSniffer
func NewPCAPFlowSniffer(device string, outputChannel chan flow.Flow, snifferNumber uint16) *PCAPFlowSniffer {
	flowTracker := tracker.NewFlowTracker(outputChannel, 2)

	var packetSource *gopacket.PacketSource
	if handle, err := pcap.OpenLive(device, 1600, true, pcap.BlockForever); err != nil {
		panic(err)
	} else {
		packetSource = gopacket.NewPacketSource(handle, handle.LinkType())
		packetSource.DecodeOptions = gopacket.DecodeOptions{
			Lazy:   true,
			NoCopy: true,
		}
	}

	return &PCAPFlowSniffer{
		FlowTracker:  flowTracker,
		PacketSource: packetSource.Packets(),
		StopChannel:  make(chan bool),
	}
}
