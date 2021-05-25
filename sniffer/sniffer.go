package sniffer

import (
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/sheacloud/go-flowprobe/flow"
	"github.com/sheacloud/go-flowprobe/tracker"
)

// FlowSniffer represents a flow sniffer
type FlowSniffer interface {
	Start()
	Stop()
}

type PacketJob struct {
	data        []byte
	captureInfo gopacket.CaptureInfo
}

func PacketProcessor(flowTracker *tracker.FlowTracker, jobs <-chan *PacketJob, waitGroup *sync.WaitGroup) {
	defer waitGroup.Done()

	var eth layers.Ethernet
	var ip4 layers.IPv4
	var tcp layers.TCP
	var udp layers.UDP
	var icmpv4 layers.ICMPv4
	var flowKey flow.FlowKey
	var networkLayer gopacket.NetworkLayer
	var transportLayer gopacket.TransportLayer
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip4, &tcp, &udp, &icmpv4)
	decoded := []gopacket.LayerType{}

	for job := range jobs {
		parser.DecodeLayers(job.data, &decoded)

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
			var err error
			flowKey, err = flow.GetPacketFlowKey(networkLayer, transportLayer)
			if err != nil {
				continue
			}
			flowTracker.TrackFlow(flowKey, networkLayer, transportLayer, job.captureInfo)
		}
	}
}
