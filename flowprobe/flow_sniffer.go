package flowprobe

import (
	"fmt"
	"log"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/afpacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// afpacketComputeSize computes the block_size and the num_blocks in such a way that the
// allocated mmap buffer is close to but smaller than target_size_mb.
// The restriction is that the block_size must be divisible by both the
// frame size and page size.
func afpacketComputeSize(targetSizeMb int, snaplen int, pageSize int) (
	frameSize int, blockSize int, numBlocks int, err error) {

	if snaplen < pageSize {
		frameSize = pageSize / (pageSize / snaplen)
	} else {
		frameSize = (snaplen/pageSize + 1) * pageSize
	}

	// 128 is the default from the gopacket library so just use that
	blockSize = frameSize * 128
	numBlocks = (targetSizeMb * 1024 * 1024) / blockSize

	if numBlocks == 0 {
		return 0, 0, 0, fmt.Errorf("Interface buffersize is too small")
	}

	return frameSize, blockSize, numBlocks, nil
}

// FlowSniffer reads from a packet stream and routes it to a FlowTracker based on it's keys
type FlowSniffer struct {
	FlowTracker  *FlowTracker
	PacketSource gopacket.ZeroCopyPacketDataSource
	device       string
	fanoutID     uint16
	StopChannel  chan bool
}

// Start the flow router
func (fr *FlowSniffer) Start() {
	fr.FlowTracker.Start()

	go func() {
		var eth layers.Ethernet
		var ip4 layers.IPv4
		var tcp layers.TCP
		var udp layers.UDP
		var ipv4FlowKey IPv4FlowKey
		var networkLayer gopacket.NetworkLayer
		var transportLayer gopacket.TransportLayer
		parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip4, &tcp, &udp)
		decoded := []gopacket.LayerType{}
	InfiniteLoop:
		for {
			select {
			case <-fr.StopChannel:
				break InfiniteLoop
			default:
				// TODO don't block forever waiting for a packet, or else we'll never get the channel stop message if no packets are arriving. OptPollTimeout might be the solution
				data, ci, err := fr.PacketSource.ZeroCopyReadPacketData()
				if err != nil {
					log.Fatal(err)
				}

				if err := parser.DecodeLayers(data, &decoded); err != nil {
					continue
				}

				isIPv4 := false
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
					ipv4FlowKey, err = GetPacketIPv4FlowKey(&eth, networkLayer, transportLayer)
					if err != nil {
						continue
					}
					fr.FlowTracker.TrackIPv4Flow(ipv4FlowKey, ci)
				}
			}
		}
		fmt.Println("FlowSniffer stopped")
	}()
}

// Stop the flow router
func (fr *FlowSniffer) Stop() {
	fr.StopChannel <- true
}

// NewFlowSniffer instantiates a FlowSniffer
func NewFlowSniffer(device string, fanoutID uint16, ipv4OutputChannel chan IPv4Flow, snifferNumber uint32) *FlowSniffer {
	flowTracker := NewFlowTracker(ipv4OutputChannel, snifferNumber)

	szFrame, szBlock, numBlocks, err := afpacketComputeSize(8, 65535, os.Getpagesize())
	if err != nil {
		log.Fatal(err)
	}

	tPacket, err := afpacket.NewTPacket(
		afpacket.OptInterface(device),
		afpacket.OptFrameSize(szFrame),
		afpacket.OptBlockSize(szBlock),
		afpacket.OptNumBlocks(numBlocks),
		afpacket.OptAddVLANHeader(false),
		afpacket.OptPollTimeout(pcap.BlockForever),
		afpacket.SocketRaw,
		afpacket.TPacketVersion3,
	)
	if err != nil {
		log.Fatal(err)
	}

	tPacket.SetFanout(afpacket.FanoutHash, fanoutID)

	source := gopacket.ZeroCopyPacketDataSource(tPacket)

	return &FlowSniffer{
		FlowTracker:  flowTracker,
		PacketSource: source,
		StopChannel:  make(chan bool),
		device:       device,
		fanoutID:     fanoutID,
	}
}
