package sniffer

import (
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/sirupsen/logrus"
)

type PCAPFlowSniffer struct {
	PacketSource     chan gopacket.Packet
	JobChannel       chan<- *PacketJob
	StopChannel      chan bool
	Iface            string
	SnifferWaitGroup *sync.WaitGroup
}

// Start the flow router
func (fr *PCAPFlowSniffer) Start() {

	go func() {

		logrus.WithFields(logrus.Fields{
			"iface": fr.Iface,
		}).Info("Starting PCAP Flow Sniffer")

	InfiniteLoop:
		for {
			select {
			case <-fr.StopChannel:
				break InfiniteLoop
			case packet := <-fr.PacketSource:
				// TODO don't block forever waiting for a packet, or else we'll never get the channel stop message if no packets are arriving. OptPollTimeout might be the solution
				data := packet.Data()

				job := PacketJob{
					data:        data,
					captureInfo: packet.Metadata().CaptureInfo,
				}

				fr.JobChannel <- &job

			}
		}
		logrus.WithFields(logrus.Fields{
			"iface": fr.Iface,
		}).Info("Stopped PCAP Flow Sniffer")
		fr.SnifferWaitGroup.Done()
	}()
}

// Stop the flow router
func (fr *PCAPFlowSniffer) Stop() {
	fr.StopChannel <- true
}

// NewPCAPFlowSniffer instantiates a PCAPFlowSniffer
func NewPCAPFlowSniffer(device string, jobChannel chan *PacketJob, snifferWaitGroup *sync.WaitGroup, snifferNumber uint16) *PCAPFlowSniffer {

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
		PacketSource:     packetSource.Packets(),
		StopChannel:      make(chan bool),
		JobChannel:       jobChannel,
		Iface:            device,
		SnifferWaitGroup: snifferWaitGroup,
	}
}
