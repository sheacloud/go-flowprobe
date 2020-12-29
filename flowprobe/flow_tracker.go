package flowprobe

import (
	"sync"
	"time"

	"github.com/google/gopacket"
)

type FlowStatistics struct {
	TotalBytes    uint64
	TotalPackets  uint64
	FlowStartTime uint64
	FlowLastSeen  uint64
}

type FlowTrackerConfiguration struct {
	MaxFlowLength uint64
	FlowTimeout   uint64
}

type FlowTracker struct {
	IPv4FlowTable     IPv4FlowTable
	ipv4FlowTableLock sync.Mutex
	ipv4OutputChannel chan IPv4Flow
}

func NewFlowTracker(ipv4OutputChannel chan IPv4Flow) *FlowTracker {
	return &FlowTracker{
		IPv4FlowTable:     make(IPv4FlowTable),
		ipv4OutputChannel: ipv4OutputChannel,
	}
}

func (ft *FlowTracker) SweepTables() {

	go func() {
		ft.ipv4FlowTableLock.Lock()
		defer ft.ipv4FlowTableLock.Unlock()
		ft.IPv4FlowTable.SweepTable(ft.ipv4OutputChannel)
	}()

}

func (ft *FlowTracker) Start() {
	ticker := time.NewTicker(5 * time.Second)
	tickerStop := make(chan bool)
	go func() {
		for {
			select {
			case <-ticker.C:
				// run through flow table and clean up old flows
				ft.SweepTables()
			case <-tickerStop:
				ticker.Stop()
				return
			}
		}
	}()
}

func (ft *FlowTracker) TrackIPv4Packet(key IPv4FlowKey, packet gopacket.Packet) {
	ft.ipv4FlowTableLock.Lock()
	defer ft.ipv4FlowTableLock.Unlock()

	ft.IPv4FlowTable.TrackPacket(key, packet)
}
