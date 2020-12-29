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
	FlowTable     map[FlowKey]*FlowStatistics
	flowTableLock sync.Mutex
	outputChannel chan Flow
}

func NewFlowTracker(outputChannel chan Flow) *FlowTracker {
	return &FlowTracker{
		FlowTable:     make(map[FlowKey]*FlowStatistics),
		outputChannel: outputChannel,
	}
}

func (ft *FlowTracker) Start() {
	ticker := time.NewTicker(5 * time.Second)
	tickerStop := make(chan bool)
	go func() {
		for {
			select {
			case <-ticker.C:
				// run through flow table and clean up old flows
				ft.flowTableLock.Lock()
				now := uint64(time.Now().UnixNano()) / 1000000
				for key, stats := range ft.FlowTable {
					switch key.Protocol {
					case 6:
						// check if flow has timed out
						if now-stats.FlowLastSeen >= 3000 {
							// export flow
							flow := Flow{
								FlowKey:               key,
								FlowStartMilliseconds: stats.FlowStartTime,
								FlowEndMilliseconds:   stats.FlowLastSeen,
								TotalBytes:            stats.TotalBytes,
								TotalPackets:          stats.TotalPackets,
							}
							ft.outputChannel <- flow
						}
					case 17:
						// check if flow has timed out
						if now-stats.FlowLastSeen >= 3000 {
							// export flow
							flow := Flow{
								FlowKey:               key,
								FlowStartMilliseconds: stats.FlowStartTime,
								FlowEndMilliseconds:   stats.FlowLastSeen,
								TotalBytes:            stats.TotalBytes,
								TotalPackets:          stats.TotalPackets,
							}
							ft.outputChannel <- flow
						}
					default:
						continue
					}

				}
				ft.flowTableLock.Unlock()
			case <-tickerStop:
				ticker.Stop()
				return
			}
		}
	}()
}

func (ft *FlowTracker) TrackPacket(key FlowKey, packet gopacket.Packet) {
	ft.flowTableLock.Lock()
	defer ft.flowTableLock.Unlock()

	stats, ok := ft.FlowTable[key]
	if !ok {
		stats = &FlowStatistics{
			TotalBytes:    uint64(len(packet.NetworkLayer().LayerPayload())),
			TotalPackets:  1,
			FlowStartTime: uint64(packet.Metadata().Timestamp.UnixNano()) / 1000000,
			FlowLastSeen:  uint64(packet.Metadata().Timestamp.UnixNano()) / 1000000,
		}
		ft.FlowTable[key] = stats
	} else {
		stats.TotalBytes += uint64(len(packet.NetworkLayer().LayerPayload()))
		stats.TotalPackets++
		stats.FlowLastSeen = uint64(packet.Metadata().Timestamp.UnixNano()) / 1000000

		// fmt.Println(stats)
	}

	//Try to determine if the flow is complete by checking TCP flags
}
