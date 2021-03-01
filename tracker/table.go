package tracker

import (
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/sheacloud/go-flowprobe/flow"
	"github.com/sheacloud/go-flowprobe/protocols"
	"github.com/sheacloud/go-flowprobe/utils"
)

type FlowTableEntry struct {
	Stats FlowStatistics
	Flow  flow.Flow
}

// FlowMetadata tracks metadata associated with a given flow
type FlowStatistics struct {
	TotalBytes          uint64
	TotalPackets        uint64
	ReverseTotalBytes   uint64
	ReverseTotalPackets uint64
	FlowStartTime       uint64
	FlowLastSeen        uint64
	FlowProtocols       []protocols.Protocol
}

type FlowTable struct {
	FlowStats        map[flow.FlowKey]*FlowTableEntry
	Lock             sync.Mutex
	ActiveFlowsGauge prometheus.Gauge
	OutputChannel    chan flow.Flow
}

func NewFlowTable(outputChannel chan flow.Flow, flowGauge prometheus.Gauge) *FlowTable {
	return &FlowTable{
		FlowStats:        make(map[flow.FlowKey]*FlowTableEntry),
		ActiveFlowsGauge: flowGauge,
		OutputChannel:    outputChannel,
	}
}

func (ft *FlowTable) TrackFlow(key flow.FlowKey, networkLayer gopacket.NetworkLayer, transportLayer gopacket.TransportLayer, ci gopacket.CaptureInfo) {
	ft.Lock.Lock()
	defer ft.Lock.Unlock()

	//Check if reverse flowkey is already in table, in which case append to that entries data
	reverseEntry, ok := ft.FlowStats[key.Reverse()]
	if ok {
		reverseEntry.Stats.ReverseTotalBytes += uint64(ci.Length)
		reverseEntry.Stats.ReverseTotalPackets++
		reverseEntry.Stats.FlowLastSeen = uint64(ci.Timestamp.UnixNano()) / 1000000
	} else {
		entry, ok := ft.FlowStats[key]
		if !ok {
			netflow, _ := flow.FlowFromLayers(networkLayer, transportLayer)
			entry = &FlowTableEntry{
				Stats: FlowStatistics{
					TotalBytes:          uint64(ci.Length),
					TotalPackets:        1,
					ReverseTotalBytes:   0,
					ReverseTotalPackets: 0,
					FlowStartTime:       uint64(ci.Timestamp.UnixNano()) / 1000000,
					FlowLastSeen:        uint64(ci.Timestamp.UnixNano()) / 1000000,
				},
				Flow: netflow,
			}
			ft.FlowStats[key] = entry
			utils.FlowsTracked.Inc()
		} else {
			entry.Stats.TotalBytes += uint64(ci.Length)
			entry.Stats.TotalPackets++
			entry.Stats.FlowLastSeen = uint64(ci.Timestamp.UnixNano()) / 1000000
		}
	}
}

func (ft *FlowTable) UpdateMetrics() {
	ft.Lock.Lock()
	defer ft.Lock.Unlock()

	ft.ActiveFlowsGauge.Set(float64(len(ft.FlowStats)))
}

func (ft *FlowTable) SweepTable() {
	ft.Lock.Lock()
	defer ft.Lock.Unlock()

	now := uint64(time.Now().UnixNano()) / 1000000
	for key, entry := range ft.FlowStats {

		// check if flow has timed out
		if now-entry.Stats.FlowLastSeen >= 30000 {
			// export flow
			entry.Flow.FlowStartMilliseconds = entry.Stats.FlowStartTime
			entry.Flow.FlowEndMilliseconds = entry.Stats.FlowLastSeen
			entry.Flow.TotalBytes = entry.Stats.TotalBytes
			entry.Flow.TotalPackets = entry.Stats.TotalPackets
			entry.Flow.ReverseTotalBytes = entry.Stats.ReverseTotalBytes
			entry.Flow.ReverseTotalPackets = entry.Stats.ReverseTotalPackets
			entry.Flow.GuessType()
			ft.OutputChannel <- entry.Flow
			delete(ft.FlowStats, key)
		}

	}
}
