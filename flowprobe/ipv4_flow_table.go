package flowprobe

import (
	"time"

	"github.com/google/gopacket"
)

type IPv4FlowTable map[IPv4FlowKey]*FlowStatistics

func (ft IPv4FlowTable) TrackPacket(key IPv4FlowKey, packet gopacket.Packet) {
	stats, ok := ft[key]
	if !ok {
		stats = &FlowStatistics{
			TotalBytes:    uint64(len(packet.NetworkLayer().LayerPayload())),
			TotalPackets:  1,
			FlowStartTime: uint64(packet.Metadata().Timestamp.UnixNano()) / 1000000,
			FlowLastSeen:  uint64(packet.Metadata().Timestamp.UnixNano()) / 1000000,
		}
		ft[key] = stats
	} else {
		stats.TotalBytes += uint64(len(packet.NetworkLayer().LayerPayload()))
		stats.TotalPackets++
		stats.FlowLastSeen = uint64(packet.Metadata().Timestamp.UnixNano()) / 1000000
	}
}

func (ft IPv4FlowTable) SweepTable(outputChannel chan IPv4Flow) {
	now := uint64(time.Now().UnixNano()) / 1000000
	for key, stats := range ft {
		switch key.Protocol {
		case 6:
			// check if flow has timed out
			if now-stats.FlowLastSeen >= 3000 {
				// export flow
				flow := IPv4Flow{
					IPv4FlowKey: key,
					FlowMetadata: FlowMetadata{
						FlowStartMilliseconds: stats.FlowStartTime,
						FlowEndMilliseconds:   stats.FlowLastSeen,
						TotalBytes:            stats.TotalBytes,
						TotalPackets:          stats.TotalPackets,
					},
				}
				outputChannel <- flow
				delete(ft, key)
			}
		case 17:
			// check if flow has timed out
			if now-stats.FlowLastSeen >= 3000 {
				// export flow
				flow := IPv4Flow{
					IPv4FlowKey: key,
					FlowMetadata: FlowMetadata{
						FlowStartMilliseconds: stats.FlowStartTime,
						FlowEndMilliseconds:   stats.FlowLastSeen,
						TotalBytes:            stats.TotalBytes,
						TotalPackets:          stats.TotalPackets,
					},
				}
				outputChannel <- flow
				delete(ft, key)
			}
		default:
			continue
		}

	}
}
