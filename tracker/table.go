package tracker

import (
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/sheacloud/go-flowprobe/flow"
	"github.com/sheacloud/go-flowprobe/protocols"
	"github.com/sheacloud/go-flowprobe/utils"
	"github.com/sirupsen/logrus"
)

type FlowTableEntry struct {
	Metadata FlowMetadata
	Flow     flow.Flow
}

// FlowMetadata tracks metadata associated with a given flow
type FlowMetadata struct {
	TotalBytes          uint64
	TotalPackets        uint64
	ReverseTotalBytes   uint64
	ReverseTotalPackets uint64
	FlowStartTime       uint64
	FlowLastSeen        uint64
	FlowProtocols       []protocols.Protocol
	ClientTCPState      protocols.TCPState
	ServerTCPState      protocols.TCPState
	SYN, ACK, FIN, RST  bool
}

type FlowTable struct {
	FlowStats        map[flow.FlowKey]*FlowTableEntry
	Lock             sync.Mutex
	ActiveFlowsGauge prometheus.Gauge
	OutputChannel    chan flow.Flow
	FlowTimeout      int
	Id               int
}

func NewFlowTable(flowTimeout, id int, outputChannel chan flow.Flow, flowGauge prometheus.Gauge) *FlowTable {
	return &FlowTable{
		FlowStats:        make(map[flow.FlowKey]*FlowTableEntry),
		ActiveFlowsGauge: flowGauge,
		OutputChannel:    outputChannel,
		FlowTimeout:      flowTimeout,
		Id:               id,
	}
}

func (ft *FlowTable) TrackFlow(key flow.FlowKey, networkLayer gopacket.NetworkLayer, transportLayer gopacket.TransportLayer, ci gopacket.CaptureInfo) {
	ft.Lock.Lock()
	defer ft.Lock.Unlock()

	//Check if reverse flowkey is already in table, in which case append to that entries data
	reverseEntry, ok := ft.FlowStats[key.Reverse()]
	if ok {
		reverseEntry.Metadata.ReverseTotalBytes += uint64(ci.Length)
		reverseEntry.Metadata.ReverseTotalPackets++
		reverseEntry.Metadata.FlowLastSeen = uint64(ci.Timestamp.UnixNano()) / 1000000

		//
		// Trying to implement logic to determine when a TCP sequence is closed is surprisingly difficult
		//
		if transportLayer != nil {
			if transportLayer.LayerType() == layers.LayerTypeTCP {
				tcp := transportLayer.(*layers.TCP)

				reverseEntry.Metadata.SYN = reverseEntry.Metadata.SYN || tcp.SYN
				reverseEntry.Metadata.ACK = reverseEntry.Metadata.ACK || tcp.ACK
				reverseEntry.Metadata.FIN = reverseEntry.Metadata.FIN || tcp.FIN
				reverseEntry.Metadata.RST = reverseEntry.Metadata.RST || tcp.RST

				// this flow is first part of the TCP termination 4-way handshake with server as the initiator of the termination
				if tcp.FIN && reverseEntry.Metadata.ServerTCPState == protocols.TCPStateEstablished {
					reverseEntry.Metadata.ServerTCPState = protocols.TCPStateFinWait1
					reverseEntry.Metadata.ClientTCPState = protocols.TCPStateCloseWait
					// logrus.Trace("Moved flow pt5")
					// This flow is final ACK in the 4-way handshake with server as the initiator of the termination
				} else if tcp.ACK && reverseEntry.Metadata.ServerTCPState == protocols.TCPStateTimeWait {
					reverseEntry.Metadata.ServerTCPState = protocols.TCPStateClosed
					reverseEntry.Metadata.ClientTCPState = protocols.TCPStateClosed
					// logrus.Trace("Moved flow pt6")
					logrus.Info("Releasing flow due to TCP termination initiated by server")
					// This flow is the 1st ACK in the 4-way handshake with client as the initiator of the termination
				} else if tcp.ACK && reverseEntry.Metadata.ServerTCPState == protocols.TCPStateCloseWait {
					// logrus.WithFields(logrus.Fields{
					// 	"fin": tcp.FIN,
					// 	"ack": tcp.ACK,
					// }).Trace("Moved flow pt7")
					if tcp.FIN {
						reverseEntry.Metadata.ClientTCPState = protocols.TCPStateTimeWait
						reverseEntry.Metadata.ServerTCPState = protocols.TCPStateLastAck
					} else {
						reverseEntry.Metadata.ClientTCPState = protocols.TCPStateFinWait2
					}
					// This flow is the 2nd FIN in the termination with client as the initiator of the termination
				} else if tcp.FIN && reverseEntry.Metadata.ServerTCPState == protocols.TCPStateCloseWait {
					reverseEntry.Metadata.ServerTCPState = protocols.TCPStateLastAck
					reverseEntry.Metadata.ClientTCPState = protocols.TCPStateTimeWait
					// logrus.Trace("Moved flow pt8")
				} else if tcp.RST {
					logrus.WithFields(logrus.Fields{
						"rst": tcp.RST,
						"ack": tcp.ACK,
						"fin": tcp.FIN,
					}).Info("TCP RST initiated by server")
					if tcp.ACK {
						reverseEntry.Metadata.ClientTCPState = protocols.TCPStateResetAcked
						reverseEntry.Metadata.ServerTCPState = protocols.TCPStateResetAcked
					} else {
						reverseEntry.Metadata.ServerTCPState = protocols.TCPStateClosed
					}
				} else if tcp.ACK && reverseEntry.Metadata.ClientTCPState == protocols.TCPStateResetAcked {
					// logrus.Info("TCP RST ACK'd by server")
					reverseEntry.Metadata.ServerTCPState = protocols.TCPStateClosed
				}

				if reverseEntry.Metadata.ClientTCPState == protocols.TCPStateClosed && reverseEntry.Metadata.ServerTCPState == protocols.TCPStateClosed {
					now := uint64(time.Now().UnixNano()) / 1000000
					logrus.WithFields(logrus.Fields{
						"flow_timeout":         ft.FlowTimeout,
						"time_since_last_seen": now - reverseEntry.Metadata.FlowLastSeen,
						"flow":                 key.String(),
						"table_id":             ft.Id,
					}).Trace("Removing flow from Flow Table due to TCP state closure")
					ft.ReleaseFlow(key, reverseEntry)
				}
			}
		}

		return
	}

	entry, ok := ft.FlowStats[key]
	if ok {
		entry.Metadata.TotalBytes += uint64(ci.Length)
		entry.Metadata.TotalPackets++
		entry.Metadata.FlowLastSeen = uint64(ci.Timestamp.UnixNano()) / 1000000

		//
		// Trying to implement logic to determine when a TCP sequence is closed is surprisingly difficult
		//
		if transportLayer != nil {
			if transportLayer.LayerType() == layers.LayerTypeTCP {
				tcp := transportLayer.(*layers.TCP)

				entry.Metadata.SYN = entry.Metadata.SYN || tcp.SYN
				entry.Metadata.ACK = entry.Metadata.ACK || tcp.ACK
				entry.Metadata.FIN = entry.Metadata.FIN || tcp.FIN
				entry.Metadata.RST = entry.Metadata.RST || tcp.RST

				// this flow is first part of the TCP termination 4-way handshake with client as the initiator of the termination
				if tcp.FIN && entry.Metadata.ClientTCPState == protocols.TCPStateEstablished {
					// logrus.Trace("Moved flow pt1")
					entry.Metadata.ClientTCPState = protocols.TCPStateFinWait1
					entry.Metadata.ServerTCPState = protocols.TCPStateCloseWait
					// This flow is final ACK in the 4-way handshake with client as the initiator of the termination
				} else if tcp.ACK && entry.Metadata.ClientTCPState == protocols.TCPStateTimeWait {
					// logrus.Trace("Moved flow pt2")
					entry.Metadata.ClientTCPState = protocols.TCPStateClosed
					entry.Metadata.ServerTCPState = protocols.TCPStateClosed
					logrus.Info("Releasing flow due to TCP termination initiated by client")

					// This flow is the 1st ACK in the 4-way handshake with server as the initiator of the termination
				} else if tcp.ACK && entry.Metadata.ClientTCPState == protocols.TCPStateCloseWait {
					// logrus.WithFields(logrus.Fields{
					// 	"fin": tcp.FIN,
					// 	"ack": tcp.ACK,
					// }).Trace("Moved flow pt3")
					if tcp.FIN {
						entry.Metadata.ServerTCPState = protocols.TCPStateTimeWait
						entry.Metadata.ClientTCPState = protocols.TCPStateLastAck
					} else {
						entry.Metadata.ServerTCPState = protocols.TCPStateFinWait2
					}
					// This flow is the 2nd FIN in the termination with server as the initiator of the termination
				} else if tcp.FIN && entry.Metadata.ClientTCPState == protocols.TCPStateCloseWait {
					// logrus.Trace("Moved flow pt4")
					entry.Metadata.ClientTCPState = protocols.TCPStateLastAck
					entry.Metadata.ServerTCPState = protocols.TCPStateTimeWait
				} else if tcp.RST {
					logrus.WithFields(logrus.Fields{
						"rst": tcp.RST,
						"ack": tcp.ACK,
						"fin": tcp.FIN,
					}).Info("TCP RST initiated by client")
					if tcp.ACK {
						entry.Metadata.ClientTCPState = protocols.TCPStateResetAcked
						entry.Metadata.ServerTCPState = protocols.TCPStateResetAcked
					} else {
						entry.Metadata.ClientTCPState = protocols.TCPStateClosed
					}
				} else if tcp.ACK && entry.Metadata.ServerTCPState == protocols.TCPStateResetAcked {
					// logrus.Info("TCP RST ACK'd by client")
					entry.Metadata.ClientTCPState = protocols.TCPStateClosed
				}

				if entry.Metadata.ClientTCPState == protocols.TCPStateClosed && entry.Metadata.ServerTCPState == protocols.TCPStateClosed {
					now := uint64(time.Now().UnixNano()) / 1000000
					logrus.WithFields(logrus.Fields{
						"flow_timeout":         ft.FlowTimeout,
						"time_since_last_seen": now - entry.Metadata.FlowLastSeen,
						"flow":                 key.String(),
						"table_id":             ft.Id,
					}).Trace("Removing flow from Flow Table due to TCP state closure")
					ft.ReleaseFlow(key, entry)
				}
			}
		}

		return
	}

	// Flow is new, create an entry for it
	netflow, _ := flow.FlowFromLayers(networkLayer, transportLayer)
	entry = &FlowTableEntry{
		Metadata: FlowMetadata{
			TotalBytes:          uint64(ci.Length),
			TotalPackets:        1,
			ReverseTotalBytes:   0,
			ReverseTotalPackets: 0,
			FlowStartTime:       uint64(ci.Timestamp.UnixNano()) / 1000000,
			FlowLastSeen:        uint64(ci.Timestamp.UnixNano()) / 1000000,
			ClientTCPState:      protocols.TCPStateEstablished,
			ServerTCPState:      protocols.TCPStateEstablished,
		},
		Flow: netflow,
	}
	ft.FlowStats[key] = entry
	utils.FlowsTracked.Inc()

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
		if now-entry.Metadata.FlowLastSeen >= uint64(ft.FlowTimeout*1000) {
			logrus.WithFields(logrus.Fields{
				"flow_timeout":         ft.FlowTimeout,
				"time_since_last_seen": now - entry.Metadata.FlowLastSeen,
				"packets":              entry.Metadata.TotalPackets,
				"reverse_packets":      entry.Metadata.ReverseTotalPackets,
				"flow":                 key.String(),
				"syn":                  entry.Metadata.SYN,
				"ack":                  entry.Metadata.ACK,
				"fin":                  entry.Metadata.FIN,
				"rst":                  entry.Metadata.RST,
				"table_id":             ft.Id,
			}).Trace("Removing flow from Flow Table due to max timeout reached")
			ft.ReleaseFlow(key, entry)
		}

	}

	logrus.WithFields(logrus.Fields{
		"table_id":                 ft.Id,
		"remaining_flows_in_table": len(ft.FlowStats),
	}).Info("Swept Flow Table")
}

// ReleaseFlow assumes that the FlowTable lock is already aquired
func (ft *FlowTable) ReleaseFlow(key flow.FlowKey, entry *FlowTableEntry) {
	// export flow
	entry.Flow.FlowStartMilliseconds = entry.Metadata.FlowStartTime
	entry.Flow.FlowEndMilliseconds = entry.Metadata.FlowLastSeen
	entry.Flow.TotalBytes = entry.Metadata.TotalBytes
	entry.Flow.TotalPackets = entry.Metadata.TotalPackets
	entry.Flow.ReverseTotalBytes = entry.Metadata.ReverseTotalBytes
	entry.Flow.ReverseTotalPackets = entry.Metadata.ReverseTotalPackets
	entry.Flow.GuessType()

	ft.OutputChannel <- entry.Flow
	delete(ft.FlowStats, key)
}
