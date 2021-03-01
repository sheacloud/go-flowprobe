package tracker

import (
	"strconv"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/sheacloud/go-flowprobe/flow"
	"github.com/sheacloud/go-flowprobe/utils"
	"k8s.io/klog"
)

type FlowTrackerConfiguration struct {
	MaxFlowLength uint64
	FlowTimeout   uint64
}

type FlowTracker struct {
	FlowTables    []*FlowTable
	FlowTableLock sync.Mutex
	OutputChannel chan flow.Flow
	NumTables     int
}

func NewFlowTracker(outputChannel chan flow.Flow, numTables int) *FlowTracker {
	tables := make([]*FlowTable, numTables)
	for i := 0; i < numTables; i++ {
		tables[i] = NewFlowTable(outputChannel, utils.ActiveFlows.WithLabelValues(strconv.Itoa(i)))
	}

	return &FlowTracker{
		FlowTables:    tables,
		OutputChannel: outputChannel,
		NumTables:     numTables,
	}
}

func (ft *FlowTracker) SweepTables() {
	for _, table := range ft.FlowTables {
		go table.SweepTable()
	}
}

func (ft *FlowTracker) UpdateMetrics() {
	for _, table := range ft.FlowTables {
		go table.UpdateMetrics()
	}
}

func (ft *FlowTracker) Start() {
	sweepTicker := time.NewTicker(5 * time.Second)
	sweepTickerStop := make(chan bool)
	go func() {
		for {
			select {
			case <-sweepTicker.C:
				// run through flow table and clean up old flows
				ft.SweepTables()
			case <-sweepTickerStop:
				sweepTicker.Stop()
				return
			}
		}
	}()

	metricTicker := time.NewTicker(500 * time.Millisecond)
	metricTickerStop := make(chan bool)
	go func() {
		for {
			select {
			case <-metricTicker.C:
				// run through flow table and clean up old flows
				ft.UpdateMetrics()
			case <-metricTickerStop:
				metricTicker.Stop()
				return
			}
		}
	}()

	klog.Info("Started flow tracker")
}

func (ft *FlowTracker) TrackFlow(key flow.FlowKey, networkLayer gopacket.NetworkLayer, transportLayer gopacket.TransportLayer, ci gopacket.CaptureInfo) {
	keyHash := key.Hash()
	flowTableIndex := int64(keyHash) % int64(ft.NumTables)
	ft.FlowTables[flowTableIndex].TrackFlow(key, networkLayer, transportLayer, ci)
}
