package tracker

import (
	"strconv"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/sheacloud/go-flowprobe/flow"
	"github.com/sheacloud/go-flowprobe/utils"
	"github.com/sirupsen/logrus"
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

func NewFlowTracker(outputChannel chan flow.Flow, numTables, flowTimeout int) *FlowTracker {
	tables := make([]*FlowTable, numTables)
	for i := 0; i < numTables; i++ {
		tables[i] = NewFlowTable(flowTimeout, i, outputChannel, utils.ActiveFlows.WithLabelValues(strconv.Itoa(i)))
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
				logrus.Info("Sweeping FlowTracker Tables")
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
				ft.UpdateMetrics()
			case <-metricTickerStop:
				metricTicker.Stop()
				return
			}
		}
	}()

	logrus.WithFields(logrus.Fields{
		"num_tables": ft.NumTables,
	}).Info("Starting Flow Tracker")
}

func (ft *FlowTracker) TrackFlow(key flow.FlowKey, networkLayer gopacket.NetworkLayer, transportLayer gopacket.TransportLayer, ci gopacket.CaptureInfo) {
	keyHash := key.Hash()
	flowTableIndex := keyHash % uint64(ft.NumTables)
	ft.FlowTables[flowTableIndex].TrackFlow(key, networkLayer, transportLayer, ci)
}
