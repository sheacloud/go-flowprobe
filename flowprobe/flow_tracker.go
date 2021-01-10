package flowprobe

import (
	"strconv"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/sheacloud/go-flowprobe/utils"
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
	IPv4FlowTable        IPv4FlowTable
	ipv4FlowTableLock    sync.Mutex
	ipv4OutputChannel    chan IPv4Flow
	trackerNum           uint32
	ipv4ActiveFlowsGauge prometheus.Gauge
}

func NewFlowTracker(ipv4OutputChannel chan IPv4Flow, trackerNum uint32) *FlowTracker {
	return &FlowTracker{
		IPv4FlowTable:        make(IPv4FlowTable),
		ipv4OutputChannel:    ipv4OutputChannel,
		trackerNum:           trackerNum,
		ipv4ActiveFlowsGauge: utils.ActiveIPv4Flows.WithLabelValues(strconv.Itoa(int(trackerNum))),
	}
}

func (ft *FlowTracker) SweepTables() {
	go func() {
		ft.ipv4FlowTableLock.Lock()
		defer ft.ipv4FlowTableLock.Unlock()
		ft.IPv4FlowTable.SweepTable(ft.ipv4OutputChannel)
	}()
}

func (ft *FlowTracker) UpdateMetrics() {
	go func() {
		ft.ipv4FlowTableLock.Lock()
		defer ft.ipv4FlowTableLock.Unlock()
		ft.ipv4ActiveFlowsGauge.Set(float64(len(ft.IPv4FlowTable)))
	}()
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
}

func (ft *FlowTracker) TrackIPv4Flow(key IPv4FlowKey, ci gopacket.CaptureInfo) {
	ft.ipv4FlowTableLock.Lock()
	defer ft.ipv4FlowTableLock.Unlock()

	ft.IPv4FlowTable.TrackPacket(key, ci)
}
