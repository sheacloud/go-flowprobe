package utils

import (
	"github.com/prometheus/client_golang/prometheus"
)

var (
	FlowsTracked = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "flows_tracked",
			Help: "Number of flows that have been tracked",
		},
	)

	ActiveFlows = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "active_ipv4_flows",
			Help: "Number of active IPv4 flows in each flow tracking table",
		},
		[]string{"table_number"},
	)
)

func init() {
	prometheus.MustRegister(FlowsTracked)
	prometheus.MustRegister(ActiveFlows)
}
