package main

import (
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sheacloud/go-flowprobe/exporter"
	"github.com/sheacloud/go-flowprobe/flow"
	"github.com/sheacloud/go-flowprobe/sniffer"

	_ "net/http/pprof"
)

var ipfixExporter *exporter.IpfixFlowExporter
var sniffers []sniffer.FlowSniffer

func signalHandler(stopCh chan struct{}) {
	signalCh := make(chan os.Signal, 1)
	signal.Notify(signalCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)

	for {
		select {
		case <-signalCh:
			close(stopCh)
			return
		}
	}
}

func httpServer() {
	http.Handle("/metrics", promhttp.Handler())
	log.Fatal(http.ListenAndServe(":2112", nil))
}

func main() {

	iface := os.Getenv("GOFLOWPROBE_IFACE")
	ipfixTarget := os.Getenv("GOFLOWPROBE_IPFIX_TARGET")
	ipfixPortString := os.Getenv("GOFLOWPROBE_IPFIX_PORT")
	numSniffersString := os.Getenv("GOFLOWPROBE_NUM_SNIFFERS")
	zeroCopy := os.Getenv("GOFLOWPROBE_ZEROCOPY")
	if iface == "" {
		iface = "eno1"
	}
	if ipfixTarget == "" {
		ipfixTarget = "127.0.0.1"
	}
	if ipfixPortString == "" {
		ipfixPortString = "4739"
	}
	if numSniffersString == "" {
		numSniffersString = "1"
	}
	ipfixPort, err := strconv.Atoi(ipfixPortString)
	if err != nil {
		panic(err)
	}
	numSniffers, err := strconv.Atoi(numSniffersString)
	if err != nil {
		panic(err)
	}
	if zeroCopy == "" {
		zeroCopy = "true"
	}

	go httpServer()

	flowChannel := make(chan flow.Flow)

	sniffers = make([]sniffer.FlowSniffer, numSniffers)
	var i uint16
	for i = 0; i < uint16(numSniffers); i++ {
		if zeroCopy == "true" {
			source := sniffer.ZeroCopyPacketDataSourceFromDevice(iface, i)
			sniffers[i] = sniffer.NewZeroCopyFlowSniffer(source, flowChannel, i)
		} else {
			sniffers[i] = sniffer.NewPCAPFlowSniffer(iface, flowChannel, i)
		}
	}

	ipfixExporter = exporter.NewIpfixFlowExporter(ipfixTarget, ipfixPort, flowChannel)

	ipfixExporter.Start()

	for _, sniffer := range sniffers {
		sniffer.Start()
	}

	stopCh := make(chan struct{})
	go signalHandler(stopCh)

	<-stopCh
	for _, sniffer := range sniffers {
		sniffer.Stop()
	}
	time.Sleep(2 * time.Second)
	ipfixExporter.Stop()
	time.Sleep(2 * time.Second)
	os.Exit(0)
}
