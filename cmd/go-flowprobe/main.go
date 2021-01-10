package main

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sheacloud/go-flowprobe/flowprobe"

	_ "net/http/pprof"
)

var exporter *flowprobe.FlowExporter
var sniffers []*flowprobe.FlowSniffer

func httpServer() {
	http.Handle("/metrics", promhttp.Handler())
	log.Fatal(http.ListenAndServe(":2112", nil))
}

func main() {

	iface := os.Getenv("GOFLOWPROBE_IFACE")
	ipfixIP := os.Getenv("GOFLOWPROBE_IPFIX_IP")
	ipfixPortString := os.Getenv("GOFLOWPROBE_IPFIX_PORT")
	numSniffersString := os.Getenv("GOFLOWPROBE_NUM_SNIFFERS")
	if iface == "" {
		iface = "eno1"
	}
	if ipfixIP == "" {
		ipfixIP = "127.0.0.1"
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

	go httpServer()

	ipv4FlowChannel := make(chan flowprobe.IPv4Flow)

	sniffers = make([]*flowprobe.FlowSniffer, numSniffers)
	var i uint32
	for i = 0; i < uint32(numSniffers); i++ {
		sniffers[i] = flowprobe.NewFlowSniffer(iface, 0, ipv4FlowChannel, i)
	}

	exporter = flowprobe.NewFlowExporter(net.ParseIP(ipfixIP), ipfixPort, ipv4FlowChannel)

	exporter.Start()

	for _, sniffer := range sniffers {
		sniffer.Start()
	}

	SetupCloseHandler()

	for {
		time.Sleep(5 * time.Second)
	}
}

func SetupCloseHandler() {
	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		fmt.Println("\r- Ctrl+C pressed in Terminal")
		exporter.Stop()
		for _, sniffer := range sniffers {
			sniffer.Stop()
		}
		time.Sleep(2 * time.Second)
		os.Exit(0)
	}()
}
