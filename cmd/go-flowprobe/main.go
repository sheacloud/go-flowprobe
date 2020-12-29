package main

import (
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/sheacloud/go-flowprobe/flowprobe"
)

var exporter *flowprobe.FlowExporter
var router *flowprobe.FlowRouter

func main() {
	iface := os.Getenv("GOFLOWPROBE_IFACE")
	ipfixIP := os.Getenv("GOFLOWPROBE_IPFIX_IP")
	ipfixPortString := os.Getenv("GOFLOWPROBE_IPFIX_PORT")
	if iface == "" {
		iface = "en11"
	}
	if ipfixIP == "" {
		ipfixIP = "127.0.0.1"
	}
	if ipfixPortString == "" {
		ipfixPortString = "4739"
	}
	ipfixPort, err := strconv.Atoi(ipfixPortString)
	if err != nil {
		panic(err)
	}

	if handle, err := pcap.OpenLive(iface, 1600, true, pcap.BlockForever); err != nil {
		panic(err)
	} else {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

		ipv4FlowChannel := make(chan flowprobe.IPv4Flow)
		router = flowprobe.NewFlowRouter(packetSource.Packets(), 4, ipv4FlowChannel)

		exporter = flowprobe.NewFlowExporter(net.ParseIP(ipfixIP), ipfixPort, ipv4FlowChannel)

		exporter.Start()
		router.Start()

		SetupCloseHandler()

		for {
			time.Sleep(5 * time.Second)
		}
	}
}

func SetupCloseHandler() {
	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		fmt.Println("\r- Ctrl+C pressed in Terminal")
		exporter.Stop()
		router.Stop()
		time.Sleep(2 * time.Second)
		os.Exit(0)
	}()
}
