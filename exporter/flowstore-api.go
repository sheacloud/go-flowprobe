package exporter

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"sync"

	"github.com/google/gopacket/layers"
	retryablehttp "github.com/hashicorp/go-retryablehttp"
	"github.com/sheacloud/go-flowprobe/flow"
	"github.com/sirupsen/logrus"
)

type FlowstorePostInput struct {
	Flows []FlowstoreFlow `json:"flows,omitempty"`
}

type FlowstorePostOutput struct {
	Error          string `json:"error"`
	ProcessedFlows int    `json:"processed_flows"`
}

type FlowstoreFlow struct {
	SourceIP               string `json:"source_ip"`
	DestinationIP          string `json:"destination_ip"`
	SourcePort             uint16 `json:"source_port"`
	DestinationPort        uint16 `json:"destination_port"`
	Protocol               uint8  `json:"protocol"`
	FlowStartMilliseconds  uint64 `json:"flow_start_milliseconds"`
	FlowEndMilliseconds    uint64 `json:"flow_end_milliseconds"`
	FlowOctetCount         uint64 `json:"flow_octet_count"`
	FlowPacketCount        uint64 `json:"flow_packet_count"`
	ReverseFlowOctetCount  uint64 `json:"reverse_flow_octet_count"`
	ReverseFlowPacketCount uint64 `json:"reverse_flow_packet_count"`
}

type FlowstoreFlowExporter struct {
	target            string
	port              int
	protocol          string
	maxFlowsPerUpload int
	flowInputChannel  chan flow.Flow
	stopChannel       chan bool
	waitGroup         *sync.WaitGroup
	flowBuffer        []FlowstoreFlow
	flowBufferIndex   int
}

func NewFlowstoreFlowExporter(target string, port int, protocol string, maxFlowsPerUpload int, flowInputChannel chan flow.Flow, waitGroup *sync.WaitGroup) *FlowstoreFlowExporter {
	return &FlowstoreFlowExporter{
		target:            target,
		port:              port,
		protocol:          protocol,
		maxFlowsPerUpload: maxFlowsPerUpload,
		flowInputChannel:  flowInputChannel,
		stopChannel:       make(chan bool),
		waitGroup:         waitGroup,
		flowBuffer:        make([]FlowstoreFlow, maxFlowsPerUpload),
		flowBufferIndex:   0,
	}
}

func (f *FlowstoreFlowExporter) Start() {
	go func() {
		logrus.WithFields(logrus.Fields{
			"target": f.target,
			"port":   f.port,
		}).Info("Starting Flowstore API Exporter")

	InfiniteLoop:
		for {
			select {
			case <-f.stopChannel:
				err := f.UploadFlows()
				if err != nil {
					logrus.WithFields(logrus.Fields{
						"error": err,
					}).Error("Error flushing flow buffer")
				}
				break InfiniteLoop
			case flow := <-f.flowInputChannel:
				switch flow.NetworkType {
				case layers.LayerTypeIPv4:
					f.AddIPv4Flow(flow)
					if f.flowBufferIndex == f.maxFlowsPerUpload {
						err := f.UploadFlows()
						if err != nil {
							logrus.WithFields(logrus.Fields{
								"error": err,
							}).Error("Error uploading flows")
						}
					}
				case layers.LayerTypeIPv6:
					logrus.Warning("IPv6 Flows not supported")
				}
			}
		}
		logrus.Info("Stopped Flowstore API Exporter")
		f.waitGroup.Done()
	}()
}

func (f *FlowstoreFlowExporter) Stop() {
	f.stopChannel <- true
}

func (f *FlowstoreFlowExporter) UploadFlows() error {
	logrus.Info("Uploading flows to flowstore")
	defer f.ResetBuffer()

	flowsInput := FlowstorePostInput{Flows: f.flowBuffer}

	flowsInputData, err := json.Marshal(flowsInput)
	if err != nil {
		return err
	}

	req, err := retryablehttp.NewRequest("POST", fmt.Sprintf("%s://%s:%v/flowstore/flows/", f.protocol, f.target, f.port), bytes.NewBuffer(flowsInputData))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	client := retryablehttp.NewClient()
	client.RetryMax = 2

	resp, err := client.Do(req)
	if err != nil {
		return err
	}

	defer resp.Body.Close()

	if resp.StatusCode == 500 {
		return fmt.Errorf("Received 500 error trying to upload flows to flowstore")
	}

	var output FlowstorePostOutput
	outputBytes, _ := ioutil.ReadAll(resp.Body)
	err = json.Unmarshal(outputBytes, &output)
	if err != nil {
		return err
	}

	if resp.StatusCode != 200 {
		logrus.WithFields(logrus.Fields{
			"error": output.Error,
		}).Error("Error uploading flows to flowstore")
		return nil
	}

	logrus.WithFields(logrus.Fields{
		"processed_flows": output.ProcessedFlows,
	}).Info("Uploaded flows to flowstore")

	return nil
}

func (f *FlowstoreFlowExporter) AddIPv4Flow(ipv4Flow flow.Flow) {
	// convert flow to flowstore format
	flowstoreFlow := FlowstoreFlow{
		Protocol:              uint8(ipv4Flow.Protocol),
		FlowStartMilliseconds: ipv4Flow.FlowStartMilliseconds,
		FlowEndMilliseconds:   ipv4Flow.FlowEndMilliseconds,
	}

	if ipv4Flow.Type == flow.Initiator || ipv4Flow.Type == flow.Unknown {
		flowstoreFlow.SourceIP = ipv4Flow.NetworkSourceAddress.String()
		flowstoreFlow.DestinationIP = ipv4Flow.NetworkDestAddress.String()
		flowstoreFlow.SourcePort = ipv4Flow.TransportSourcePort
		flowstoreFlow.DestinationPort = ipv4Flow.TransportDestPort
		flowstoreFlow.FlowOctetCount = ipv4Flow.TotalBytes
		flowstoreFlow.FlowPacketCount = ipv4Flow.TotalPackets
		flowstoreFlow.ReverseFlowOctetCount = ipv4Flow.ReverseTotalBytes
		flowstoreFlow.ReverseFlowPacketCount = ipv4Flow.ReverseTotalPackets
	} else {
		flowstoreFlow.SourceIP = ipv4Flow.NetworkDestAddress.String()
		flowstoreFlow.DestinationIP = ipv4Flow.NetworkSourceAddress.String()
		flowstoreFlow.SourcePort = ipv4Flow.TransportDestPort
		flowstoreFlow.DestinationPort = ipv4Flow.TransportSourcePort
		flowstoreFlow.FlowOctetCount = ipv4Flow.ReverseTotalBytes
		flowstoreFlow.FlowPacketCount = ipv4Flow.ReverseTotalPackets
		flowstoreFlow.ReverseFlowOctetCount = ipv4Flow.TotalBytes
		flowstoreFlow.ReverseFlowPacketCount = ipv4Flow.TotalPackets
	}

	if f.flowBufferIndex >= len(f.flowBuffer) {
		panic(fmt.Errorf("Flowstore flow buffer index exceeded buffer size: %v", f.flowBufferIndex))
	}

	f.flowBuffer[f.flowBufferIndex] = flowstoreFlow
	f.flowBufferIndex += 1
}

func (f *FlowstoreFlowExporter) ResetBuffer() {
	f.flowBuffer = make([]FlowstoreFlow, f.maxFlowsPerUpload)
	f.flowBufferIndex = 0
}
