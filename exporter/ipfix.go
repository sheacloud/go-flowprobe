package exporter

import (
	"fmt"
	"net"

	"github.com/cenkalti/backoff/v4"
	"github.com/google/gopacket/layers"
	"github.com/sheacloud/go-flowprobe/flow"
	"github.com/vmware/go-ipfix/pkg/entities"
	"github.com/vmware/go-ipfix/pkg/exporter"
	"github.com/vmware/go-ipfix/pkg/registry"
	"k8s.io/klog"
)

func init() {
	registry.LoadRegistry()
}

type IpfixFlowExporter struct {
	exporter                 *exporter.ExportingProcess
	uniDataSet               entities.Set
	biDataSet                entities.Set
	unidirectionalTemplateID uint16
	bidirectionalTemplateID  uint16
	FlowRecordsSent          uint64
	UniElementBuffer         []*entities.InfoElementWithValue
	BiElementBuffer          []*entities.InfoElementWithValue
	StopChannel              chan bool
	InputChannel             chan flow.Flow
	collectorTarget          string
	collectorPort            int
}

var sourceIPv4AddressElement *entities.InfoElement
var destinationIPv4AddressElement *entities.InfoElement
var sourceTransportPortElement *entities.InfoElement
var destinationTransportPortElement *entities.InfoElement
var protocolIdentifierElement *entities.InfoElement
var flowStartMillisecondsElement *entities.InfoElement
var flowEndMillisecondsElement *entities.InfoElement
var octetDeltaCountElement *entities.InfoElement
var packetDeltaCountElement *entities.InfoElement

var initiatorOctetsElement *entities.InfoElement
var initiatorPacketsElement *entities.InfoElement
var responderOctetsElement *entities.InfoElement
var responderPacketsElement *entities.InfoElement

func fetchAddrFromName(hostname string) (net.IP, error) {
	ips, err := net.LookupHost(hostname)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("Did not find any IPs from %s", hostname)
	}

	ip := net.ParseIP(ips[0])
	if ip == nil {
		return nil, fmt.Errorf("Got bad IP from DNS")
	}
	return ip, nil

}

func NewIpfixFlowExporter(collectorTarget string, collectorPort int, flowInputChannel chan flow.Flow) *IpfixFlowExporter {
	flowExporter := &IpfixFlowExporter{
		UniElementBuffer: make([]*entities.InfoElementWithValue, 9),
		BiElementBuffer:  make([]*entities.InfoElementWithValue, 11),
		StopChannel:      make(chan bool),
		InputChannel:     flowInputChannel,
		collectorTarget:  collectorTarget,
		collectorPort:    collectorPort,
	}

	flowExporter.refreshExporter()

	return flowExporter
}

func (fe *IpfixFlowExporter) refreshExporter() {
	ip, _ := fetchAddrFromName(fe.collectorTarget)

	var exporterProcess *exporter.ExportingProcess

	operation := func() error {
		var err error
		fmt.Printf("creating exporter\n")
		exporterProcess, err = exporter.InitExportingProcess(exporter.ExporterInput{
			CollectorAddress:    fmt.Sprintf("%v:%v", ip, fe.collectorPort),
			CollectorProtocol:   "tcp",
			ObservationDomainID: 1,
			TempRefTimeout:      0,
		})
		if err != nil {
			fmt.Printf("got error creating exporting process %s\n", err)
		}

		return err
	}

	err := backoff.Retry(operation, backoff.NewExponentialBackOff())
	if err != nil {
		panic("failed to create exporter")
	}

	uniTemplateID := exporterProcess.NewTemplateID()
	biTemplateID := exporterProcess.NewTemplateID()

	uniDataSet := entities.NewSet(false)
	uniDataSet.PrepareSet(entities.Data, uniTemplateID)
	biDataSet := entities.NewSet(false)
	biDataSet.PrepareSet(entities.Data, biTemplateID)

	fe.uniDataSet = uniDataSet
	fe.biDataSet = biDataSet
	fe.unidirectionalTemplateID = uniTemplateID
	fe.bidirectionalTemplateID = biTemplateID
	fe.exporter = exporterProcess
}

func (fe *IpfixFlowExporter) refreshUniTemplate() {
	templateElementNames := []string{"sourceIPv4Address", "destinationIPv4Address", "sourceTransportPort", "destinationTransportPort", "protocolIdentifier", "flowStartMilliseconds", "flowEndMilliseconds", "octetDeltaCount", "packetDeltaCount"}

	templateSet := entities.NewSet(false)
	templateSet.PrepareSet(entities.Template, fe.unidirectionalTemplateID)
	elements := make([]*entities.InfoElementWithValue, 0)

	for _, elementName := range templateElementNames {
		element, err := registry.GetInfoElement(elementName, registry.IANAEnterpriseID)
		if err != nil {
			fmt.Printf("Did not find the element with name %v\n", elementName)
			return
		}
		ie := entities.NewInfoElementWithValue(element, nil)
		elements = append(elements, ie)
	}

	templateSet.AddRecord(elements, fe.unidirectionalTemplateID)

	_, err := fe.exporter.SendSet(templateSet)
	if err != nil {
		fmt.Printf("Got error when sending record: %v\n", err)
		return
	}
}

func (fe *IpfixFlowExporter) refreshBiTemplate() {
	templateElementNames := []string{"sourceIPv4Address", "destinationIPv4Address", "sourceTransportPort", "destinationTransportPort", "protocolIdentifier", "flowStartMilliseconds", "flowEndMilliseconds", "initiatorOctets", "initiatorPackets", "responderOctets", "responderPackets"}

	templateSet := entities.NewSet(false)
	templateSet.PrepareSet(entities.Template, fe.bidirectionalTemplateID)
	elements := make([]*entities.InfoElementWithValue, 0)

	for _, elementName := range templateElementNames {
		element, err := registry.GetInfoElement(elementName, registry.IANAEnterpriseID)
		if err != nil {
			fmt.Printf("Did not find the element with name %v\n", elementName)
			return
		}
		ie := entities.NewInfoElementWithValue(element, nil)
		elements = append(elements, ie)
	}

	templateSet.AddRecord(elements, fe.bidirectionalTemplateID)

	_, err := fe.exporter.SendSet(templateSet)
	if err != nil {
		fmt.Printf("Got error when sending record: %v\n", err)
		return
	}
}

func (fe *IpfixFlowExporter) Start() {
	fe.refreshUniTemplate()
	fe.refreshBiTemplate()

	sourceIPv4AddressElement, _ = registry.GetInfoElement("sourceIPv4Address", registry.IANAEnterpriseID)
	destinationIPv4AddressElement, _ = registry.GetInfoElement("destinationIPv4Address", registry.IANAEnterpriseID)
	sourceTransportPortElement, _ = registry.GetInfoElement("sourceTransportPort", registry.IANAEnterpriseID)
	destinationTransportPortElement, _ = registry.GetInfoElement("destinationTransportPort", registry.IANAEnterpriseID)
	protocolIdentifierElement, _ = registry.GetInfoElement("protocolIdentifier", registry.IANAEnterpriseID)
	flowStartMillisecondsElement, _ = registry.GetInfoElement("flowStartMilliseconds", registry.IANAEnterpriseID)
	flowEndMillisecondsElement, _ = registry.GetInfoElement("flowEndMilliseconds", registry.IANAEnterpriseID)
	octetDeltaCountElement, _ = registry.GetInfoElement("octetDeltaCount", registry.IANAEnterpriseID)
	packetDeltaCountElement, _ = registry.GetInfoElement("packetDeltaCount", registry.IANAEnterpriseID)
	initiatorOctetsElement, _ = registry.GetInfoElement("initiatorOctets", registry.IANAEnterpriseID)
	initiatorPacketsElement, _ = registry.GetInfoElement("initiatorPackets", registry.IANAEnterpriseID)
	responderOctetsElement, _ = registry.GetInfoElement("responderOctets", registry.IANAEnterpriseID)
	responderPacketsElement, _ = registry.GetInfoElement("responderPackets", registry.IANAEnterpriseID)

	go func() {
	InfiniteLoop:
		for {
			select {
			case <-fe.StopChannel:
				fe.SendUniDataSet()
				fe.SendBiDataSet()
				break InfiniteLoop
			case flow := <-fe.InputChannel:
				if fe.GetCurrentUniMessageSize() >= 300 {
					fe.SendUniDataSet()
				}
				if fe.GetCurrentBiMessageSize() >= 300 {
					fe.SendBiDataSet()
				}
				switch flow.NetworkType {
				case layers.LayerTypeIPv4:
					fe.AddIPv4Flow(flow)
				case layers.LayerTypeIPv6:
					klog.Info("IPv6 flow exporting not supported yet")
				}
			}
		}
		fmt.Println("IpfixFlowExporter stopped")
	}()

}

func (fe *IpfixFlowExporter) Stop() {
	fe.StopChannel <- true
}

func (fe *IpfixFlowExporter) GetCurrentUniMessageSize() int {
	return 20 + fe.uniDataSet.GetBuffer().Len()
}

func (fe *IpfixFlowExporter) GetCurrentBiMessageSize() int {
	return 20 + fe.biDataSet.GetBuffer().Len()
}

func (fe *IpfixFlowExporter) SendUniDataSet() {

	_, err := fe.exporter.SendSet(fe.uniDataSet)
	if err != nil {
		//TODO retry sending the data set after creating a new exporter
		fmt.Printf("Got error when sending record: %v\n", err)
		fe.refreshExporter()
		fe.refreshUniTemplate()
		fmt.Printf("Reset exporter")
		return
	}
	fmt.Println("sent data set")
	fe.FlowRecordsSent += uint64(len(fe.uniDataSet.GetRecords()))

	fe.uniDataSet.ResetSet()
	fe.uniDataSet.PrepareSet(entities.Data, fe.unidirectionalTemplateID)
}

func (fe *IpfixFlowExporter) SendBiDataSet() {

	_, err := fe.exporter.SendSet(fe.biDataSet)
	if err != nil {
		//TODO retry sending the data set after creating a new exporter
		fmt.Printf("Got error when sending record: %v\n", err)
		fe.refreshExporter()
		fe.refreshBiTemplate()
		fmt.Printf("Reset exporter")
		return
	}
	fmt.Println("sent data set")
	fe.FlowRecordsSent += uint64(len(fe.biDataSet.GetRecords()))

	fe.biDataSet.ResetSet()
	fe.biDataSet.PrepareSet(entities.Data, fe.bidirectionalTemplateID)
}

func (fe *IpfixFlowExporter) CloseExporter() {
	fe.exporter.CloseConnToCollector()
}

func (fe *IpfixFlowExporter) AddIPv4Flow(ipv4Flow flow.Flow) {

	if ipv4Flow.ReverseTotalPackets == 0 && ipv4Flow.Type == flow.Unknown {
		fe.UniElementBuffer[0] = entities.NewInfoElementWithValue(sourceIPv4AddressElement, ipv4Flow.NetworkSourceAddress.To4())
		fe.UniElementBuffer[1] = entities.NewInfoElementWithValue(destinationIPv4AddressElement, ipv4Flow.NetworkDestAddress.To4())
		fe.UniElementBuffer[2] = entities.NewInfoElementWithValue(sourceTransportPortElement, ipv4Flow.TransportSourcePort)
		fe.UniElementBuffer[3] = entities.NewInfoElementWithValue(destinationTransportPortElement, ipv4Flow.TransportDestPort)
		fe.UniElementBuffer[4] = entities.NewInfoElementWithValue(protocolIdentifierElement, uint8(ipv4Flow.Protocol))
		fe.UniElementBuffer[5] = entities.NewInfoElementWithValue(flowStartMillisecondsElement, ipv4Flow.FlowStartMilliseconds)
		fe.UniElementBuffer[6] = entities.NewInfoElementWithValue(flowEndMillisecondsElement, ipv4Flow.FlowEndMilliseconds)
		fe.UniElementBuffer[7] = entities.NewInfoElementWithValue(octetDeltaCountElement, ipv4Flow.TotalBytes)
		fe.UniElementBuffer[8] = entities.NewInfoElementWithValue(packetDeltaCountElement, ipv4Flow.TotalPackets)

		fe.uniDataSet.AddRecord(fe.UniElementBuffer, fe.unidirectionalTemplateID)
	} else {
		fe.BiElementBuffer[4] = entities.NewInfoElementWithValue(protocolIdentifierElement, uint8(ipv4Flow.Protocol))
		fe.BiElementBuffer[5] = entities.NewInfoElementWithValue(flowStartMillisecondsElement, ipv4Flow.FlowStartMilliseconds)
		fe.BiElementBuffer[6] = entities.NewInfoElementWithValue(flowEndMillisecondsElement, ipv4Flow.FlowEndMilliseconds)

		if ipv4Flow.Type == flow.Initiator || ipv4Flow.Type == flow.Unknown {
			fe.BiElementBuffer[0] = entities.NewInfoElementWithValue(sourceIPv4AddressElement, ipv4Flow.NetworkSourceAddress.To4())
			fe.BiElementBuffer[1] = entities.NewInfoElementWithValue(destinationIPv4AddressElement, ipv4Flow.NetworkDestAddress.To4())
			fe.BiElementBuffer[2] = entities.NewInfoElementWithValue(sourceTransportPortElement, ipv4Flow.TransportSourcePort)
			fe.BiElementBuffer[3] = entities.NewInfoElementWithValue(destinationTransportPortElement, ipv4Flow.TransportDestPort)

			fe.BiElementBuffer[7] = entities.NewInfoElementWithValue(initiatorOctetsElement, ipv4Flow.TotalBytes)
			fe.BiElementBuffer[8] = entities.NewInfoElementWithValue(initiatorPacketsElement, ipv4Flow.TotalPackets)
			fe.BiElementBuffer[9] = entities.NewInfoElementWithValue(responderOctetsElement, ipv4Flow.ReverseTotalBytes)
			fe.BiElementBuffer[10] = entities.NewInfoElementWithValue(responderPacketsElement, ipv4Flow.ReverseTotalPackets)
		} else {
			fe.BiElementBuffer[0] = entities.NewInfoElementWithValue(sourceIPv4AddressElement, ipv4Flow.NetworkDestAddress.To4())
			fe.BiElementBuffer[1] = entities.NewInfoElementWithValue(destinationIPv4AddressElement, ipv4Flow.NetworkSourceAddress.To4())
			fe.BiElementBuffer[2] = entities.NewInfoElementWithValue(sourceTransportPortElement, ipv4Flow.TransportDestPort)
			fe.BiElementBuffer[3] = entities.NewInfoElementWithValue(destinationTransportPortElement, ipv4Flow.TransportSourcePort)

			fe.BiElementBuffer[7] = entities.NewInfoElementWithValue(initiatorOctetsElement, ipv4Flow.ReverseTotalBytes)
			fe.BiElementBuffer[8] = entities.NewInfoElementWithValue(initiatorPacketsElement, ipv4Flow.ReverseTotalPackets)
			fe.BiElementBuffer[9] = entities.NewInfoElementWithValue(responderOctetsElement, ipv4Flow.TotalBytes)
			fe.BiElementBuffer[10] = entities.NewInfoElementWithValue(responderPacketsElement, ipv4Flow.TotalPackets)
		}

		fe.biDataSet.AddRecord(fe.BiElementBuffer, fe.bidirectionalTemplateID)
	}
}
