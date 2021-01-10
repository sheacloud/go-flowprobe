package flowprobe

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"

	"github.com/vmware/go-ipfix/pkg/entities"
	"github.com/vmware/go-ipfix/pkg/exporter"
	"github.com/vmware/go-ipfix/pkg/registry"
)

func init() {
	registry.LoadRegistry()
}

type FlowExporter struct {
	exporter         *exporter.ExportingProcess
	dataSet          entities.Set
	templateID       uint16
	FlowRecordsSent  uint64
	RecordBuffer     bytes.Buffer
	ElementBuffer    []*entities.InfoElementWithValue
	StopChannel      chan bool
	IPv4InputChannel chan IPv4Flow
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

func NewFlowExporter(collectorIp net.IP, collectorPort int, ipv4InputChannel chan IPv4Flow) *FlowExporter {

	udpAddr := net.UDPAddr{
		IP:   collectorIp,
		Port: collectorPort,
	}
	exporter, _ := exporter.InitExportingProcess(exporter.ExporterInput{
		CollectorAddr:       &udpAddr,
		ObservationDomainID: 1,
		TempRefTimeout:      1,
	})
	templateID := exporter.NewTemplateID()
	dataSet := entities.NewSet(entities.Data, templateID, false)

	return &FlowExporter{
		exporter:         exporter,
		dataSet:          dataSet,
		RecordBuffer:     bytes.Buffer{},
		ElementBuffer:    make([]*entities.InfoElementWithValue, 9),
		templateID:       templateID,
		StopChannel:      make(chan bool),
		IPv4InputChannel: ipv4InputChannel,
	}
}

func (fe *FlowExporter) Start() {
	templateElementNames := []string{"sourceIPv4Address", "destinationIPv4Address", "sourceTransportPort", "destinationTransportPort", "protocolIdentifier", "flowStartMilliseconds", "flowEndMilliseconds", "octetDeltaCount", "packetDeltaCount"}

	// Create template record with two fields
	templateSet := entities.NewSet(entities.Template, fe.templateID, false)
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

	templateSet.AddRecord(elements, fe.templateID)

	_, err := fe.exporter.SendSet(templateSet)
	if err != nil {
		fmt.Printf("Got error when sending record: %v\n", err)
		return
	}

	sourceIPv4AddressElement, _ = registry.GetInfoElement("sourceIPv4Address", registry.IANAEnterpriseID)
	destinationIPv4AddressElement, _ = registry.GetInfoElement("destinationIPv4Address", registry.IANAEnterpriseID)
	sourceTransportPortElement, _ = registry.GetInfoElement("sourceTransportPort", registry.IANAEnterpriseID)
	destinationTransportPortElement, _ = registry.GetInfoElement("destinationTransportPort", registry.IANAEnterpriseID)
	protocolIdentifierElement, _ = registry.GetInfoElement("protocolIdentifier", registry.IANAEnterpriseID)
	flowStartMillisecondsElement, _ = registry.GetInfoElement("flowStartMilliseconds", registry.IANAEnterpriseID)
	flowEndMillisecondsElement, _ = registry.GetInfoElement("flowEndMilliseconds", registry.IANAEnterpriseID)
	octetDeltaCountElement, _ = registry.GetInfoElement("octetDeltaCount", registry.IANAEnterpriseID)
	packetDeltaCountElement, _ = registry.GetInfoElement("packetDeltaCount", registry.IANAEnterpriseID)

	go func() {
	InfiniteLoop:
		for {
			select {
			case <-fe.StopChannel:
				fe.SendDataSet()
				break InfiniteLoop
			case flow := <-fe.IPv4InputChannel:
				if fe.GetCurrentMessageSize() >= 300 {
					fe.SendDataSet()
				}
				fe.AddIPv4Flow(flow)
			}
		}
		fmt.Println("FlowExporter stopped")
	}()

}

func (fe *FlowExporter) Stop() {
	fe.StopChannel <- true
}

func (fe *FlowExporter) GetCurrentMessageSize() int {
	return 20 + int(fe.dataSet.GetBuffLen())
}

func (fe *FlowExporter) SendDataSet() {

	_, err := fe.exporter.SendSet(fe.dataSet)
	if err != nil {
		fmt.Printf("Got error when sending record: %v\n", err)
		return
	}
	fmt.Println("sent data set")
	fe.FlowRecordsSent += uint64(len(fe.dataSet.GetRecords()))

	fe.dataSet = entities.NewSet(entities.Data, fe.templateID, false)
}

func (fe *FlowExporter) CloseExporter() {
	fe.exporter.CloseConnToCollector()
}

func (fe *FlowExporter) AddIPv4Flow(flow IPv4Flow) {
	srcIPBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(srcIPBytes, flow.SourceIPv4Address)
	srcIP := net.IP(srcIPBytes)

	dstIPBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(dstIPBytes, flow.DestinationIPv4Address)
	dstIP := net.IP(dstIPBytes)

	fe.ElementBuffer[0] = entities.NewInfoElementWithValue(sourceIPv4AddressElement, srcIP)
	fe.ElementBuffer[1] = entities.NewInfoElementWithValue(destinationIPv4AddressElement, dstIP)
	fe.ElementBuffer[2] = entities.NewInfoElementWithValue(sourceTransportPortElement, flow.SourcePort)
	fe.ElementBuffer[3] = entities.NewInfoElementWithValue(destinationTransportPortElement, flow.DestinationPort)
	fe.ElementBuffer[4] = entities.NewInfoElementWithValue(protocolIdentifierElement, flow.Protocol)
	fe.ElementBuffer[5] = entities.NewInfoElementWithValue(flowStartMillisecondsElement, flow.FlowStartMilliseconds)
	fe.ElementBuffer[6] = entities.NewInfoElementWithValue(flowEndMillisecondsElement, flow.FlowEndMilliseconds)
	fe.ElementBuffer[7] = entities.NewInfoElementWithValue(octetDeltaCountElement, flow.TotalBytes)
	fe.ElementBuffer[8] = entities.NewInfoElementWithValue(packetDeltaCountElement, flow.TotalPackets)

	fe.dataSet.AddRecord(fe.ElementBuffer, fe.templateID)

	// fmt.Println(flow.String())
}
