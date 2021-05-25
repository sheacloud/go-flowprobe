package exporter

import (
	"fmt"
	"net"
	"sync"

	"github.com/cenkalti/backoff/v4"
	"github.com/google/gopacket/layers"
	"github.com/sheacloud/go-flowprobe/flow"
	"github.com/sirupsen/logrus"
	"github.com/vmware/go-ipfix/pkg/entities"
	"github.com/vmware/go-ipfix/pkg/exporter"
	"github.com/vmware/go-ipfix/pkg/registry"
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
	maxRecordSize            int
	waitGroup                *sync.WaitGroup
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

func NewIpfixFlowExporter(collectorTarget string, collectorPort, maxRecordSize int, flowInputChannel chan flow.Flow, waitGroup *sync.WaitGroup) *IpfixFlowExporter {
	flowExporter := &IpfixFlowExporter{
		UniElementBuffer: make([]*entities.InfoElementWithValue, 9),
		BiElementBuffer:  make([]*entities.InfoElementWithValue, 11),
		StopChannel:      make(chan bool),
		InputChannel:     flowInputChannel,
		collectorTarget:  collectorTarget,
		collectorPort:    collectorPort,
		maxRecordSize:    maxRecordSize,
		waitGroup:        waitGroup,
	}

	flowExporter.reconnectExporter()

	return flowExporter
}

func (fe *IpfixFlowExporter) reconnectExporter() {
	ip, _ := fetchAddrFromName(fe.collectorTarget)

	var exporterProcess *exporter.ExportingProcess

	operation := func() error {
		var err error
		logrus.WithFields(logrus.Fields{
			"ip": ip,
		}).Info("Reconnecting IPFIX Exporter")
		exporterProcess, err = exporter.InitExportingProcess(exporter.ExporterInput{
			CollectorAddress:    fmt.Sprintf("%v:%v", ip, fe.collectorPort),
			CollectorProtocol:   "tcp",
			ObservationDomainID: 1,
			TempRefTimeout:      0,
		})
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"ip":    ip,
				"error": err,
			}).Error("Error creating exporting process")
		}

		return err
	}

	err := backoff.Retry(operation, backoff.NewExponentialBackOff())
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"error": err,
		}).Panic("Failed to create exporting process")
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

func (fe *IpfixFlowExporter) refreshUniTemplate() error {
	templateElementNames := []string{"sourceIPv4Address", "destinationIPv4Address", "sourceTransportPort", "destinationTransportPort", "protocolIdentifier", "flowStartMilliseconds", "flowEndMilliseconds", "octetDeltaCount", "packetDeltaCount"}

	templateSet := entities.NewSet(false)
	templateSet.PrepareSet(entities.Template, fe.unidirectionalTemplateID)
	elements := make([]*entities.InfoElementWithValue, 0)

	for _, elementName := range templateElementNames {
		element, err := registry.GetInfoElement(elementName, registry.IANAEnterpriseID)
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"element_name": elementName,
			}).Panic("Could not find matching registry element")
		}
		ie := entities.NewInfoElementWithValue(element, nil)
		elements = append(elements, ie)
	}

	templateSet.AddRecord(elements, fe.unidirectionalTemplateID)

	_, err := fe.exporter.SendSet(templateSet)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"error": err,
		}).Error("Error sending Uni Template record set")
		return err
	}

	return nil
}

func (fe *IpfixFlowExporter) refreshBiTemplate() error {
	templateElementNames := []string{"sourceIPv4Address", "destinationIPv4Address", "sourceTransportPort", "destinationTransportPort", "protocolIdentifier", "flowStartMilliseconds", "flowEndMilliseconds", "initiatorOctets", "initiatorPackets", "responderOctets", "responderPackets"}

	templateSet := entities.NewSet(false)
	templateSet.PrepareSet(entities.Template, fe.bidirectionalTemplateID)
	elements := make([]*entities.InfoElementWithValue, 0)

	for _, elementName := range templateElementNames {
		element, err := registry.GetInfoElement(elementName, registry.IANAEnterpriseID)
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"element_name": elementName,
			}).Panic("Could not find matching registry element")
		}
		ie := entities.NewInfoElementWithValue(element, nil)
		elements = append(elements, ie)
	}

	templateSet.AddRecord(elements, fe.bidirectionalTemplateID)

	_, err := fe.exporter.SendSet(templateSet)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"error": err,
		}).Error("Error sending Uni Template record set")
		return err
	}

	return nil
}

func (fe *IpfixFlowExporter) Start() error {
	err := fe.refreshUniTemplate()
	if err != nil {
		return err
	}

	err = fe.refreshBiTemplate()
	if err != nil {
		return err
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
	initiatorOctetsElement, _ = registry.GetInfoElement("initiatorOctets", registry.IANAEnterpriseID)
	initiatorPacketsElement, _ = registry.GetInfoElement("initiatorPackets", registry.IANAEnterpriseID)
	responderOctetsElement, _ = registry.GetInfoElement("responderOctets", registry.IANAEnterpriseID)
	responderPacketsElement, _ = registry.GetInfoElement("responderPackets", registry.IANAEnterpriseID)

	go func() {
		logrus.WithFields(logrus.Fields{
			"target": fe.collectorTarget,
			"port":   fe.collectorPort,
		}).Info("Starting IPFIX Exporter")

	InfiniteLoop:
		for {
			select {
			case <-fe.StopChannel:
				fe.SendUniDataSet()
				fe.SendBiDataSet()
				break InfiniteLoop
			case flow := <-fe.InputChannel:
				if fe.GetCurrentUniMessageSize() >= fe.maxRecordSize {
					logrus.WithFields(logrus.Fields{
						"current_record_size": fe.GetCurrentUniMessageSize(),
						"max_record_size":     fe.maxRecordSize,
					}).Info("Exporting unidirectional flows due to max record size reached")
					fe.SendUniDataSet()
				}
				if fe.GetCurrentBiMessageSize() >= fe.maxRecordSize {
					logrus.WithFields(logrus.Fields{
						"current_record_size": fe.GetCurrentBiMessageSize(),
						"max_record_size":     fe.maxRecordSize,
					}).Info("Exporting bidirectional flows due to max record size reached")
					fe.SendBiDataSet()
				}
				switch flow.NetworkType {
				case layers.LayerTypeIPv4:
					fe.AddIPv4Flow(flow)
				case layers.LayerTypeIPv6:
					logrus.Warning("IPv6 Flows not supported")
				}
			}
		}
		logrus.Info("Stopped IPFIX Exporter")
		fe.waitGroup.Done()
	}()

	return nil
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

func (fe *IpfixFlowExporter) SendUniDataSet() error {

	reconnectFirst := false

	operation := func() error {
		if reconnectFirst {
			fe.reconnectExporter()
			err := fe.refreshUniTemplate()
			if err != nil {
				return err
			}
			err = fe.refreshBiTemplate()
			if err != nil {
				return err
			}
		}
		_, err := fe.exporter.SendSet(fe.uniDataSet)

		// if the send fails, error out so the backoff will retry
		if err != nil {
			reconnectFirst = true
			return err
		}

		logrus.WithFields(logrus.Fields{
			"num_flows": fe.uniDataSet.GetNumberOfRecords(),
		}).Info("Exported unidirectional flows")

		return nil
	}

	err := backoff.Retry(operation, backoff.NewExponentialBackOff())
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"error": err,
		}).Error("Error sending uni data set")
		return err
	}

	fe.FlowRecordsSent += uint64(fe.uniDataSet.GetNumberOfRecords())

	fe.uniDataSet.ResetSet()
	fe.uniDataSet.PrepareSet(entities.Data, fe.unidirectionalTemplateID)

	return nil
}

func (fe *IpfixFlowExporter) SendBiDataSet() error {

	reconnectFirst := false

	operation := func() error {
		if reconnectFirst {
			fe.reconnectExporter()
			err := fe.refreshUniTemplate()
			if err != nil {
				return err
			}
			err = fe.refreshBiTemplate()
			if err != nil {
				return err
			}
		}
		_, err := fe.exporter.SendSet(fe.biDataSet)

		// if the send fails, error out so the backoff will retry
		if err != nil {
			reconnectFirst = true
			return err
		}

		logrus.WithFields(logrus.Fields{
			"num_flows": fe.biDataSet.GetNumberOfRecords(),
		}).Info("Exported bidirectional flows")

		return nil
	}

	err := backoff.Retry(operation, backoff.NewExponentialBackOff())
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"error": err,
		}).Error("Error sending bi data set")
		return err
	}

	fe.FlowRecordsSent += uint64(fe.biDataSet.GetNumberOfRecords())

	fe.biDataSet.ResetSet()
	fe.biDataSet.PrepareSet(entities.Data, fe.bidirectionalTemplateID)

	return nil
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
