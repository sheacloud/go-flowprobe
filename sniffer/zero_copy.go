package sniffer

import (
	"fmt"
	"os"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/afpacket"
	"github.com/google/gopacket/pcap"
	"github.com/sirupsen/logrus"
)

// afpacketComputeSize computes the block_size and the num_blocks in such a way that the
// allocated mmap buffer is close to but smaller than target_size_mb.
// The restriction is that the block_size must be divisible by both the
// frame size and page size.
func afpacketComputeSize(targetSizeMb int, snaplen int, pageSize int) (
	frameSize int, blockSize int, numBlocks int, err error) {

	if snaplen < pageSize {
		frameSize = pageSize / (pageSize / snaplen)
	} else {
		frameSize = (snaplen/pageSize + 1) * pageSize
	}

	// 128 is the default from the gopacket library so just use that
	blockSize = frameSize * 128
	numBlocks = (targetSizeMb * 1024 * 1024) / blockSize

	if numBlocks == 0 {
		return 0, 0, 0, fmt.Errorf("Interface buffersize is too small")
	}

	return frameSize, blockSize, numBlocks, nil
}

// ZeroCopyFlowSniffer reads from a zero-copy packet stream (like afpacket) and routes it to a FlowTracker based on it's keys
type ZeroCopyFlowSniffer struct {
	PacketSource     gopacket.ZeroCopyPacketDataSource
	JobChannel       chan<- *PacketJob
	StopChannel      chan bool
	Iface            string
	SnifferNumber    uint16
	SnifferWaitGroup *sync.WaitGroup
}

// Start the flow router
func (fr *ZeroCopyFlowSniffer) Start() {

	go func() {

		logrus.WithFields(logrus.Fields{
			"iface": fr.Iface,
		}).Info("Starting ZeroCopy Flow Sniffer")

	InfiniteLoop:
		for {
			select {
			case <-fr.StopChannel:
				break InfiniteLoop
			default:
				// TODO don't block forever waiting for a packet, or else we'll never get the channel stop message if no packets are arriving. OptPollTimeout might be the solution

				//Subsequent calls to ZeroCopyReadPacketData will invalidate data, potentially overriding it depending on buffer size
				data, ci, err := fr.PacketSource.ZeroCopyReadPacketData()
				if err != nil {
					logrus.WithFields(logrus.Fields{
						"error": err,
					}).Error("Error reading from zero copy packet source")
				} else {

					job := PacketJob{
						data:        data,
						captureInfo: ci,
					}

					fr.JobChannel <- &job

				}
			}
		}
		logrus.WithFields(logrus.Fields{
			"iface": fr.Iface,
		}).Info("Stopped ZeroCopy Flow Sniffer")
		fr.SnifferWaitGroup.Done()
	}()
}

// Stop the flow router
func (fr *ZeroCopyFlowSniffer) Stop() {
	fr.StopChannel <- true
}

func ZeroCopyPacketDataSourceFromDevice(device string, fanoutID uint16) gopacket.ZeroCopyPacketDataSource {
	szFrame, szBlock, numBlocks, err := afpacketComputeSize(8, 65535, os.Getpagesize())
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"error": err,
		}).Fatal("Error computing AF packet sizes")
	}

	tPacket, err := afpacket.NewTPacket(
		afpacket.OptInterface(device),
		afpacket.OptFrameSize(szFrame),
		afpacket.OptBlockSize(szBlock),
		afpacket.OptNumBlocks(numBlocks),
		afpacket.OptAddVLANHeader(false),
		afpacket.OptPollTimeout(pcap.BlockForever),
		afpacket.SocketRaw,
		afpacket.TPacketVersion3,
	)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"iface": device,
			"error": err,
		}).Fatal("Error getting AFPacket source")
	}

	tPacket.SetFanout(afpacket.FanoutHash, fanoutID)

	source := gopacket.ZeroCopyPacketDataSource(tPacket)

	return source
}

// NewZeroCopyFlowSniffer instantiates a ZeroCopyFlowSniffer
func NewZeroCopyFlowSniffer(source gopacket.ZeroCopyPacketDataSource, jobChannel chan *PacketJob, snifferWaitGroup *sync.WaitGroup, snifferNumber uint16, iface string) *ZeroCopyFlowSniffer {
	return &ZeroCopyFlowSniffer{
		PacketSource:     source,
		SnifferWaitGroup: snifferWaitGroup,
		StopChannel:      make(chan bool),
		JobChannel:       jobChannel,
		SnifferNumber:    snifferNumber,
		Iface:            iface,
	}
}
