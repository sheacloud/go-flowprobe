package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sheacloud/go-flowprobe/exporter"
	"github.com/sheacloud/go-flowprobe/flow"
	"github.com/sheacloud/go-flowprobe/sniffer"
	"github.com/sheacloud/go-flowprobe/tracker"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"k8s.io/klog"

	_ "net/http/pprof"
)

var (
	ipfixExporter     *exporter.IpfixFlowExporter
	flowstoreExporter *exporter.FlowstoreFlowExporter
	sniffers          []sniffer.FlowSniffer
)

var (
	ipfixViper      = viper.New()
	flowstoreViper  = viper.New()
	snifferViper    = viper.New()
	prometheusViper = viper.New()
	logViper        = viper.New()

	logLevel  string
	logCaller bool

	rootCmd = &cobra.Command{
		Use:   "go-flowprobe",
		Short: "Flow probe & exporter",
		Run: func(cmd *cobra.Command, args []string) {
			run()
		},
	}
)

func initIpfixOptions() {
	ipfixViper.SetEnvPrefix("ipfix")
	ipfixViper.AutomaticEnv()

	ipfixViper.BindEnv("enable")
	ipfixViper.SetDefault("enable", false)

	ipfixViper.BindEnv("target")
	ipfixViper.SetDefault("target", "127.0.0.1")

	ipfixViper.BindEnv("port")
	ipfixViper.SetDefault("port", "4739")

	ipfixViper.BindEnv("max_record_size")
	ipfixViper.SetDefault("max_record_size", 1000)
}

func initFlowstoreOptions() {
	flowstoreViper.SetEnvPrefix("flowstore")
	flowstoreViper.AutomaticEnv()

	flowstoreViper.BindEnv("enable")
	flowstoreViper.SetDefault("enable", true)

	flowstoreViper.BindEnv("target")
	flowstoreViper.SetDefault("target", "127.0.0.1")

	flowstoreViper.BindEnv("port")
	flowstoreViper.SetDefault("port", "8080")

	flowstoreViper.BindEnv("protocol")
	flowstoreViper.SetDefault("protocol", "http")

	flowstoreViper.BindEnv("max_flows_per_upload")
	flowstoreViper.SetDefault("max_flows_per_upload", 100)
}

func initSnifferOptions() {
	snifferViper.SetEnvPrefix("sniffer")
	snifferViper.AutomaticEnv()

	snifferViper.BindEnv("ifaces")
	snifferViper.SetDefault("ifaces", "eno1")

	snifferViper.BindEnv("per_iface")
	snifferViper.SetDefault("per_iface", 1)

	snifferViper.BindEnv("zero_copy")
	snifferViper.SetDefault("zero_copy", true)

	snifferViper.BindEnv("flow_timeout")
	snifferViper.SetDefault("flow_timeout", 600)

	snifferViper.BindEnv("workers")
	snifferViper.SetDefault("workers", 8)
}

func initPrometheusOptions() {
	prometheusViper.SetEnvPrefix("prometheus")
	prometheusViper.AutomaticEnv()

	prometheusViper.BindEnv("addr")
	prometheusViper.SetDefault("addr", "0.0.0.0")

	prometheusViper.BindEnv("port")
	prometheusViper.SetDefault("port", "9091")

	prometheusViper.BindEnv("path")
	prometheusViper.SetDefault("path", "/metrics")
}

func initLogOptions() {
	logViper.SetEnvPrefix("log")
	logViper.AutomaticEnv()

	logViper.BindEnv("level")
	logViper.SetDefault("level", "info")

	logViper.BindEnv("caller")
	logViper.SetDefault("caller", false)
}

func initLogging() {
	// disable klog logging to mute underlying go-ipfix library
	klog.InitFlags(nil)
	flag.Set("logtostderr", "false")
	flag.Set("alsologtostderr", "false")
	klog.SetOutput(ioutil.Discard)

	logrus.SetReportCaller(logViper.GetBool("caller"))
	logrus.SetOutput(os.Stdout)
	logrus.SetFormatter(&logrus.TextFormatter{
		FullTimestamp: true,
	})

	switch strings.ToLower(logViper.GetString("level")) {
	case "panic":
		logrus.SetLevel(logrus.PanicLevel)
	case "fatal":
		logrus.SetLevel(logrus.FatalLevel)
	case "error":
		logrus.SetLevel(logrus.ErrorLevel)
	case "warning":
		logrus.SetLevel(logrus.WarnLevel)
	case "info":
		logrus.SetLevel(logrus.InfoLevel)
	case "debug":
		logrus.SetLevel(logrus.DebugLevel)
	case "trace":
		logrus.SetLevel(logrus.TraceLevel)
	default:
		fmt.Printf("Invalid log level %s - valid options are trace, debug, info, warning, error, fatal, panic\n", logLevel)
		os.Exit(1)
	}
}

func init() {
	initIpfixOptions()
	initFlowstoreOptions()
	initSnifferOptions()
	initPrometheusOptions()
	initLogOptions()

	initLogging()
}

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
	logrus.WithFields(logrus.Fields{
		"addr": prometheusViper.GetString("addr"),
		"port": prometheusViper.GetString("port"),
		"path": prometheusViper.GetString("path"),
	}).Info("Starting Prometheus...")

	http.Handle(prometheusViper.GetString("path"), promhttp.Handler())
	logrus.Fatal(http.ListenAndServe(fmt.Sprintf(":%v", prometheusViper.GetString("port")), nil))
}

func run() {

	enableIpfix := ipfixViper.GetBool("enable")
	enableFlowstore := flowstoreViper.GetBool("enable")

	ifaces := strings.Split(snifferViper.GetString("ifaces"), ",")
	zeroCopy := snifferViper.GetBool("zero_copy")

	flowChannel := make(chan flow.Flow)
	jobChannel := make(chan *sniffer.PacketJob)

	var jobWaitGroup sync.WaitGroup
	var snifferWaitGroup sync.WaitGroup
	var exporterWaitGroup sync.WaitGroup

	flowTracker := tracker.NewFlowTracker(flowChannel, 1, snifferViper.GetInt("flow_timeout"))
	flowTracker.Start()

	for i := 0; i < snifferViper.GetInt("workers"); i++ {
		go func(i int) {
			logrus.WithFields(logrus.Fields{
				"id": i,
			}).Info("Started Packet Processing Worker")
			jobWaitGroup.Add(1)
			sniffer.PacketProcessor(flowTracker, jobChannel, &jobWaitGroup)
		}(i)
	}

	sniffers = make([]sniffer.FlowSniffer, 0)
	for i, iface := range ifaces {
		if zeroCopy {
			for j := 0; j < snifferViper.GetInt("per_iface"); j++ {
				source := sniffer.ZeroCopyPacketDataSourceFromDevice(iface, uint16(j))
				sniffers = append(sniffers, sniffer.NewZeroCopyFlowSniffer(source, jobChannel, &snifferWaitGroup, uint16(j), iface))
			}
		} else {
			sniffers = append(sniffers, sniffer.NewPCAPFlowSniffer(iface, jobChannel, &snifferWaitGroup, uint16(i)))
		}
	}

	if enableIpfix {
		ipfixTarget := ipfixViper.GetString("target")
		ipfixPortString := ipfixViper.GetString("port")

		ipfixPort, err := strconv.Atoi(ipfixPortString)
		if err != nil {
			panic(err)
		}

		ipfixExporter = exporter.NewIpfixFlowExporter(ipfixTarget, ipfixPort, ipfixViper.GetInt("max_record_size"), flowChannel, &exporterWaitGroup)
		exporterWaitGroup.Add(1)
		ipfixExporter.Start()
	} else if enableFlowstore {
		flowstoreTarget := flowstoreViper.GetString("target")
		flowstorePort := flowstoreViper.GetInt("port")
		flowstoreProtocol := flowstoreViper.GetString("protocol")
		maxFlowsPerUpload := flowstoreViper.GetInt("max_flows_per_upload")

		flowstoreExporter = exporter.NewFlowstoreFlowExporter(flowstoreTarget, flowstorePort, flowstoreProtocol, maxFlowsPerUpload, flowChannel, &exporterWaitGroup)
		exporterWaitGroup.Add(1)
		flowstoreExporter.Start()
	}

	for _, sniffer := range sniffers {
		snifferWaitGroup.Add(1)
		sniffer.Start()
	}

	stopCh := make(chan struct{})
	go signalHandler(stopCh)

	<-stopCh
	for _, sniffer := range sniffers {
		sniffer.Stop()
	}
	// wait for sniffers to finish so we can safely close jobs channel
	snifferWaitGroup.Wait()
	close(jobChannel)

	// wait for jobs to finish so we can stop the exporter and tracker
	jobWaitGroup.Wait()

	if enableIpfix {
		ipfixExporter.Stop()
	} else if enableFlowstore {
		flowstoreExporter.Stop()
	}

	exporterWaitGroup.Wait()

	os.Exit(0)
}

func main() {
	go httpServer()

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
