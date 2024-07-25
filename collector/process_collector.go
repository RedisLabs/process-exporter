package collector

import (
	"fmt"
	"log"
	"strings"
	"time"

	common "github.com/ncabatoff/process-exporter"
	"github.com/ncabatoff/process-exporter/proc"
	"github.com/prometheus/client_golang/prometheus"
)

type (
	scrapeRequest struct {
		results chan<- prometheus.Metric
		done    chan struct{}
	}

	ProcessCollectorOption struct {
		ProcFSPath        string
		Children          bool
		Threads           bool
		GatherSMaps       bool
		Namer             common.MatchNamer
		Recheck           bool
		RecheckTimeLimit  time.Duration
		Debug             bool
		RemoveEmptyGroups bool
		CustomLabel       string
	}

	NamedProcessCollector struct {
		scrapeChan chan scrapeRequest
		*proc.Grouper
		threads              bool
		smaps                bool
		source               proc.Source
		scrapeErrors         int
		scrapeProcReadErrors int
		scrapePartialErrors  int
		debug                bool
		metricDiscriptions   *MetricDiscriptions
	}

	MetricDiscriptions struct {
		cpuSecsDesc               *prometheus.Desc
		numprocsDesc              *prometheus.Desc
		readBytesDesc             *prometheus.Desc
		writeBytesDesc            *prometheus.Desc
		membytesDesc              *prometheus.Desc
		openFDsDesc               *prometheus.Desc
		worstFDRatioDesc          *prometheus.Desc
		startTimeDesc             *prometheus.Desc
		majorPageFaultsDesc       *prometheus.Desc
		minorPageFaultsDesc       *prometheus.Desc
		contextSwitchesDesc       *prometheus.Desc
		numThreadsDesc            *prometheus.Desc
		statesDesc                *prometheus.Desc
		scrapeErrorsDesc          *prometheus.Desc
		scrapeProcReadErrorsDesc  *prometheus.Desc
		scrapePartialErrorsDesc   *prometheus.Desc
		threadWchanDesc           *prometheus.Desc
		threadCountDesc           *prometheus.Desc
		threadCpuSecsDesc         *prometheus.Desc
		threadIoBytesDesc         *prometheus.Desc
		threadMajorPageFaultsDesc *prometheus.Desc
		threadMinorPageFaultsDesc *prometheus.Desc
		threadContextSwitchesDesc *prometheus.Desc
	}
)

func NewProcessCollector(options ProcessCollectorOption) (*NamedProcessCollector, error) {
	fs, err := proc.NewFS(options.ProcFSPath, options.Debug)
	if err != nil {
		return nil, err
	}

	additional_lables := []string{}
	customLabelCommand := ""
	if len(options.CustomLabel) > 0 {
		splitCustomLabel := strings.SplitN(options.CustomLabel, ":", 2)
		if len(splitCustomLabel) != 2 {
			return nil, fmt.Errorf("bad customLabel %q", options.CustomLabel)
		}
		additional_lables = append(additional_lables, splitCustomLabel[0])
		customLabelCommand = splitCustomLabel[1]
	}

	metricDiscriptions := &MetricDiscriptions{
		numprocsDesc: prometheus.NewDesc(
			"namedprocess_namegroup_num_procs",
			"number of processes in this group",
			append([]string{"groupname"}, additional_lables...),
			nil),
		cpuSecsDesc: prometheus.NewDesc(
			"namedprocess_namegroup_cpu_seconds_total",
			"Cpu user usage in seconds",
			append([]string{"groupname", "mode"}, additional_lables...),
			nil),
		readBytesDesc: prometheus.NewDesc(
			"namedprocess_namegroup_read_bytes_total",
			"number of bytes read by this group",
			append([]string{"groupname"}, additional_lables...),
			nil),
		writeBytesDesc: prometheus.NewDesc(
			"namedprocess_namegroup_write_bytes_total",
			"number of bytes written by this group",
			append([]string{"groupname"}, additional_lables...),
			nil),
		majorPageFaultsDesc: prometheus.NewDesc(
			"namedprocess_namegroup_major_page_faults_total",
			"Major page faults",
			append([]string{"groupname"}, additional_lables...),
			nil),
		minorPageFaultsDesc: prometheus.NewDesc(
			"namedprocess_namegroup_minor_page_faults_total",
			"Minor page faults",
			append([]string{"groupname"}, additional_lables...),
			nil),
		contextSwitchesDesc: prometheus.NewDesc(
			"namedprocess_namegroup_context_switches_total",
			"Context switches",
			append([]string{"groupname", "ctxswitchtype"}, additional_lables...),
			nil),
		membytesDesc: prometheus.NewDesc(
			"namedprocess_namegroup_memory_bytes",
			"number of bytes of memory in use",
			append([]string{"groupname", "memtype"}, additional_lables...),
			nil),
		openFDsDesc: prometheus.NewDesc(
			"namedprocess_namegroup_open_filedesc",
			"number of open file descriptors for this group",
			append([]string{"groupname"}, additional_lables...),
			nil),
		worstFDRatioDesc: prometheus.NewDesc(
			"namedprocess_namegroup_worst_fd_ratio",
			"the worst (closest to 1) ratio between open fds and max fds among all procs in this group",
			append([]string{"groupname"}, additional_lables...),
			nil),
		startTimeDesc: prometheus.NewDesc(
			"namedprocess_namegroup_oldest_start_time_seconds",
			"start time in seconds since 1970/01/01 of oldest process in group",
			append([]string{"groupname"}, additional_lables...),
			nil),
		numThreadsDesc: prometheus.NewDesc(
			"namedprocess_namegroup_num_threads",
			"Number of threads",
			append([]string{"groupname"}, additional_lables...),
			nil),
		statesDesc: prometheus.NewDesc(
			"namedprocess_namegroup_states",
			"Number of processes in states Running, Sleeping, Waiting, Zombie, or Other",
			append([]string{"groupname", "state"}, additional_lables...),
			nil),
		scrapeErrorsDesc: prometheus.NewDesc(
			"namedprocess_scrape_errors",
			"general scrape errors: no proc metrics collected during a cycle",
			nil,
			nil),
		scrapeProcReadErrorsDesc: prometheus.NewDesc(
			"namedprocess_scrape_procread_errors",
			"incremented each time a proc's metrics collection fails",
			nil,
			nil),
		scrapePartialErrorsDesc: prometheus.NewDesc(
			"namedprocess_scrape_partial_errors",
			"incremented each time a tracked proc's metrics collection fails partially, e.g. unreadable I/O stats",
			nil,
			nil),
		threadWchanDesc: prometheus.NewDesc(
			"namedprocess_namegroup_threads_wchan",
			"Number of threads in this group waiting on each wchan",
			append([]string{"groupname", "wchan"}, additional_lables...),
			nil),
		threadCountDesc: prometheus.NewDesc(
			"namedprocess_namegroup_thread_count",
			"Number of threads in this group with same threadname",
			append([]string{"groupname", "threadname"}, additional_lables...),
			nil),
		threadCpuSecsDesc: prometheus.NewDesc(
			"namedprocess_namegroup_thread_cpu_seconds_total",
			"Cpu user/system usage in seconds",
			append([]string{"groupname", "threadname", "mode"}, additional_lables...),
			nil),
		threadIoBytesDesc: prometheus.NewDesc(
			"namedprocess_namegroup_thread_io_bytes_total",
			"number of bytes read/written by these threads",
			append([]string{"groupname", "threadname", "iomode"}, additional_lables...),
			nil),
		threadMajorPageFaultsDesc: prometheus.NewDesc(
			"namedprocess_namegroup_thread_major_page_faults_total",
			"Major page faults for these threads",
			append([]string{"groupname", "threadname"}, additional_lables...),
			nil),
		threadMinorPageFaultsDesc: prometheus.NewDesc(
			"namedprocess_namegroup_thread_minor_page_faults_total",
			"Minor page faults for these threads",
			append([]string{"groupname", "threadname"}, additional_lables...),
			nil),
		threadContextSwitchesDesc: prometheus.NewDesc(
			"namedprocess_namegroup_thread_context_switches_total",
			"Context switches for these threads",
			append([]string{"groupname", "threadname", "ctxswitchtype"}, additional_lables...),
			nil),
	}

	fs.GatherSMaps = options.GatherSMaps
	p := &NamedProcessCollector{
		scrapeChan:         make(chan scrapeRequest),
		Grouper:            proc.NewGrouper(options.Namer, options.Children, options.Threads, options.Recheck, options.RecheckTimeLimit, options.Debug, options.RemoveEmptyGroups, customLabelCommand),
		source:             fs,
		threads:            options.Threads,
		smaps:              options.GatherSMaps,
		debug:              options.Debug,
		metricDiscriptions: metricDiscriptions,
	}

	colErrs, _, err := p.Update(p.source.AllProcs())
	if err != nil {
		if options.Debug {
			log.Print(err)
		}
		return nil, err
	}
	p.scrapePartialErrors += colErrs.Partial
	p.scrapeProcReadErrors += colErrs.Read

	go p.start()

	return p, nil
}

// Describe implements prometheus.Collector.
func (p *NamedProcessCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- p.metricDiscriptions.cpuSecsDesc
	ch <- p.metricDiscriptions.numprocsDesc
	ch <- p.metricDiscriptions.readBytesDesc
	ch <- p.metricDiscriptions.writeBytesDesc
	ch <- p.metricDiscriptions.membytesDesc
	ch <- p.metricDiscriptions.openFDsDesc
	ch <- p.metricDiscriptions.worstFDRatioDesc
	ch <- p.metricDiscriptions.startTimeDesc
	ch <- p.metricDiscriptions.majorPageFaultsDesc
	ch <- p.metricDiscriptions.minorPageFaultsDesc
	ch <- p.metricDiscriptions.contextSwitchesDesc
	ch <- p.metricDiscriptions.numThreadsDesc
	ch <- p.metricDiscriptions.statesDesc
	ch <- p.metricDiscriptions.scrapeErrorsDesc
	ch <- p.metricDiscriptions.scrapeProcReadErrorsDesc
	ch <- p.metricDiscriptions.scrapePartialErrorsDesc
	ch <- p.metricDiscriptions.threadWchanDesc
	ch <- p.metricDiscriptions.threadCountDesc
	ch <- p.metricDiscriptions.threadCpuSecsDesc
	ch <- p.metricDiscriptions.threadIoBytesDesc
	ch <- p.metricDiscriptions.threadMajorPageFaultsDesc
	ch <- p.metricDiscriptions.threadMinorPageFaultsDesc
	ch <- p.metricDiscriptions.threadContextSwitchesDesc
}

// Collect implements prometheus.Collector.
func (p *NamedProcessCollector) Collect(ch chan<- prometheus.Metric) {
	req := scrapeRequest{results: ch, done: make(chan struct{})}
	p.scrapeChan <- req
	<-req.done
}

func (p *NamedProcessCollector) start() {
	for req := range p.scrapeChan {
		ch := req.results
		p.scrape(ch)
		req.done <- struct{}{}
	}
}

func (p *NamedProcessCollector) scrape(ch chan<- prometheus.Metric) {
	permErrs, groups, err := p.Update(p.source.AllProcs())
	p.scrapePartialErrors += permErrs.Partial
	if err != nil {
		p.scrapeErrors++
		log.Printf("error reading procs: %v", err)
	} else {
		for gname, gcounts := range groups {
			ch <- prometheus.MustNewConstMetric(p.metricDiscriptions.numprocsDesc,
				prometheus.GaugeValue, float64(gcounts.Procs), gname, gcounts.CustomLabelValue)
			ch <- prometheus.MustNewConstMetric(p.metricDiscriptions.membytesDesc,
				prometheus.GaugeValue, float64(gcounts.Memory.ResidentBytes), gname, "resident", gcounts.CustomLabelValue)
			ch <- prometheus.MustNewConstMetric(p.metricDiscriptions.membytesDesc,
				prometheus.GaugeValue, float64(gcounts.Memory.VirtualBytes), gname, "virtual", gcounts.CustomLabelValue)
			ch <- prometheus.MustNewConstMetric(p.metricDiscriptions.membytesDesc,
				prometheus.GaugeValue, float64(gcounts.Memory.VmSwapBytes), gname, "swapped", gcounts.CustomLabelValue)
			ch <- prometheus.MustNewConstMetric(p.metricDiscriptions.startTimeDesc,
				prometheus.GaugeValue, float64(gcounts.OldestStartTime.Unix()), gname, gcounts.CustomLabelValue)
			ch <- prometheus.MustNewConstMetric(p.metricDiscriptions.openFDsDesc,
				prometheus.GaugeValue, float64(gcounts.OpenFDs), gname, gcounts.CustomLabelValue)
			ch <- prometheus.MustNewConstMetric(p.metricDiscriptions.worstFDRatioDesc,
				prometheus.GaugeValue, float64(gcounts.WorstFDratio), gname, gcounts.CustomLabelValue)
			ch <- prometheus.MustNewConstMetric(p.metricDiscriptions.cpuSecsDesc,
				prometheus.CounterValue, gcounts.CPUUserTime, gname, "user", gcounts.CustomLabelValue)
			ch <- prometheus.MustNewConstMetric(p.metricDiscriptions.cpuSecsDesc,
				prometheus.CounterValue, gcounts.CPUSystemTime, gname, "system", gcounts.CustomLabelValue)
			ch <- prometheus.MustNewConstMetric(p.metricDiscriptions.readBytesDesc,
				prometheus.CounterValue, float64(gcounts.ReadBytes), gname, gcounts.CustomLabelValue)
			ch <- prometheus.MustNewConstMetric(p.metricDiscriptions.writeBytesDesc,
				prometheus.CounterValue, float64(gcounts.WriteBytes), gname, gcounts.CustomLabelValue)
			ch <- prometheus.MustNewConstMetric(p.metricDiscriptions.majorPageFaultsDesc,
				prometheus.CounterValue, float64(gcounts.MajorPageFaults), gname, gcounts.CustomLabelValue)
			ch <- prometheus.MustNewConstMetric(p.metricDiscriptions.minorPageFaultsDesc,
				prometheus.CounterValue, float64(gcounts.MinorPageFaults), gname, gcounts.CustomLabelValue)
			ch <- prometheus.MustNewConstMetric(p.metricDiscriptions.contextSwitchesDesc,
				prometheus.CounterValue, float64(gcounts.CtxSwitchVoluntary), gname, "voluntary", gcounts.CustomLabelValue)
			ch <- prometheus.MustNewConstMetric(p.metricDiscriptions.contextSwitchesDesc,
				prometheus.CounterValue, float64(gcounts.CtxSwitchNonvoluntary), gname, "nonvoluntary", gcounts.CustomLabelValue)
			ch <- prometheus.MustNewConstMetric(p.metricDiscriptions.numThreadsDesc,
				prometheus.GaugeValue, float64(gcounts.NumThreads), gname, gcounts.CustomLabelValue)
			ch <- prometheus.MustNewConstMetric(p.metricDiscriptions.statesDesc,
				prometheus.GaugeValue, float64(gcounts.States.Running), gname, "Running", gcounts.CustomLabelValue)
			ch <- prometheus.MustNewConstMetric(p.metricDiscriptions.statesDesc,
				prometheus.GaugeValue, float64(gcounts.States.Sleeping), gname, "Sleeping", gcounts.CustomLabelValue)
			ch <- prometheus.MustNewConstMetric(p.metricDiscriptions.statesDesc,
				prometheus.GaugeValue, float64(gcounts.States.Waiting), gname, "Waiting", gcounts.CustomLabelValue)
			ch <- prometheus.MustNewConstMetric(p.metricDiscriptions.statesDesc,
				prometheus.GaugeValue, float64(gcounts.States.Zombie), gname, "Zombie", gcounts.CustomLabelValue)
			ch <- prometheus.MustNewConstMetric(p.metricDiscriptions.statesDesc,
				prometheus.GaugeValue, float64(gcounts.States.Other), gname, "Other", gcounts.CustomLabelValue)

			for wchan, count := range gcounts.Wchans {
				ch <- prometheus.MustNewConstMetric(p.metricDiscriptions.threadWchanDesc,
					prometheus.GaugeValue, float64(count), gname, wchan, gcounts.CustomLabelValue)
			}

			if p.smaps {
				ch <- prometheus.MustNewConstMetric(p.metricDiscriptions.membytesDesc,
					prometheus.GaugeValue, float64(gcounts.Memory.ProportionalBytes), gname, "proportionalResident", gcounts.CustomLabelValue)
				ch <- prometheus.MustNewConstMetric(p.metricDiscriptions.membytesDesc,
					prometheus.GaugeValue, float64(gcounts.Memory.ProportionalSwapBytes), gname, "proportionalSwapped", gcounts.CustomLabelValue)
			}

			if p.threads {
				for _, thr := range gcounts.Threads {
					ch <- prometheus.MustNewConstMetric(p.metricDiscriptions.threadCountDesc,
						prometheus.GaugeValue, float64(thr.NumThreads),
						gname, thr.Name, gcounts.CustomLabelValue)
					ch <- prometheus.MustNewConstMetric(p.metricDiscriptions.threadCpuSecsDesc,
						prometheus.CounterValue, float64(thr.CPUUserTime),
						gname, thr.Name, "user", gcounts.CustomLabelValue)
					ch <- prometheus.MustNewConstMetric(p.metricDiscriptions.threadCpuSecsDesc,
						prometheus.CounterValue, float64(thr.CPUSystemTime),
						gname, thr.Name, "system", gcounts.CustomLabelValue)
					ch <- prometheus.MustNewConstMetric(p.metricDiscriptions.threadIoBytesDesc,
						prometheus.CounterValue, float64(thr.ReadBytes),
						gname, thr.Name, "read", gcounts.CustomLabelValue)
					ch <- prometheus.MustNewConstMetric(p.metricDiscriptions.threadIoBytesDesc,
						prometheus.CounterValue, float64(thr.WriteBytes),
						gname, thr.Name, "write", gcounts.CustomLabelValue)
					ch <- prometheus.MustNewConstMetric(p.metricDiscriptions.threadMajorPageFaultsDesc,
						prometheus.CounterValue, float64(thr.MajorPageFaults),
						gname, thr.Name, gcounts.CustomLabelValue)
					ch <- prometheus.MustNewConstMetric(p.metricDiscriptions.threadMinorPageFaultsDesc,
						prometheus.CounterValue, float64(thr.MinorPageFaults),
						gname, thr.Name, gcounts.CustomLabelValue)
					ch <- prometheus.MustNewConstMetric(p.metricDiscriptions.threadContextSwitchesDesc,
						prometheus.CounterValue, float64(thr.CtxSwitchVoluntary),
						gname, thr.Name, "voluntary", gcounts.CustomLabelValue)
					ch <- prometheus.MustNewConstMetric(p.metricDiscriptions.threadContextSwitchesDesc,
						prometheus.CounterValue, float64(thr.CtxSwitchNonvoluntary),
						gname, thr.Name, "nonvoluntary", gcounts.CustomLabelValue)
				}
			}
		}
	}
	ch <- prometheus.MustNewConstMetric(p.metricDiscriptions.scrapeErrorsDesc,
		prometheus.CounterValue, float64(p.scrapeErrors))
	ch <- prometheus.MustNewConstMetric(p.metricDiscriptions.scrapeProcReadErrorsDesc,
		prometheus.CounterValue, float64(p.scrapeProcReadErrors))
	ch <- prometheus.MustNewConstMetric(p.metricDiscriptions.scrapePartialErrorsDesc,
		prometheus.CounterValue, float64(p.scrapePartialErrors))
}
