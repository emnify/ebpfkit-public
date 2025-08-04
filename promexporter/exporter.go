package promexporter

import (
	"errors"
	"fmt"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/prometheus/client_golang/prometheus"

	"opensource.emnify.fyi/go/ebpfkit/internal/btfutil"
)

type MetricsOptions struct {
	// Namespace
	Namespace string

	// Subsystem
	Subsystem string

	// SubStructPath refers to a nested struct within map value type
	// (selects a subset of data stored in the map)
	SubStructPath []string
}

// NewMetrics creates a Prometheus collector exposing struct fields
// stored in a per-CPU ebpf map. NB: call .Close() to release ebpf map
// when done.
//
// Collector uses ebpf type info (BTF) to locate uint64 struct fields.
// Each field, including ones found in nested structures, is exposed as
// Prometheus metric.
func NewMetrics(m *ebpf.Map, spec *ebpf.MapSpec, opts *MetricsOptions) (*Metrics, error) {
	var met Metrics

	if opts == nil {
		opts = &MetricsOptions{}
	}
	if spec == nil {
		return nil, errors.New("nil ebpf.MapSpec")
	}
	if m == nil {
		return nil, errors.New("nil ebpf.Map")
	}
	if err := spec.Compatible(m); err != nil {
		return nil, fmt.Errorf("inconsitent ebpf.Map and ebpf.MapSpec: %w", err)
	}

	if m.Type() != ebpf.PerCPUArray {
		return nil, fmt.Errorf("expecting %s, got %s", ebpf.PerCPUArray, m.Type())
	}
	if m.MaxEntries() != 1 {
		return nil, errors.New("expecting a map with 1 entry")
	}
	if spec.Value == nil {
		return nil, errors.New("type info missing")
	}

	// apply opts.SubStructPath
	typ, offset, err := btfutil.SubStruct(spec.Value, opts.SubStructPath)
	if err != nil {
		return nil, err
	}

	// parse type info and discover metrics
	ms := metricsSourcer{
		namespace: opts.Namespace,
		subsystem: opts.Subsystem,
	}
	rpath, lpath := copyPath(opts.SubStructPath), make([]string, 0, maxDepth)
	if err := ms.process(promTypeUntyped, rpath, lpath, typ, offset, nil); err != nil {
		return nil, err
	}
	if len(ms.metrics) == 0 {
		return nil, fmt.Errorf("map %q: no metrics found", spec.Name)
	}
	met.metrics = ms.metrics

	// grab a reference to target map
	m, err = m.Clone()
	if err != nil {
		return nil, err
	}
	met.m = m
	return &met, nil
}

type Metrics struct {
	m       *ebpf.Map
	metrics []metric
}

type metric struct {
	offset      uint32
	id          string
	desc        *prometheus.Desc
	labelValues []string
	valueType   prometheus.ValueType
}

func (met *Metrics) Close() error {
	if met == nil {
		return nil
	}
	return met.m.Close()
}

func (met *Metrics) Describe(c chan<- *prometheus.Desc) {
	for _, metric := range met.metrics {
		c <- metric.desc
	}
}

func (met *Metrics) Collect(c chan<- prometheus.Metric) {
	data, err := met.rawData()
	if err != nil {
		// TODO log (can we use golang's structured log?)
		return
	}
	for _, metric := range met.metrics {
		val := float64(data.uint64At(metric.offset))
		cm, err := prometheus.NewConstMetric(
			metric.desc, metric.valueType, val, metric.labelValues...)
		if err != nil {
			continue
		}
		c <- cm
	}
}

var _ prometheus.Collector = (*Metrics)(nil)

// RawMetrics exposes underlying data. It is useful in tests and when
// more control over data submitted to Prometheus is desired.
func (met *Metrics) RawMetrics() (map[string]uint64, error) {
	data, err := met.rawData()
	if err != nil {
		return nil, err
	}
	raw := make(map[string]uint64, len(met.metrics))
	for _, metric := range met.metrics {
		raw[metric.id] = data.uint64At(metric.offset)
	}
	return raw, nil
}

func (met *Metrics) rawData() (perCPUMapData, error) {
	data, err := newPerCPUMapData(met.m.ValueSize())
	if err != nil {
		return nil, err
	}
	zero := uint32(0)
	err = met.m.Lookup(zero, &data)
	if err != nil {
		return nil, err
	}
	return data, nil
}

// realPath represents a sequence of steps taken through nested structures
type realPath []string

func (path realPath) String() string { return strings.Join(path, "/") }

// logPath (logical path) unlike realPath omits SubStructPath prefix
// (and may omit some steps due to the use of "squash" feature)
type logPath []string

func (path logPath) String() string { return strings.Join(path, "_") }

// protects against invalid BTF (with loops)
const maxDepth = 16

// copyPath creates a copy that can append w/o realloc up to maxDepth
func copyPath(path []string) realPath {
	return append(make(realPath, 0, maxDepth), path...)
}

type metricsSourcer struct {
	namespace, subsystem string
	labels, labelValues  []string

	vecBase  int // lpath[:vecBase] is the metric name and [vecBase:] is the label value
	vecLabel string

	metrics []metric
}

type promType int

const (
	promTypeVecBit promType = 1

	promTypeUntyped = promType(prometheus.UntypedValue << 1)
	promTypeCounter = promType(prometheus.CounterValue << 1)
	promTypeGauge   = promType(prometheus.GaugeValue << 1)

	promTypeCounterVec = promTypeCounter | promTypeVecBit
	promTypeGaugeVec   = promTypeGauge | promTypeVecBit
)

func parsePromType(s string) (promType, error) {
	switch s {
	case "counter":
		return promTypeCounter, nil
	case "gauge":
		return promTypeGauge, nil
	case "counter_vec":
		return promTypeCounterVec, nil
	case "gauge_vec":
		return promTypeGaugeVec, nil
	}
	return promTypeUntyped, fmt.Errorf("unknown prom_type: %q", s)
}

func (t promType) isVec() bool { return t&promTypeVecBit != 0 }

func (t promType) toValueType() prometheus.ValueType { return prometheus.ValueType(t >> 1) }

func (ms *metricsSourcer) process(pt promType, rpath realPath, lpath logPath, typ btf.Type, offset uint32, parent *btf.Member) error {
	if len(rpath) >= maxDepth {
		return fmt.Errorf("%s: max depth exceeded", rpath)
	}

	if pt == promTypeUntyped && parent != nil {
		var err error
		pt, err = ms.handlePromTypeTags(parent.Tags)
		if err != nil {
			return fmt.Errorf("%s: field tags: %v", rpath, err)
		}
		ms.vecBase = len(lpath)
	}

	if btfutil.IsUint64(typ) {
		id := append(lpath, ms.labelValues...).String()
		if pt.isVec() && ms.vecBase != len(lpath) {
			ms.pushLabel(ms.vecLabel, lpath[ms.vecBase:].String())
			defer ms.popLabel()
			lpath = lpath[:ms.vecBase]
		}
		name := prometheus.BuildFQName(ms.namespace, ms.subsystem, lpath.String())
		desc := prometheus.NewDesc(name, "", ms.labels, nil)
		ms.metrics = append(ms.metrics, metric{
			offset: offset, id: id, desc: desc, labelValues: ms.labelValues,
			valueType: pt.toValueType(),
		})
		return nil
	}

	record, ok := btf.As[*btf.Struct](typ)
	if !ok {
		return nil
	}

	if pt == promTypeUntyped {
		var err error
		pt, err = ms.handlePromTypeTags(record.Tags)
		if err != nil {
			return fmt.Errorf("%s: struct type tags: %v", rpath, err)
		}
		ms.vecBase = len(lpath)
	}

	variations, err := getTag(record.Tags, "prom_variations:", parent)
	if err != nil {
		return fmt.Errorf("%s: %w", rpath, err)
	}
	if variations != "" {
		for _, m := range record.Members {
			if btf.UnderlyingType(m.Type) != btf.UnderlyingType(record.Members[0].Type) {
				return fmt.Errorf("%s: tagged prom_variations but fields %s and %s have incompatible types", rpath, m.Name, record.Members[0].Name)
			}
			if btfutil.IsABitfield(m) {
				continue
			}
			offset := offset + m.Offset.Bytes()
			rpath := append(rpath, m.Name)
			ms.pushLabel(variations, m.Name)
			if err := ms.process(pt, rpath, lpath, m.Type, offset, &m); err != nil {
				return err
			}
			ms.popLabel()
		}
		return nil
	}

	for _, m := range record.Members {
		if btfutil.IsABitfield(m) {
			continue
		}
		offset := offset + m.Offset.Bytes()
		rpath, lpath := append(rpath, m.Name), lpath
		if len(filterTags(m.Tags, "prom_squash:")) == 0 {
			lpath = append(lpath, m.Name)
		}
		if err := ms.process(pt, rpath, lpath, m.Type, offset, &m); err != nil {
			return err
		}
	}
	return nil
}

func (ms *metricsSourcer) pushLabel(label, labelValue string) {
	ms.labels = append(ms.labels, label)
	ms.labelValues = append(ms.labelValues, labelValue)
}

func (ms *metricsSourcer) popLabel() {
	// tweak capacity to ensure that subsequent pushLabel allocates new arrays
	ms.labels = ms.labels[: len(ms.labels)-1 : len(ms.labels)-1]
	ms.labelValues = ms.labelValues[: len(ms.labelValues)-1 : len(ms.labelValues)-1]
}

func (ms *metricsSourcer) handlePromTypeTags(tags []string) (promType, error) {
	promTypes := filterTags(tags, "prom_type:")
	switch {
	case len(promTypes) == 0:
		return promTypeUntyped, nil
	case len(promTypes) > 1:
		return 0, errors.New("conflicting prom_type tags")
	}
	pt, err := parsePromType(promTypes[0])
	if err != nil {
		return 0, err
	}
	if !pt.isVec() {
		return pt, nil
	}
	promLabels := filterTags(tags, "prom_label:")
	switch {
	case len(promLabels) == 0:
		return 0, fmt.Errorf("prom_type:%s requires a prom_label tag", promTypes[0])
	case len(promLabels) > 1:
		return 0, errors.New("conflicting prom_label tags")
	}
	ms.vecLabel = promLabels[0]
	return pt, nil
}

func getTag(tags []string, prefix string, parent *btf.Member) (string, error) {
	if parent != nil {
		values := filterTags(parent.Tags, prefix)
		switch {
		case len(values) == 1:
			return values[0], nil
		case len(values) > 1:
			return "", fmt.Errorf("field tags: conflicting %s tags", strings.TrimRight(prefix, ":"))
		}
	}
	values := filterTags(tags, prefix)
	switch {
	case len(values) == 1:
		return values[0], nil
	case len(values) > 1:
		return "", fmt.Errorf("struct type tags: conflicting %s tags", strings.TrimRight(prefix, ":"))
	}
	return "", nil
}

func filterTags(tags []string, prefix string) (res []string) {
	for _, val := range tags {
		if strings.HasPrefix(val, prefix) {
			res = append(res, val[len(prefix):])
		}
	}
	return
}
