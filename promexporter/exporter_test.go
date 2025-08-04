package promexporter_test

import (
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"

	"github.com/EMnify/ebpfkit"
	"github.com/EMnify/ebpfkit/promexporter"
	testdata "github.com/EMnify/ebpfkit/promexporter/internal"
	"github.com/EMnify/ebpfkit/testing/ebpftest"
)

func TestExporter(t *testing.T) {
	ebpftest.RequirePrivileges(t)

	spec, err := testdata.Load()
	require.NoError(t, err)
	loader := ebpfkit.Loader{CollectionSpec: spec}

	// export "counters_map" as a collection of Prometheus metrics
	m1, err := promexporter.NewMetrics(&loader, promexporter.MetricsOptions{
		MapName: "counters_map",
	})
	require.NoError(t, err)
	defer m1.Close()

	// multiple metrics objects can coexist, and even share the same map
	// (in here we are testing SubStructPath feature)
	m2, err := promexporter.NewMetrics(&loader, promexporter.MetricsOptions{
		MapName:       "counters_map",
		SubStructPath: []string{"bar"},
	})
	require.NoError(t, err)
	defer m2.Close()

	// even before ebpf spec is fully loaded, metrics are operational; it
	// is fine to add it to Prometheus registry right away
	dict, err := m1.RawMetrics()
	require.NoError(t, err)
	require.Equal(t, map[string]uint64{"foo": 0, "bar_martians": 0}, dict)

	// load spec
	var objects testdata.Objects
	err = loader.LoadAndAssign(&objects)
	require.NoError(t, err)
	defer objects.Close()

	// run a program to alter data stored in ebpf map
	rc, _, err := objects.PokeCounters.Test(make([]byte, 14))
	require.NoError(t, err)
	require.Equal(t, uint32(0), rc)

	// ensure that PokeCounters changes are visible
	dict, err = m1.RawMetrics()
	require.NoError(t, err)
	require.Equal(t, map[string]uint64{"foo": 1, "bar_martians": 2}, dict)

	dict, err = m2.RawMetrics()
	require.NoError(t, err)
	require.Equal(t, map[string]uint64{"martians": 2}, dict)
}

func TestVariations(t *testing.T) {
	ebpftest.RequirePrivileges(t)

	spec, err := testdata.Load()
	require.NoError(t, err)
	loader := ebpfkit.Loader{CollectionSpec: spec}

	m, err := promexporter.NewMetrics(&loader, promexporter.MetricsOptions{
		MapName: "stats_by_function",
	})
	require.NoError(t, err)
	defer m.Close()

	expected := `
# HELP bytes
# TYPE bytes untyped
bytes{fn="downstream",kind="drop"} 0
bytes{fn="downstream",kind="pass"} 0
bytes{fn="downstream",kind="rx"} 0
bytes{fn="downstream",kind="tx"} 0
bytes{fn="upstream",kind="drop"} 0
bytes{fn="upstream",kind="pass"} 0
bytes{fn="upstream",kind="rx"} 0
bytes{fn="upstream",kind="tx"} 0
# HELP pkt
# TYPE pkt untyped
pkt{fn="downstream",kind="drop"} 0
pkt{fn="downstream",kind="pass"} 0
pkt{fn="downstream",kind="rx"} 0
pkt{fn="downstream",kind="tx"} 0
pkt{fn="upstream",kind="drop"} 0
pkt{fn="upstream",kind="pass"} 0
pkt{fn="upstream",kind="rx"} 0
pkt{fn="upstream",kind="tx"} 0
`
	require.NoError(t, testutil.CollectAndCompare(m, strings.NewReader(expected)))

	dict, err := m.RawMetrics()
	require.NoError(t, err)
	require.Equal(t, map[string]uint64{
		"bytes_downstream_drop": 0,
		"bytes_downstream_pass": 0,
		"bytes_downstream_rx":   0,
		"bytes_downstream_tx":   0,
		"bytes_upstream_drop":   0,
		"bytes_upstream_pass":   0,
		"bytes_upstream_rx":     0,
		"bytes_upstream_tx":     0,
		"pkt_downstream_drop":   0,
		"pkt_downstream_pass":   0,
		"pkt_downstream_rx":     0,
		"pkt_downstream_tx":     0,
		"pkt_upstream_drop":     0,
		"pkt_upstream_pass":     0,
		"pkt_upstream_rx":       0,
		"pkt_upstream_tx":       0,
	}, dict)
}

func TestSquash(t *testing.T) {
	ebpftest.RequirePrivileges(t)

	spec, err := testdata.Load()
	require.NoError(t, err)
	loader := ebpfkit.Loader{CollectionSpec: spec}

	m, err := promexporter.NewMetrics(&loader, promexporter.MetricsOptions{
		MapName: "toplevel",
	})
	require.NoError(t, err)
	defer m.Close()

	dict, err := m.RawMetrics()
	require.NoError(t, err)
	require.Equal(t, map[string]uint64{"foo": 0, "bar": 0, "dummy": 0}, dict)
}

func TestTypeLabel(t *testing.T) {
	ebpftest.RequirePrivileges(t)

	spec, err := testdata.Load()
	require.NoError(t, err)
	loader := ebpfkit.Loader{CollectionSpec: spec}

	m, err := promexporter.NewMetrics(&loader, promexporter.MetricsOptions{
		MapName: "toplevel_counter_vec",
	})
	require.NoError(t, err)
	defer m.Close()

	expected := `
# HELP stats
# TYPE stats counter
stats{label="bar"} 0
stats{label="nested_foo"} 0
stats{label="nested_dummy"} 0
`
	require.NoError(t, testutil.CollectAndCompare(m, strings.NewReader(expected)))
}

func TestFieldTags(t *testing.T) {
	ebpftest.RequirePrivileges(t)

	spec, err := testdata.Load()
	require.NoError(t, err)
	loader := ebpfkit.Loader{CollectionSpec: spec}

	m, err := promexporter.NewMetrics(&loader, promexporter.MetricsOptions{
		MapName: "toplevel_taged_fields",
	})
	require.NoError(t, err)
	defer m.Close()

	expected := `
# HELP foo 
# TYPE foo counter
foo 0
# HELP bar 
# TYPE bar gauge
bar 0
# HELP counter_vec
# TYPE counter_vec counter
counter_vec{label="foo"} 0
counter_vec{label="dummy"} 0
# HELP overlapping_tags
# TYPE overlapping_tags counter
overlapping_tags{new_label="bar"} 0
overlapping_tags{new_label="nested_foo"} 0
overlapping_tags{new_label="nested_dummy"} 0
# HELP bytes 
# TYPE bytes untyped
bytes{fn="downstream",kind="rx"} 0
bytes{fn="downstream",kind="tx"} 0
bytes{fn="upstream",kind="rx"} 0
bytes{fn="upstream",kind="tx"} 0
# HELP pkt 
# TYPE pkt untyped
pkt{fn="downstream",kind="rx"} 0
pkt{fn="downstream",kind="tx"} 0
pkt{fn="upstream",kind="rx"} 0
pkt{fn="upstream",kind="tx"} 0
# HELP single_label
# TYPE single_label counter
single_label 0
`
	require.NoError(t, testutil.CollectAndCompare(m, strings.NewReader(expected)))
}
