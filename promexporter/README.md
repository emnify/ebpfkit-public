# promexporter

Package `promexporter` exposes metrics hosted in eBPF [per-CPU array map](https://docs.ebpf.io/linux/map-type/BPF_MAP_TYPE_PERCPU_ARRAY/)
to Prometheus.

Ex:

```c
struct metrics {
    __u64 foo;
    __u64 bar;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, int);
    __type(value, struct metrics);
} metrics_map SEC(".maps");
```

Pass `metrics_map` as `*ebpf.Map` to `promexporter.NewMetrics` to initialize an exporter.
The exporter automatically parses eBPF typeinfo and exposes every `__u64` field
found in `struct metrics`:

```
foo   42  # TYPE foo untyped
bar 1337  # TYPE bar untyped
```

## Nested structures

Fields found in nested structures are exposed. E.g.

```c
struct metrics {
    struct net_stats {
        __u64 bytes_total;
        __u64 packets_total;
    } ingress, egress;
};
```
produces
```
ingress_bytes_total   1240440446  # TYPE ingress_bytes_total   untyped
ingress_packets_total    4801015  # TYPE ingress_packets_total untyped
egress_bytes_total    1368631333  # TYPE egress_bytes_total    untyped
egress_packets_total     3585747  # TYPE egress_packets_total  untyped
```
## Fine-tuning metrics

Prometheus supports different metric types, such as counters and gauges.
Use `PROM_TYPE("type")` macro to specify the metric type.

`PROM_TYPE` and further macros are defined in `exporter.h`

Note: it might be necessary to literally copy `exporter.h` into your project.
We contributed support in Cilium's `bpf2go` for pulling C headers from external Golang
packages, but unfortunately it was [rejected](https://github.com/cilium/ebpf/pull/1625).

Pulling a header from an external Golang project should be as easy as
```
#include <tech.emnify.com/go/ebpfkit/promexporter/exporter.h>
```

### Metric types

```c
struct net_stats {
    __u64 bytes_total;
    __u64 packets_total;
} PROM_TYPE("counter");

struct metrics {
    struct net_stats ingress, egress;
};
```

`PROM_TYPE` on a structure applies to all enclosed fields.
Alternatively, one can attach `PROM_TYPE` to individual fields.
Supported types include `"counter"`, `"gauge"` and vectors (see next section).

```
ingress_bytes_total   1240440446  # TYPE ingress_bytes_total   counter
ingress_packets_total    4801015  # TYPE ingress_packets_total counter
egress_bytes_total    1368631333  # TYPE egress_bytes_total    counter
egress_packets_total     3585747  # TYPE egress_packets_total  counter
```

### Counter and gauge vectors

```c
struct drop_stats {
    __u64 truncated;
    __u64 bad_checksum;
} PROM_TYPE("counter_vec") LABEL("drop_reason");

struct metrics {
    struct drop_stats drops_total;
};
```

Vectors are convenient to group related metrics such as `drops_total`.


```
# TYPE drops_total counter
drops_total{drop_reason="truncated"} 0
drops_total{drop_reason="bad_checksum"} 0
```
