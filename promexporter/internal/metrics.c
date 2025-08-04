//go:build ignore
#include "../exporter.h"
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct counters {
    __u64 foo;
    struct {
        __u64 martians;
    } bar;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, int);
    __type(value, struct counters);
} counters_map SEC(".maps");

SEC("xdp")
int poke_counters(struct xdp_md *ctx)
{
    __u32 zero = 0;
    struct counters *counters = bpf_map_lookup_elem(&counters_map, &zero);
    if (!counters) {
        return 2;
    }
    counters->foo = 1;
    counters->bar.martians = 2;
    return 0;
}

struct combined_counter {
    __u64 bytes, pkt;
};

struct stats_by_kind {
    struct combined_counter rx, tx, drop, pass;
} PROM_VARIATIONS("kind");

struct stats_by_function {
    struct stats_by_kind upstream, downstream;
} PROM_VARIATIONS("fn");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, int);
    __type(value, struct stats_by_function);
} stats_by_function SEC(".maps");

struct nested {
    __u64 foo, dummy;
};

struct toplevel {
    __u64 bar;
    struct nested nested PROM_SQUASH;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, int);
    __type(value, struct toplevel);
} toplevel SEC(".maps");

struct counter_vec {
    __u64 bar;
    struct nested nested;
} PROM_TYPE("counter_vec") PROM_LABEL("label");

struct toplevel_counter_vec {
    struct counter_vec stats;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, int);
    __type(value, struct toplevel_counter_vec);
} toplevel_counter_vec SEC(".maps");

struct kinds_untaged {
    struct combined_counter rx, tx;
};

struct taged_by_function {
    struct kinds_untaged upstream PROM_VARIATIONS("kind");
    struct kinds_untaged downstream PROM_VARIATIONS("kind");
};

struct toplevel_taged_fields {
    __u64 foo PROM_TYPE("counter");
    __u64 bar PROM_TYPE("gauge");
    struct nested counter_vec PROM_TYPE("counter_vec") PROM_LABEL("label");
    struct counter_vec overlapping_tags PROM_TYPE("counter_vec") PROM_LABEL("new_label");
    struct taged_by_function variations PROM_SQUASH PROM_VARIATIONS("fn");
    __u64 single_label PROM_TYPE("counter_vec") PROM_LABEL("label");
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, int);
    __type(value, struct toplevel_taged_fields);
} toplevel_taged_fields SEC(".maps");
