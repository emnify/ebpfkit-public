#pragma once

// PROM_VARIATIONS(label) applies to a struct field or a sruct definition.
// It tells promexporter that the structure is comprised of multiple
// *identical* metric sets. A field name becomes a label value attached to
// metrics discovered in the field type.
// Ex:
//    struct metrics{
//      __u64 foo;
//    };
//    struct metrics_by_direction {
//      struct metrics upstream, downstream;
//    } PROM_VARIATIONS("dir");
//    Produces "foo[dir=upstream]" and "foo[dir=downstream]".
#define PROM_VARIATIONS(label) __attribute__((btf_decl_tag("prom_variations:" label)))

// PROM_SQUASH applies to a struct field. It tells promexporter to omit
// the field name when generating nested metric names.
// Ex:
//    struct nested {
//      __u64 metric;
//    };
//    struct counters {
//      struct nested nested PROM_SQUASH;
//    };
//    Produces "metric" instead of "nested_metric".
#define PROM_SQUASH __attribute__((btf_decl_tag("prom_squash:")))

// PROM_TYPE(type) applies to a struct field or a struct definition.
// It tells promexporter how to interpret metrics it discovers in the struct
// itself and nested types.  Available types are: "counter", "gauge",
// "counter_vec" and "gauge_vec".
//
// Please note that "*_vec" types are handled somewhat differently.
// Specifically, every metric discovered *under* a structure marked
// PROM_TYPE("counter_vec") or PROM_TYPE("gauge_vec") gets its path
// split into two components. The path leading to the structure bearing
// PROM_TYPE("*_vec") tag becomes the metric name while the rest
// is used as a label value. The label name comes from PROM_LABEL("...")
// tag (required).
//
// Ex:
//    struct errors_libabc {
//      __u64 foo;
//    };
//    struct errors {
//      __u64 bar;
//      struct errors_libabc libabc;
//    } PROM_TYPE("counter_vec") PROM_LABEL("name");
//    struct metrics {
//      struct errors errors;
//    };
//    Produces "errors[name=bar]" and "errors[name=libabc_foo]".
//
// Note: unlike PROM_VARIATIONS("..."), another mechanism to attach
// labels, vectors can have labels spanning multiple structures like
// "libabc_foo" above.
#define PROM_TYPE(type) __attribute__((btf_decl_tag("prom_type:" type)))

// PROM_LABEL(label) goes together with PROM_TYPE("counter_vec") and
// PROM_TYPE("gauge_vec").
#define PROM_LABEL(label) __attribute__((btf_decl_tag("prom_label:" label)))
