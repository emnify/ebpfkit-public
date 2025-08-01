//go:build ignore
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define noinline __attribute__((__noinline__))

noinline int a(void)
{
    int res = 42;
    barrier_var(res);
    return res;
}

struct foo {
    int bar;
};

noinline static int b(int param, struct foo *foo)
{
    barrier_var(param);
    barrier_var(foo);
    return param;
}

SEC("tc")
int test(void *ctx)
{
    struct foo foo = {.bar = a()};
    int x = 1;
    barrier_var(x);
    return b(x, &foo);
}

char _license[] SEC("license") = "Dual BSD/GPL";
