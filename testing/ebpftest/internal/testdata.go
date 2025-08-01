package internal

import (
	"github.com/cilium/ebpf"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go testdata mock_test.c -- -I/usr/include/x86_64-linux-gnu -I/usr/include/aarch64-linux-gnu

func Load() (*ebpf.CollectionSpec, error) {
	return loadTestdata()
}
