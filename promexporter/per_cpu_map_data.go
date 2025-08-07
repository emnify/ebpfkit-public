package promexporter

import (
	"encoding/binary"

	"github.com/cilium/ebpf"
)

type perCPUMapData [][]byte

func newPerCPUMapData(valueSize uint32) (perCPUMapData, error) {
	n, err := ebpf.PossibleCPU()
	if err != nil {
		return nil, err
	}
	data := make(perCPUMapData, n)
	for i := range data {
		data[i] = make([]byte, valueSize)
	}
	return data, nil
}

func (data perCPUMapData) uint64At(offset uint32) uint64 {
	var res uint64
	for _, chunk := range data {
		if int(offset) < 0 || int(offset) > len(chunk)-8 {
			continue
		}
		res += binary.NativeEndian.Uint64(chunk[offset : offset+8])
	}
	return res
}
