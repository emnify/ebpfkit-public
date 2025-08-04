// Package btfutil provides helpers for working with BTF.
package btfutil

import (
	"fmt"
	"slices"
	"strings"

	"github.com/cilium/ebpf/btf"
)

func StructMembers(typ btf.Type) []btf.Member {
	record, ok := btf.As[*btf.Struct](typ)
	if !ok {
		return nil
	}
	return record.Members
}

func IsABitfield(m btf.Member) bool {
	return m.Offset&7 != 0 || m.BitfieldSize != 0
}

func IsUint64(typ btf.Type) bool {
	typ = btf.UnderlyingType(typ)
	integer, ok := typ.(*btf.Int)
	return ok && integer.Size == 8 && integer.Encoding == btf.Unsigned
}

func SubStruct(typ btf.Type, path []string) (btf.Type, uint32, error) {
	offset := uint32(0)
	for i, name := range path {
		m := StructMembers(typ)
		idx := slices.IndexFunc(m, func(m btf.Member) bool { return m.Name == name })
		if idx == -1 {
			return nil, 0, fmt.Errorf("%s: no such member", strings.Join(path[:i+1], "/"))
		}
		if IsABitfield(m[idx]) {
			return nil, 0, fmt.Errorf("%s: is a bitfield", strings.Join(path[:i+1], "/"))
		}
		offset += m[idx].Offset.Bytes()
		typ = m[idx].Type
	}
	return typ, offset, nil
}
