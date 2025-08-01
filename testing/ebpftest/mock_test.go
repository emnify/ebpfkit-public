package ebpftest

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go mk mock_test.c -- -I/usr/include/x86_64-linux-gnu -I/usr/include/aarch64-linux-gnu

import (
	"encoding/binary"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type foo struct {
	Bar uint32
}

type mockedFuncsAB struct {
	A func() Res[uint32] `ebpf:"a"`
	B func(uint32, *foo) `ebpf:"b"`
}

func TestBasicMock(t *testing.T) {
	SkipIfIncapable(t)

	spec, err := loadMk()
	require.NoError(t, err)

	mock := NewMock[mockedFuncsAB](t, spec)

	var prog struct {
		*ebpf.Program `ebpf:"test"`
	}
	RequireNoError(t, spec.LoadAndAssign(&prog, nil))
	defer prog.Close()

	// stub calls are registered
	mock.Expect().A()
	mock.Expect().B(1, &foo{})
	run(t, prog)

	mock.Reset()

	// function result override works
	mock.Expect().A().Return(0xdeadbeef)
	mock.Expect().B(1, &foo{Bar: 0xdeadbeef})
	run(t, prog)

	mock.Reset()

	// unexpected calls are reported
	run(t, prog)
	assert.Equal(t, mock.reset(), report{unexpected: []unexpectedCall{
		{name: "a", ncalls: 1},
		{name: "b", ncalls: 1},
	}})

	// unexpected calls (2)
	mock.Expect().A()
	run(t, prog)
	assert.Equal(t, mock.reset(), report{unexpected: []unexpectedCall{
		{name: "b", ncalls: 1},
	}})

	// unexpected calls, multiple calls are registered
	mock.Expect().A()
	run(t, prog)
	run(t, prog)
	assert.Equal(t, mock.reset(), report{unexpected: []unexpectedCall{
		{name: "a", ncalls: 2, expectedOnce: true},
		{name: "b", ncalls: 2},
	}})

	// mismatched args
	mock.Expect().A()
	mock.Expect().B(0, &foo{Bar: 42})
	run(t, prog)
	assert.Equal(t, mock.reset(), report{mismatch: []argMismatch{
		{name: "b", args: []any{uint32(1), &foo{}}, expectedArgs: []any{uint32(0), &foo{Bar: 42}}},
	}})
}

func TestReplaceMain(t *testing.T) {
	SkipIfIncapable(t)

	type mockedFuncs struct {
		mockedFuncsAB
		Test func(any) `ebpf:"test"`
	}

	spec, err := loadMk()
	require.NoError(t, err)

	mock := NewMock[mockedFuncs](t, spec)

	var prog struct {
		*ebpf.Program `ebpf:"test"`
	}
	RequireNoError(t, spec.LoadAndAssign(&prog, nil))
	defer prog.Close()

	// Main function replaced, prog.Test() invokes a stub, A and B skipped.
	// Being able to stub main function enables tail call interception.
	mock.Expect().Test(Any)
	run(t, prog)
	mock.Reset()

	// Ensure that .A and .B are properly initialized (nested structures in NewMock).
	mock.Expect().A()
	mock.Expect().B(0, nil)
	run(t, prog)
	assert.Equal(t, mock.reset(), report{missing: []string{"a", "b"}, unexpected: []unexpectedCall{
		{name: "test", ncalls: 1},
	}})
}

func TestReportIndirectUnknown(t *testing.T) {
	SkipIfIncapable(t)

	type mockedTest struct {
		Test func(any) `ebpf:"test"`
	}

	spec, err := loadMk()
	require.NoError(t, err)

	mock := NewMock[mockedTest](t, spec)

	var prog struct {
		*ebpf.Program `ebpf:"test"`
	}
	RequireNoError(t, spec.LoadAndAssign(&prog, nil))
	defer prog.Close()

	// Size of *void, forward-declared types and most context structs is unknown.
	// Surfaces as either NonNil or nil.
	mock.Expect().Test(nil)
	run(t, prog)
	assert.Equal(t, mock.reset(), report{mismatch: []argMismatch{
		{name: "test", args: []any{NonNil}, expectedArgs: []any{nil}},
	}})
}

func TestMockAny(t *testing.T) {
	SkipIfIncapable(t)

	// Any, any handling.
	type mockedB struct {
		B func(uint32, any) `ebpf:"b"`
	}

	spec, err := loadMk()
	require.NoError(t, err)

	mock := NewMock[mockedB](t, spec)

	var prog struct {
		*ebpf.Program `ebpf:"test"`
	}
	RequireNoError(t, spec.LoadAndAssign(&prog, nil))
	defer prog.Close()

	mock.Expect().B(1, Any)
	run(t, prog)
	mock.Reset()

	// we don't trip on nil; can't unmarshal since the type is unknown, expose raw bytes
	mock.Expect().B(1, nil)
	run(t, prog)

	rawVal := make([]byte, 4)
	binary.NativeEndian.PutUint32(rawVal, 42)
	assert.Equal(t, mock.reset(), report{mismatch: []argMismatch{
		{name: "b", args: []any{uint32(1), rawVal}, expectedArgs: []any{uint32(1), nil}},
	}})

	// ... or a TYPED nil
	mock.Expect().B(1, (*foo)(nil))
	run(t, prog)
	assert.Equal(t, mock.reset(), report{mismatch: []argMismatch{
		{name: "b", args: []any{uint32(1), &foo{Bar: 42}}, expectedArgs: []any{uint32(1), (*foo)(nil)}},
	}})

	// Any in expectedArgs is replaced with actual arg.
	mock.Expect().B(0, Any)
	run(t, prog)
	assert.Equal(t, mock.reset(), report{mismatch: []argMismatch{
		{name: "b", args: []any{uint32(1), rawVal}, expectedArgs: []any{uint32(0), rawVal}},
	}})

	// NonNil in expectedArgs is replaced with actual arg (for non-nil pointers).
	mock.Expect().B(0, NonNil)
	run(t, prog)
	assert.Equal(t, mock.reset(), report{mismatch: []argMismatch{
		{name: "b", args: []any{uint32(1), rawVal}, expectedArgs: []any{uint32(0), rawVal}},
	}})
}

func run(t *testing.T, testable interface {
	Test([]byte) (uint32, []byte, error)
}) {
	t.Helper()
	_, _, err := testable.Test(make([]byte, 14))
	assert.NoError(t, err)
}
