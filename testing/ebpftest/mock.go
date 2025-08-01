package ebpftest

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"github.com/google/go-cmp/cmp"
	"golang.org/x/sys/unix"
)

type anyArg struct{}

// Any matches any value, e.g. mock.Expect().Foobar(Any, Any)
var Any anyArg

type nonNilArg struct{}

var NonNil nonNilArg

type res struct {
	m        *mock
	funcName string
}

// Res is used as the result type in mock functions, enables
// mock.Expect().Foobar().Return(42) syntax.
type Res[T any] res

func (r Res[T]) Return(res T) {
	r.m.t.Helper()
	if err := r.m.overrideResult(r.funcName, res); err != nil {
		r.m.t.Fatal(err)
	}
}

type mock struct {
	t     *testing.T
	stubs map[string]stubInfo
	mem   *ebpf.Map

	// memView is protected with the mutex, enables safe munmap
	memViewMut sync.Mutex
	memView    []byte

	callsExpected map[string][]any
}

type Mock[MockedFuncs any] struct {
	*mock
	funcs MockedFuncs
}

func (m *Mock[MockedFuncs]) Expect() MockedFuncs {
	return m.funcs
}

// Reset discards accumulated state, enabling mock reuse. Any discrepancies in expectations vs. reality are reported.
func (m *Mock[MockedFuncs]) Reset() {
	m.t.Helper()
	report := m.reset()
	for _, unexpected := range report.unexpected {
		suffix := ""
		if unexpected.expectedOnce {
			suffix = ": expected once"
		}
		m.t.Logf("unexpected call to %q, %d time(s)%s", unexpected.name, unexpected.ncalls, suffix)
		m.t.Fail()
	}
	for _, mismatch := range report.mismatch {
		m.t.Logf("unexpected args in a call to %q: %s", mismatch.name, cmp.Diff(mismatch.expectedArgs, mismatch.args))
		m.t.Fail()
	}
	for _, name := range report.missing {
		m.t.Logf("missing call to %q", name)
		m.t.Fail()
	}
}

// NewMock rewrites spec such that select eBPF functions are replaced
// with stubs. Functions to be replaced are encoded in MockedFuncs type.
// Ex:
//
//	type myFuncs struct {
//	    Foo func(any)                 `ebpf:"foo"`
//	    Bar func(any, any) Res[int32] `ebpf:"bar"`
//	}
//	mock := NewMock[myFuncs](...)
//	mock.Expect().Foo(42)
//	mock.Expect().Bar(Any, 0).Return(-1)
//
// In this example, functions known in C source as "foo" and "bar" are
// replaced with stubs. Every call to a stub is registered. A test
// communicates expected calls through mock.Expect().Foo and
// mock.Expect().Bar. One can optionally override the result (0 is used
// by default).
//
// We might eventually add support for tracking repeated stub calls, so
// far only the last call is registered.
func NewMock[MockedFuncs any](t *testing.T, spec *ebpf.CollectionSpec) *Mock[MockedFuncs] {
	t.Helper()
	m := &Mock[MockedFuncs]{}
	mock, funcs, err := newMock(t, spec, reflect.TypeOf(m.funcs))
	if err != nil {
		if mock != nil {
			mock.close()
		}
		t.Fatal(err)
	}
	m.mock = mock
	m.funcs = funcs.(MockedFuncs)
	t.Cleanup(func() {
		m.Reset()
		m.mock.close()
	})
	return m
}

func newMock(t *testing.T, spec *ebpf.CollectionSpec, funcsType reflect.Type) (*mock, any, error) {
	if funcsType.Kind() != reflect.Struct {
		return nil, nil, fmt.Errorf("expecting a struct type, got %s instead", funcsType)
	}

	funcs := reflect.New(funcsType).Elem()
	ebpfFuncs := extractEbpfFuncs(spec)
	goFuncs, err := extractGoFuncs(funcs, ebpfFuncs)
	if err != nil {
		return nil, nil, err
	}
	if len(goFuncs) == 0 {
		return nil, nil, errors.New("please specify at least one function to mock")
	}

	m := &mock{t: t, stubs: make(map[string]stubInfo)}

	memSize := 0
	for _, goFunc := range goFuncs {
		goFunc.val.Set(goFunc.create(m))
		if _, ok := m.stubs[goFunc.ebpfName]; ok {
			continue
		}
		info, err := makeStubInfo(ebpfFuncs[goFunc.ebpfName])
		if err != nil {
			return nil, nil, err
		}
		info.baseOffset = memSize
		memSize += info.memSize()
		m.stubs[goFunc.ebpfName] = info
	}

	const BPF_F_MMAPPABLE = 1024
	m.mem, err = ebpf.NewMap(&ebpf.MapSpec{
		Name:       "mock_mem",
		Type:       ebpf.Array,
		KeySize:    4,
		ValueSize:  uint32(memSize),
		MaxEntries: 1,
		Flags:      BPF_F_MMAPPABLE,
	})
	if err != nil {
		return nil, nil, err
	}

	m.memView, err = unix.Mmap(m.mem.FD(), 0, memSize, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		return m, nil, err
	}

	for _, prog := range spec.Programs {
		prog.Instructions = rewriteProg(prog.Instructions, m.stubs, m.mem)
	}

	return m, funcs.Interface(), nil
}

func (m *mock) close() {
	_ = m.mem.Close()
	m.memViewMut.Lock()
	defer m.memViewMut.Unlock()
	if m.memView != nil {
		_ = unix.Munmap(m.memView)
		m.memView = nil
	}
}

// expectCall records that the function NAME is expected to be called once with the specified ARGS.
func (m *mock) expectCall(name string, args []any) error {
	if _, dup := m.callsExpected[name]; dup {
		return fmt.Errorf("%q: call already expected, can't expect multiple calls", name)
	}
	info := m.stubs[name]
	for i, arg := range args {
		if arg == Any || arg == NonNil || arg == nil {
			continue
		}
		if info.arg[i] == valueTypeIndirectUnknown() {
			return fmt.Errorf("%q: arg %d size is unknown", name, i)
		}
		// Ensure that the value serializes to the expected size. We
		// might be getting nil typed pointers, therefore create
		// entity from scratch (blank).
		argTyp := reflect.TypeOf(arg)
		var blank reflect.Value
		if argTyp.Kind() == reflect.Pointer {
			blank = reflect.New(argTyp.Elem())
		} else {
			blank = reflect.New(argTyp)
		}
		buf := &bytes.Buffer{}
		if err := binary.Write(buf, binary.NativeEndian, blank.Interface()); err != nil {
			return fmt.Errorf("%q: marshalling arg %d: %s", name, i, err)
		}
		if info.arg[i].size != len(buf.Bytes()) {
			return fmt.Errorf("%q: arg %d: value doesn't marshal to %d bytes", name, i, info.arg[i].size)
		}
	}
	if m.callsExpected == nil {
		m.callsExpected = make(map[string][]any)
	}
	m.callsExpected[name] = args
	return nil
}

// overrideResult makes the function NAME return the specified RES.
func (m *mock) overrideResult(name string, res any) error {
	buf := &bytes.Buffer{}
	if err := binary.Write(buf, binary.NativeEndian, res); err != nil {
		return err
	}

	info := m.stubs[name]
	if info.res.size != len(buf.Bytes()) {
		return fmt.Errorf("%q: result value doesn't marshal to %d bytes", name, info.res.size)
	}

	m.memViewMut.Lock()
	defer m.memViewMut.Unlock()
	stubMem := (*stubMem)(unsafe.Pointer(&m.memView[info.baseOffset]))
	if atomic.LoadUint64(&stubMem.ncalls) != 0 {
		return fmt.Errorf("%q: can't override result, already called", name)
	}
	copy(stubMem.res[:], buf.Bytes())

	return nil
}

type report struct {
	unexpected []unexpectedCall
	mismatch   []argMismatch
	missing    []string
}

type unexpectedCall struct {
	name         string
	ncalls       uint64
	expectedOnce bool
}

type argMismatch struct {
	name         string
	args         []any
	expectedArgs []any
}

// reset discards accumulated state, enabling mock reuse. Any discrepancies in expectations vs. reality are reported.
func (m *mock) reset() report {
	var report report

	expected := m.callsExpected
	recorded := m.resetCalls()
	m.callsExpected = nil

	for name, rec := range recorded {
		if _, isExpected := expected[name]; !isExpected {
			report.unexpected = append(report.unexpected, unexpectedCall{
				name: name, ncalls: rec.ncalls,
			})
		}
	}

	for name, expectedArgs := range expected {
		rec, found := recorded[name]
		if !found {
			report.missing = append(report.missing, name)
			continue
		}
		if rec.ncalls != 1 {
			report.unexpected = append(report.unexpected, unexpectedCall{
				name: name, ncalls: rec.ncalls, expectedOnce: true,
			})
		}

		args := make([]any, len(expectedArgs))
		for i, arg := range expectedArgs {
			if rec.arg[i].pointeeReadErr != nil {
				args[i] = rec.arg[i].pointeeReadErr
				continue
			}

			if arg == nil || arg == Any || arg == NonNil {
				if rec.arg[i].val != nil {
					args[i] = rec.arg[i].val
				} else if rec.arg[i].ptr != 0 {
					args[i] = NonNil
				}
				if arg == Any {
					// Let the value surface in the report. We don't
					// know the type but raw bytes might still give a hint.
					expectedArgs[i] = args[i]
				}
				if arg == NonNil && rec.arg[i].ptr != 0 {
					expectedArgs[i] = args[i]
				}
				continue
			}

			argTyp := reflect.TypeOf(arg)
			var blank reflect.Value
			if argTyp.Kind() == reflect.Pointer {
				blank = reflect.New(argTyp.Elem())
			} else {
				blank = reflect.New(argTyp)
			}

			buf := bytes.NewReader(rec.arg[i].val)
			if err := binary.Read(buf, binary.NativeEndian, blank.Interface()); err != nil {
				args[i] = err
				continue
			}

			if argTyp.Kind() == reflect.Pointer {
				args[i] = blank.Interface()
			} else {
				args[i] = blank.Elem().Interface()
			}
		}

		if !cmp.Equal(expectedArgs, args) {
			report.mismatch = append(report.mismatch, argMismatch{
				name: name, args: args, expectedArgs: expectedArgs,
			})
		}
	}

	slices.SortFunc(report.unexpected, func(a, b unexpectedCall) int { return strings.Compare(a.name, b.name) })
	slices.SortFunc(report.mismatch, func(a, b argMismatch) int { return strings.Compare(a.name, b.name) })
	slices.Sort(report.missing)
	return report
}

type callRecord struct {
	ncalls uint64      // how many times it was called
	arg    [5]struct { // arguments received (last call)
		val            []byte // for pointers, the pointee is captured
		ptr            uintptr
		pointeeReadErr error
	}
}

// resetCalls extracts call history accumulated so far and clears eBPF memory
func (m *mock) resetCalls() map[string]callRecord {
	m.memViewMut.Lock()
	defer m.memViewMut.Unlock()

	if m.memView == nil {
		return nil
	}

	calls := make(map[string]callRecord)

	for name, info := range m.stubs {
		tail := m.memView[info.baseOffset:]
		stubMem := (*stubMem)(unsafe.Pointer(&tail[0]))
		if atomic.LoadUint64(&stubMem.ncalls) == 0 {
			continue
		}
		tail = tail[unsafe.Sizeof(*stubMem):]
		call := callRecord{}
		for i, arg := range info.arg[:info.nargs] {
			if arg.indirect {
				call.arg[i].ptr = uintptr(binary.NativeEndian.Uint64(stubMem.arg[i][:]))
			} else {
				call.arg[i].val = make([]byte, arg.size)
				copy(call.arg[i].val, stubMem.arg[i][:])
			}
			if arg.indirectSize() > 0 {
				if call.arg[i].ptr != 0 {
					if stubMem.rc[i] == 0 {
						call.arg[i].val = make([]byte, arg.size)
						copy(call.arg[i].val, tail)
					} else {
						call.arg[i].pointeeReadErr = syscall.Errno(-stubMem.rc[i])
					}
				}
				tail = tail[arg.indirectSize():]
			}
		}
		call.ncalls = atomic.LoadUint64(&stubMem.ncalls)
		calls[name] = call
	}

	copy(m.memView, make([]byte, len(m.memView)))
	return calls
}

// valueType summarises btf.Type. Captures the value size and whether it is passed by value or by pointer.
type valueType struct {
	size     int
	indirect bool
}

// valueTypeIndirectUnknown: pointer to forward-declared type, void, or blacklisted type
func valueTypeIndirectUnknown() valueType { return valueType{size: -1, indirect: true} }

func makeValueType(typ btf.Type) (valueType, error) {
	if ptr, ok := btf.As[*btf.Pointer](typ); ok {
		target := btf.UnderlyingType(ptr.Target)
		switch target := target.(type) {
		case *btf.Fwd:
			return valueTypeIndirectUnknown(), nil
		case *btf.Void:
			return valueTypeIndirectUnknown(), nil
		case *btf.Struct:
			if _, blacklisted := bpfStructBlacklist[target.Name]; blacklisted {
				return valueTypeIndirectUnknown(), nil
			}
		}
		sz, err := btf.Sizeof(target)
		if err != nil {
			return valueType{}, err
		}
		return valueType{indirect: true, size: sz}, nil
	}
	sz, err := btf.Sizeof(typ)
	if err != nil {
		return valueType{}, err
	}
	if sz == 1 || sz == 2 || sz == 4 || sz == 8 {
		return valueType{size: sz}, nil
	}
	return valueType{}, fmt.Errorf("unsupported size: %d", sz)
}

var bpfStructBlacklist = map[string]struct{}{
	// "virtual" types, underlying types have different layout
	"__sk_buff": {},
	"xdp_md":    {},
}

func (vt valueType) asmSize() asm.Size {
	if vt.indirect {
		return asm.DWord
	}
	switch vt.size {
	case 8:
		return asm.DWord
	case 4:
		return asm.Word
	case 2:
		return asm.Half
	case 1:
		return asm.Byte
	default:
		return asm.InvalidSize
	}
}

func (vt valueType) indirectSize() int {
	if vt.indirect && vt.size > 0 {
		return vt.size
	}
	return 0
}

// stubInfo captures info necessary to generate a stub
type stubInfo struct {
	baseOffset int
	nargs      int
	res        valueType
	arg        [5]valueType
}

func makeStubInfo(fn *btf.Func) (stubInfo, error) {
	proto := fn.Type.(*btf.FuncProto)
	info := stubInfo{}
	var err error
	info.res, err = makeValueType(proto.Return)
	if err != nil {
		return info, fmt.Errorf("%s: result %s: %w", fn.Name, proto.Return, err)
	}
	info.nargs = len(proto.Params)
	if info.nargs > 5 {
		return info, fmt.Errorf("%s: too many arguments %d", fn.Name, len(proto.Params))
	}
	for i, param := range proto.Params {
		info.arg[i], err = makeValueType(param.Type)
		if err != nil {
			return info, fmt.Errorf("%s: %s (param %d) %s: %w", fn.Name, param.Name, i, param.Type, err)
		}
	}
	return info, nil
}

// stubMem is directly manipulated by (generated) eBPF stub
type stubMem struct {
	// structs.HostLayout

	ncalls uint64
	res    [8]byte
	arg    [5][8]byte
	rc     [5]int64 // bpf_probe_read_kernel status for i-th arg

	// variable-length buffers for "indirect" params
}

func (l *stubInfo) memSize() int {
	sz := int(unsafe.Sizeof(stubMem{}))
	for _, arg := range l.arg {
		sz += arg.indirectSize()
	}
	return (sz + 7) & ^7
}

func (l *stubInfo) genStub(name string, typ *btf.Func, mem *ebpf.Map) []asm.Instruction {
	const (
		ncallsOffset = int(unsafe.Offsetof(stubMem{}.ncalls))
		resOffset    = int(unsafe.Offsetof(stubMem{}.res))
		argOffset    = int(unsafe.Offsetof(stubMem{}.arg))
		rcOffset     = int(unsafe.Offsetof(stubMem{}.rc))
	)
	_ = ([1]struct{}{})[ncallsOffset] // assert(ncallsOffset == 0)

	// Put pointer to memory into R6. It is preserved across function calls.
	memPtrR := asm.R6

	bytecode := []asm.Instruction{
		asm.LoadMapValue(memPtrR, mem.FD(), uint32(l.baseOffset)),
		asm.Mov.Imm(asm.R0, 1),
		asm.StoreXAdd(memPtrR, asm.R0, asm.DWord), // __sync_fetch_and_add(&ncalls, 1)
	}

	// Capture args.
	for i, arg := range l.arg[:l.nargs] {
		bytecode = append(bytecode,
			asm.StoreMem(memPtrR, int16(argOffset+i*8), asm.Register(int(asm.R1)+i), arg.asmSize()))
	}

	// Capture "indirect" args. Reload arg value stored previously,
	// since intervening bpf_probe_read_kernel() clobbers R0-R5.
	offset := int(unsafe.Sizeof(stubMem{}))
	for i, arg := range l.arg[:l.nargs] {
		if arg.indirect && arg.size > 0 {
			bytecode = append(bytecode,
				asm.LoadMem(asm.R3, memPtrR, int16(argOffset+i*8), asm.DWord),
				asm.Instruction{ // if r3 == 0x0 goto pc+5
					OpCode:   asm.OpCode(asm.JumpClass).SetJumpOp(asm.JEq).SetSource(asm.ImmSource),
					Dst:      asm.R3,
					Constant: 0,
					Offset:   +5,
				},
				asm.Mov.Reg(asm.R1, memPtrR),
				asm.Add.Imm(asm.R1, int32(offset)),
				asm.Mov.Imm(asm.R2, int32(arg.size)),
				asm.FnProbeReadKernel.Call(),
				asm.StoreMem(memPtrR, int16(rcOffset+i*8), asm.R0, asm.DWord),
			)
			offset += arg.size
		}
	}

	// Epilog.
	bytecode = append(bytecode,
		asm.LoadMem(asm.R0, memPtrR, int16(resOffset), l.res.asmSize()), // return res
		asm.Return(),
	)

	// Attach mandatory metadata.
	bytecode[0] = bytecode[0].WithSymbol(name).WithSource(asm.Comment("// stub " + name))
	if typ != nil {
		bytecode[0] = btf.WithFuncMetadata(bytecode[0], typ)
	}

	return bytecode
}

// rewriteProg instantiates stubs, eliminates sub programs that are no longer needed.
// Ex: A->B->C, B replaced with a stub, C no longer needed.
func rewriteProg(insn []asm.Instruction, stubs map[string]stubInfo, mem *ebpf.Map) []asm.Instruction {
	used := usedSubProgs(insn, stubs)
	bc, keep := make([]asm.Instruction, 0, len(insn)), true
	for i, insn := range insn {
		if sym := insn.Symbol(); sym != "" {
			_, isUsed := used[sym]
			isUsed = isUsed || i == 0
			stubInfo, isStub := stubs[sym]
			if isUsed && isStub {
				bc = append(bc, stubInfo.genStub(sym, btf.FuncMetadata(&insn), mem)...)
			}
			keep = isUsed && !isStub
		}
		if keep {
			bc = append(bc, insn)
		}
	}
	return bc
}

// usedSubProgs builds a set of subprograms that are still needed after stub instantiation.
func usedSubProgs(insn []asm.Instruction, stubs map[string]stubInfo) map[string]struct{} {
	used := make(map[string]struct{})
	for {
		nused, scan := len(used), true
		for i, insn := range insn {
			if sym := insn.Symbol(); sym != "" {
				_, isUsed := used[sym]
				isUsed = isUsed || i == 0
				_, isStub := stubs[sym]
				scan = isUsed && !isStub
			}
			if scan && insn.IsFunctionReference() {
				used[insn.Reference()] = struct{}{}
			}
		}
		if len(used) == nused {
			return used
		}
	}
}

// extractEbpfFuncs builds a complete set of functions plus associated btf typeinfo-s
func extractEbpfFuncs(spec *ebpf.CollectionSpec) map[string]*btf.Func {
	funcs := make(map[string]*btf.Func)
	for _, prog := range spec.Programs {
		for _, insn := range prog.Instructions {
			if name := insn.Symbol(); name != "" {
				funcs[name] = btf.FuncMetadata(&insn)
			}
		}
	}
	return funcs
}

type goFunc struct {
	ebpfName string
	val      reflect.Value
}

// extractGoFuncs extracts func() members recursively from val
func extractGoFuncs(val reflect.Value, btfFuncs map[string]*btf.Func) ([]goFunc, error) {
	var funcs []goFunc
	typ := val.Type()
	for i := range typ.NumField() {
		fval := val.Field(i)
		field := typ.Field(i)
		switch fval.Kind() {
		case reflect.Func:
			ebpfName := field.Tag.Get("ebpf")
			if err := checkGoFunc(fval, btfFuncs, ebpfName); err != nil {
				return nil, fmt.Errorf("%s, field %s: %w", typ, field.Name, err)
			}
			funcs = append(funcs, goFunc{ebpfName: ebpfName, val: fval})

		case reflect.Struct:
			nested, err := extractGoFuncs(fval, btfFuncs)
			if err != nil {
				return nil, err
			}
			funcs = append(funcs, nested...)

		default:
			return nil, fmt.Errorf("%s, field %s: unsupported type %s: expecting a func or a nested struct",
				typ, field.Name, field.Type)
		}
	}
	return funcs, nil
}

// checkGoFunc ensures that the func() member is a valid mock definition.
func checkGoFunc(val reflect.Value, btfFuncs map[string]*btf.Func, ebpfName string) error {
	if ebpfName == "" || strings.Contains(ebpfName, ",") {
		return fmt.Errorf("invalid function name %q, check \"ebpf:\" tag", ebpfName)
	}
	btfFunc, ok := btfFuncs[ebpfName]
	if !ok {
		return fmt.Errorf("eBPF function %q: not found", ebpfName)
	}
	if btfFunc == nil {
		return fmt.Errorf("eBPF function %q: no typeinfo", ebpfName)
	}
	btfFuncProto, ok := btfFunc.Type.(*btf.FuncProto)
	if !ok {
		return fmt.Errorf("eBPF function %q: malformed typeinfo", ebpfName)
	}
	funcTyp := val.Type()
	if funcTyp.NumIn() != len(btfFuncProto.Params) {
		return fmt.Errorf("expecting function with %d parameters", len(btfFuncProto.Params))
	}
	switch funcTyp.NumOut() {
	case 0:
	case 1:
		if !funcTyp.Out(0).ConvertibleTo(reflect.TypeOf(res{})) {
			return errors.New("expecting function returning Res[T]")
		}
	default:
		return errors.New("expecting function with 0 or 1 output parameters")
	}
	if !val.CanSet() {
		return errors.New("can't set")
	}
	return nil
}

// create patches func() member, creating a frontend on top of mock.expectCall() and mock.overrideResult().
func (f goFunc) create(m *mock) reflect.Value {
	typ := f.val.Type()
	return reflect.MakeFunc(typ, func(values []reflect.Value) []reflect.Value {
		m.t.Helper()
		args := make([]any, len(values))
		for i, val := range values {
			args[i] = val.Interface()
		}
		if err := m.expectCall(f.ebpfName, args); err != nil {
			m.t.Fatal(err)
		}
		if typ.NumOut() == 0 {
			return nil
		}
		return []reflect.Value{reflect.ValueOf(res{m: m, funcName: f.ebpfName}).Convert(typ.Out(0))}
	})
}
