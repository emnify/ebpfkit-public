# ebpftest

The `ebpftest` package contains golang utilities and helpers that simplify the testing of eBPF programs from golang userpace.

This package contains:
- `Mock` that brings mocking functionality to eBPF
- helpers to be used in tests, such as `RequireVariableEqual` and `RequireNoError`


## Effortlessly mocking eBPF programs

This package allows golang tests to replace a eBPF program or sub-program (eBPF function) on-demand with a stub, without having to modify eBPF code.
In addition, the user can:
- assert that the mock has been called 
- assert input arguments
- specify the return value of the mock


### Usage

The following example will replace eBPF functions `foo` and `bar` with mocks. 
```golang
func Test(t *testing.T) {

    type FunctionsToMock struct {
        Foo func()         `ebpf:"foo"`
        Bar func(any, any) `ebpf:"bar"`
    }

    collectionSpec = <specs of the eBPF programs provided by Cilium/ebpf>
    mock = ebpftest.NewMock[FunctionsToMock](t, collectionSpec)
}
```

One can then set the expectation that a mock gets called:
```golang
mock.Expect().Foo()
```

One can also set expectations on all (or some) of the input arguments
```golang
mock.Expect().Bar(uint32(42), ebpftest.Any)
```

Mocks return 0 by default. One can set a different return value by declaring a function with `ebpftest.Res[T]` result:
```golang
type FunctionsToMock struct {
    Foo func() ebpftest.Res[uint32] `ebpf:"foo"`
}

mock.Expect().Foo().Return(42)
```

### Limitations
- can't mock inlined functions.
- mocked calls are evaluated once. If the user wants to setup another expectation on a mock `m`, they can call `m.Reset()`, followed by a new `m.Expect()`
- mocks are simple stubs, can't have custom eBPF code as part of the mock (i.e. no equivalent of `.Do` like in `gomock`).
