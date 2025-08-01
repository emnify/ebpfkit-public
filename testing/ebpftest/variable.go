package ebpftest

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/ebpf"
)

// VariableSet is a convenience wrapper for seting eBPF variables in
// tests.
func VariableSet(t *testing.T, v *ebpf.Variable, value any) {
	t.Helper()
	require.NoError(t, v.Set(value))
}

// VariableEqual asserts that eBPF variable has expected value.
// On failure, similarly to github.com/stretchr/testify/assert,
// the test continues.
func VariableEqual[Value any](t *testing.T, v *ebpf.Variable, value Value) bool {
	t.Helper()
	var current Value
	require.NoError(t, v.Get(&current))
	return assert.Equal(t, value, current)
}

// RequireVariableEqual asserts that eBPF variable has expected value.
// On failure, similarly to github.com/stretchr/testify/require,
// the test is aborted (via .FailNow).
func RequireVariableEqual[Value any](t *testing.T, v *ebpf.Variable, value Value) {
	t.Helper()
	var current Value
	require.NoError(t, v.Get(&current))
	require.Equal(t, value, current)
}
