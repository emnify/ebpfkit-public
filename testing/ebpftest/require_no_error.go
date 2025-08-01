package ebpftest

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/EMnify/ebpfkit"
)

// RequireNoError aborts the test if the err value is non-nil, similarly
// to github.com/stretchr/testify/require. Additionally, it dumps eBPF
// verifier logs.
func RequireNoError(t *testing.T, err error) {
	t.Helper()
	if log := ebpfkit.VerifierLog(err); log != "" {
		t.Cleanup(func() { t.Log(log) })
	}
	require.NoError(t, err)
}
