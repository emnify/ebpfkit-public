package ebpftest

import (
	"os"
	"strconv"
	"testing"
)

// SkipIfIncapable skips the test if not currently running as root.
// Set EBPFTEST_IS_CAPABLE=<bool> in the environment to override.
func SkipIfIncapable(t testing.TB) {
	t.Helper()
	const ebpftestIsCapable = "EBPFTEST_IS_CAPABLE"
	val, ok := os.LookupEnv(ebpftestIsCapable)
	switch {
	case ok:
		isPriv, err := strconv.ParseBool(val)
		if err != nil {
			t.Fatalf("please check %s in the environment: %v", ebpftestIsCapable, err)
		}
		if isPriv {
			return
		}
		fallthrough
	case os.Getuid() != 0:
		t.Skip("Requires superuser privileges (sudo)")
	}
}
