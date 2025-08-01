package ebpftest

import (
	"os"
	"strconv"
	"testing"
)

// RequirePriveleges skips the test if not currently running as root.
// Set EBPFTEST_IS_PRIVELEGED=<bool> in the environment to override.
func RequirePrivileges(t testing.TB) {
	t.Helper()
	const ebpftestIsPrivileged = "EBPFTEST_IS_PRIVILEGED"
	val, ok := os.LookupEnv(ebpftestIsPrivileged)
	switch {
	case ok:
		isPriv, err := strconv.ParseBool(val)
		if err != nil {
			t.Fatalf("please check %s in the environment: %v", ebpftestIsPrivileged, err)
		}
		if isPriv {
			return
		}
		fallthrough
	case os.Getuid() != 0:
		t.Skip("Requires superuser privileges (sudo)")
	}
}
