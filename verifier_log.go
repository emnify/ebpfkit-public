package ebpfkit

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
)

// VerifierLog extracts eBPF verifier log from the supplied error.
// Note: cilium/ebpf attempts to condense verifier logs when displaying
// errors which often omits important details.
func VerifierLog(err error) string {
	var ve *ebpf.VerifierError
	if errors.As(err, &ve) {
		return fmt.Sprintf("%+v", ve)
	}
	return ""
}
