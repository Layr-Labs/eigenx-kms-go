package kmsClient

import (
	"testing"

	"go.uber.org/goleak"
)

func TestMain(m *testing.M) {
	// hashicorp/golang-lru/v2/expirable.NewLRU spawns a background eviction
	// goroutine that lives for the process lifetime. It is started during
	// package init of an indirect dependency (go-tpm-tools/sdk/attest) and
	// has no Close hook exposed to us, so we ignore it.
	goleak.VerifyTestMain(m,
		goleak.IgnoreAnyFunction("github.com/hashicorp/golang-lru/v2/expirable.NewLRU[...].func1"),
	)
}
