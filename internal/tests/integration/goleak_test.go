package integration

import (
	"testing"

	"go.uber.org/goleak"
)

func TestMain(m *testing.M) {
	// glog's file sink starts a flush daemon in its init() that never exits;
	// it's pulled in transitively via dgraph-io/ristretto (used by badger).
	// hashicorp/golang-lru/v2/expirable.NewLRU spawns a background eviction
	// goroutine pulled in via go-tpm-tools/sdk/attest with no Close hook.
	goleak.VerifyTestMain(m,
		goleak.IgnoreAnyFunction("github.com/golang/glog.(*fileSink).flushDaemon"),
		goleak.IgnoreAnyFunction("github.com/hashicorp/golang-lru/v2/expirable.NewLRU[...].func1"),
	)
}
