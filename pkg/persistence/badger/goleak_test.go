package badger

import (
	"testing"

	"go.uber.org/goleak"
)

func TestMain(m *testing.M) {
	// glog's file sink starts a flush daemon in its init() that never exits;
	// it's pulled in transitively via dgraph-io/ristretto.
	goleak.VerifyTestMain(m,
		goleak.IgnoreAnyFunction("github.com/golang/glog.(*fileSink).flushDaemon"),
	)
}
