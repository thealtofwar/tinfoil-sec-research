//go:build gotdx_main

package gotdxcasefold

import (
	"time"

	"github.com/google/go-tdx-guest/verify"
)

// go-tdx-guest main (b0a2dd8, 2026-10-03): Options.Now is a *TimeSet.
func setNow(o *verify.Options) {
	n := time.Now()
	o.Now = &verify.TimeSet{PckCertChain: n, TcbInfo: n, QeIdentity: n, PckCrl: n, RootCaCrl: n}
}
