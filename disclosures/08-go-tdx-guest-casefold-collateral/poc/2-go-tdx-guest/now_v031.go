//go:build !gotdx_main

package gotdxcasefold

import (
	"time"

	"github.com/google/go-tdx-guest/verify"
)

// go-tdx-guest v0.3.1: Options.Now is a time.Time.
func setNow(o *verify.Options) { o.Now = time.Now() }
