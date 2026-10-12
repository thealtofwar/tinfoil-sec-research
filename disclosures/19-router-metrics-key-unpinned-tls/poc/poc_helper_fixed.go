//go:build poc && pocfix

package manager

// Signature after fix-pin-metrics.patch: the attested TLS key fingerprint is pinned.
func pocNewEnclaveMetrics(host, model, fp string) *enclaveMetrics { return newEnclaveMetrics(host, model, fp) }
