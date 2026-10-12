//go:build poc && !pocfix

package manager

// Shipped signature (manager/metrics.go:56): the attested TLS key is not passed in.
func pocNewEnclaveMetrics(host, model, _ string) *enclaveMetrics { return newEnclaveMetrics(host, model) }
