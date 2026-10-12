package client

// PoCSetGroundTruth is a LOCAL-PoC-ONLY hook: it installs a verified state as
// if attestation had succeeded, replacing only the fetch+verify step.
func PoCSetGroundTruth(s *SecureClient, gt *GroundTruth) {
	s.stateMu.Lock()
	s.groundTruth = gt
	s.stateMu.Unlock()
}
