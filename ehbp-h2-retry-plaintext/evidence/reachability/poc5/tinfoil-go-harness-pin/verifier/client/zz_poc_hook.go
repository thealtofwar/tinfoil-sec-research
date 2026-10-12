package client

// PoC-ONLY hook (local copy of tinfoil-go v0.15.4-0.20260828072713-251feb041ce8,
// the version confidential-tinfoil-harness pins). Presets the result a
// successful Verify() would have stored, so no attestation traffic is needed.
func PoCPresetGroundTruth(s *SecureClient, gt *GroundTruth) {
	s.stateMu.Lock()
	s.groundTruth = gt
	s.stateMu.Unlock()
}
