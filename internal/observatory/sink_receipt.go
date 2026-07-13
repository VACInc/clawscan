package observatory

// clonePrivatePayloads isolates private stream ownership before correlation.
// For controlled-sink streams it is called only after the canonical typed
// receipt verifier succeeds. The analyzer independently bounds stream count and
// aggregate scanned bytes.
func clonePrivatePayloads(payloads ...[]byte) [][]byte {
	cloned := make([][]byte, len(payloads))
	for index, payload := range payloads {
		cloned[index] = append([]byte(nil), payload...)
	}
	return cloned
}
