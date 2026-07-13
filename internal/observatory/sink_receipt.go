package observatory

// clonePrivateSinkPayloads adapts payload byte slices extracted from an already
// parsed and verified typed sink receipt into the analyzer's private input. It
// deliberately knows nothing about receipt encoding or identity. The canonical
// mock-egress parser owns those checks, and the analyzer independently bounds
// stream count and aggregate scanned bytes.
func clonePrivateSinkPayloads(payloads ...[]byte) [][]byte {
	cloned := make([][]byte, len(payloads))
	for index, payload := range payloads {
		cloned[index] = append([]byte(nil), payload...)
	}
	return cloned
}
