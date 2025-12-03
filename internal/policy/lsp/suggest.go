package lsp

// suggestName returns the closest known name within distance 2.
func suggestName(name string, known []string) (string, bool) {
	best := ""
	bestDist := 3
	for _, k := range known {
		d := levenshteinDistance(name, k)
		if d < bestDist {
			bestDist = d
			best = k
		}
	}
	if best == "" {
		return "", false
	}
	return best, true
}
