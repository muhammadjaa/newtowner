package util

// TruncateString truncates a string to a max length and adds "..." if truncated.
// If maxLength is less than 3, it will truncate to maxLength without adding "...".
func TruncateString(s string, maxLength int) string {
	if len(s) <= maxLength {
		return s
	}
	if maxLength < 3 {
		if maxLength < 0 {
			maxLength = 0
		}
		return s[:maxLength]
	}
	return s[:maxLength-3] + "..."
}

// GetMapKeys returns a slice of keys from a map.
// This is a generic function that works with any comparable key type and any value type.
func GetMapKeys[K comparable, V any](m map[K]V) []K {
	keys := make([]K, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
