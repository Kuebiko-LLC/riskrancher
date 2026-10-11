package report

import (
	"fmt"
	"strconv"
	"strings"
)

// ExtractJSONField traverses an unmarshaled JSON object using dot notation.
func ExtractJSONField(data any, path string) string {
	if path == "" || data == nil {
		return ""
	}

	parts := strings.Split(path, ".")
	current := data

	for _, part := range parts {
		if current == nil {
			return ""
		}

		switch v := current.(type) {
		case map[string]any:
			val, ok := v[part]
			if !ok {
				return ""
			}
			current = val

		case []any:
			idx, err := strconv.Atoi(part)
			if err != nil || idx < 0 || idx >= len(v) {
				return ""
			}
			current = v[idx]

		default:
			return ""
		}
	}

	if current == nil {
		return ""
	}

	switch v := current.(type) {
	case string:
		return v
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(v)
	default:
		return fmt.Sprintf("%v", v)
	}
}
