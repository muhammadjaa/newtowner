package util

import (
	"bufio"
	"os"
	"regexp"
	"strings"
)

// ReadURLsFromFile reads a file line by line, trims whitespace from each line,
// and returns a slice of non-empty strings (URLs).
func ReadURLsFromFile(filePath string) ([]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var urls []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			urls = append(urls, line)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return urls, nil
}

var invalidFilenameChars = regexp.MustCompile(`[\\/:\*\?"<>\|\s]`) // Added \s to also replace spaces

// SanitizeFilename removes or replaces characters that are invalid in filenames.
func SanitizeFilename(input string) string {
	// Replace invalid characters with an underscore
	sanitized := invalidFilenameChars.ReplaceAllString(input, "_")
	// Replace multiple underscores with a single one
	sanitized = regexp.MustCompile(`_+`).ReplaceAllString(sanitized, "_")
	// Trim leading/trailing underscores or spaces that might have been created or were already there
	sanitized = strings.Trim(sanitized, "_ ")
	return sanitized
}
