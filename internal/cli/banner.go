package cli

import (
	_ "embed"
	"strings"
)

// bannerArt is the Caeruleus wordmark shown atop the root help and the
// interactive shell. Kept in a sidecar .txt (embedded) because the art
// contains backticks and backslashes that would need escaping inline.
//
//go:embed banner.txt
var bannerArt string

// bannerMaxWidth is the width (in columns) of the widest line of the wordmark.
func bannerMaxWidth() int {
	max := 0
	for _, line := range strings.Split(bannerArt, "\n") {
		if n := len([]rune(line)); n > max {
			max = n
		}
	}
	return max
}

// showBanner reports whether the terminal is wide enough to render the
// wordmark without wrapping it. Returns false when the width is unknown
// (piped / redirected), so non-interactive output stays clean.
func showBanner() bool {
	w := termWidth()
	return w > 0 && w >= bannerMaxWidth()
}
