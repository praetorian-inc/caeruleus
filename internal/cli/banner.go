package cli

import _ "embed"

// bannerArt is the Caeruleus wordmark shown atop the root help and the
// interactive shell. Kept in a sidecar .txt (embedded) because the art
// contains backticks and backslashes that would need escaping inline.
//
//go:embed banner.txt
var bannerArt string
