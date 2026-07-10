package cli

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
	"github.com/praetorian-inc/titus"
	"github.com/spf13/cobra"

	"github.com/praetorian-inc/caeruleus/internal/bluez"
)

// Severity grades a finding. Ordering (low->high) drives sorted output.
type Severity string

const (
	SevInfo     Severity = "info"
	SevLow      Severity = "low"
	SevMedium   Severity = "medium"
	SevHigh     Severity = "high"
	SevCritical Severity = "critical"
)

func sevRank(s Severity) int {
	switch s {
	case SevCritical:
		return 4
	case SevHigh:
		return 3
	case SevMedium:
		return 2
	case SevLow:
		return 1
	default:
		return 0
	}
}

// Finding is one observation from an assessment. It is intentionally flat so
// the JSON is trivial for the skill layer to correlate across runs.
type Finding struct {
	Title    string   `json:"title"`
	Severity Severity `json:"severity"`
	Handle   uint16   `json:"handle,omitempty"`
	UUID     string   `json:"uuid,omitempty"`
	Evidence string   `json:"evidence,omitempty"`
	Detail   string   `json:"detail,omitempty"`
}

// assessResult is the common envelope every `assess` subcommand emits.
type assessResult struct {
	Address  string    `json:"address"`
	Test     string    `json:"test"`
	Summary  string    `json:"summary,omitempty"`
	Findings []Finding `json:"findings"`
}

func newAssessCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "assess",
		Short: "Active security tests: auth, encryption, pairing, write-without-response, DFU",
		Long: `assess groups the active security tests that compose the read / write /
pair / listen primitives into a single deterministic pass and emit structured
findings (use -o json for the skill / report layer).

Subcommands:
  check-auth    what an unpaired attacker can read (read-only by default; --probe-write for writes)
  encryption    whether pairing changes what is exposed (enforcement / fallback)
  pairing       SMP feature-exchange + downgrade probe (raw, root, takes over adapter)
  wwr           write-without-response overflow + rapid-fire resilience
  dfu           detect a DFU service and whether entry is unauthenticated

Findings are data, not command failure: these exit 0 even when issues are
found. See 'caeruleus recon' for the passive profile + GATT audit.`,
	}
	c.AddCommand(
		newAssessCheckAuthCmd(),
		newAssessEncryptionCmd(),
		newAssessPairingCmd(),
		newAssessWWRCmd(),
		newAssessDFUCmd(),
	)
	return c
}

// --- shared classification helpers --------------------------------------

// accessClass buckets the outcome of a read/write attempt.
type accessClass string

const (
	accessOK     accessClass = "ok"            // operation succeeded
	accessAuth   accessClass = "auth_required" // blocked by pairing/encryption/authorization
	accessDenied accessClass = "denied"        // operation not permitted by the attribute
	accessError  accessClass = "error"         // transient / unexpected
)

// classifyAccessErr maps a BlueZ/ATT error to an accessClass. BlueZ surfaces
// the ATT error code as the D-Bus error message, so we match on substrings.
func classifyAccessErr(err error) accessClass {
	if err == nil {
		return accessOK
	}
	s := strings.ToLower(err.Error())
	switch {
	case containsAnyLower(s, "not authorized", "authoriz", "not paired",
		"insufficient authentication", "insufficient encryption", "authentication"):
		return accessAuth
	// A declared-readable/writable attribute whose access cannot complete on an
	// unpaired link manifests as a timeout (BlueZ stuck elevating security with
	// no pairing agent) or an "in progress" follow-on error. For assessment
	// purposes that is an authentication gate, not a transient fault.
	case containsAnyLower(s, "context deadline exceeded", "operation already in progress", "in progress"):
		return accessAuth
	case containsAnyLower(s, "not permitted", "read not permitted",
		"write not permitted", "not supported", "notsupported"):
		return accessDenied
	default:
		return accessError
	}
}

func containsAnyLower(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// secret detection is backed by Praetorian Titus, which carries ~500 rules
// for structured secrets (API keys, tokens, private keys). The scanner loads
// its rule set once and is reused for the life of the process.
var (
	secretScannerOnce sync.Once
	secretScanner     *titus.Scanner
)

func secretDetector() *titus.Scanner {
	secretScannerOnce.Do(func() {
		s, err := titus.NewScanner()
		if err != nil {
			logf("titus scanner init failed; secret detection disabled: %v", err)
			return
		}
		secretScanner = s
	})
	return secretScanner
}

// detectSecret runs a characteristic value through Titus and returns the name
// of the first matching rule, or ("", false) when nothing matches or the
// scanner is unavailable. Titus targets structured secrets (keys/tokens), not
// arbitrary password-like text, so a finding here is high-confidence.
func detectSecret(value []byte) (string, bool) {
	s := secretDetector()
	if s == nil || len(value) == 0 {
		return "", false
	}
	matches, err := s.ScanBytes(value)
	if err != nil || len(matches) == 0 {
		return "", false
	}
	return matches[0].RuleName, true
}

// credPairRe matches a "user:secret" pair such as "admin:password123".
var credPairRe = regexp.MustCompile(`^[A-Za-z0-9._@-]{1,32}:[^\s:]{4,}$`)

// looksLikeCredential is a light heuristic for plaintext credentials/secrets
// that Titus's structured-secret rules do not flag (e.g. a username:password
// pair, or text containing a password/secret keyword or a PEM key header).
// Used as a lower-confidence backstop behind detectSecret.
func looksLikeCredential(ascii string) bool {
	s := strings.TrimSpace(ascii)
	if s == "" {
		return false
	}
	l := strings.ToLower(s)
	for _, k := range []string{"password", "passwd", "pwd=", "passphrase",
		"secret", "bearer ", "api key", "apikey", "api_key", "credential",
		"private key", "begin rsa", "begin ec", "begin openssh", "begin private"} {
		if strings.Contains(l, k) {
			return true
		}
	}
	return credPairRe.MatchString(s)
}

// isSIGBaseUUID reports whether a 128-bit UUID is in the Bluetooth SIG base
// range (i.e. an adopted 16-bit UUID), as opposed to a vendor/custom service.
func isSIGBaseUUID(u string) bool {
	u = strings.ToLower(u)
	return strings.HasPrefix(u, "0000") && strings.HasSuffix(u, "-0000-1000-8000-00805f9b34fb")
}

// readSIG16 reads the first characteristic with the given adopted 16-bit UUID
// and returns its value as a trimmed printable string.
func (s *session) readSIG16(u16 uint16) (string, bool) {
	full := fmt.Sprintf("0000%04x-0000-1000-8000-00805f9b34fb", u16)
	chs := s.tree.ByUUID[full]
	if len(chs) == 0 {
		return "", false
	}
	v, err := s.conn.Characteristic(chs[0].Path).ReadValue(0)
	if err != nil || len(v) == 0 {
		return "", false
	}
	return strings.TrimSpace(strings.Trim(asciiize(v), ". ")), true
}

// readSIG16Raw reads the first characteristic with the given adopted 16-bit
// UUID and returns the raw bytes.
func (s *session) readSIG16Raw(u16 uint16) ([]byte, error) {
	full := fmt.Sprintf("0000%04x-0000-1000-8000-00805f9b34fb", u16)
	chs := s.tree.ByUUID[full]
	if len(chs) == 0 {
		return nil, fmt.Errorf("characteristic 0x%04x not found", u16)
	}
	return s.conn.Characteristic(chs[0].Path).ReadValue(0)
}

// charByHandle resolves an ATT handle to a typed Characteristic within a
// session's enumerated tree, or nil when the handle is unknown.
func (s *session) charByHandle(h uint16) *bluez.Characteristic {
	if obj, ok := s.tree.ByHandle[h]; ok {
		return s.conn.Characteristic(obj.Path)
	}
	return nil
}

// charValuePreview reads a characteristic and returns a "hex (\"ascii\")"
// rendering of the value for use as finding evidence, plus the raw bytes.
func charValuePreview(c *bluez.Characteristic) (string, []byte, error) {
	v, err := c.ReadValue(0)
	if err != nil {
		return "", nil, err
	}
	return valuePreview(v), v, nil
}

// valuePreview renders bytes as evidence. Values up to previewCap bytes are
// shown in full (so credentials / tokens / PII are never cut); longer blobs
// show the first previewCap bytes with a "+N bytes" note rather than dumping
// hundreds of hex characters into a table cell.
func valuePreview(v []byte) string {
	const previewCap = 64
	shown, suffix := v, ""
	if len(v) > previewCap {
		shown = v[:previewCap]
		suffix = fmt.Sprintf(" +%d bytes", len(v)-previewCap)
	}
	return fmt.Sprintf("%x (%q)%s", shown, asciiize(shown), suffix)
}

// --- shared output ------------------------------------------------------

// emitAssess renders an assessResult as JSON (machine path) or a sorted
// severity table (human path). Always returns nil for a clean exit code - // findings are observations, not a failed command.
func emitAssess(res assessResult) error {
	// Highest severity first, then by handle for stable ordering.
	sort.SliceStable(res.Findings, func(i, j int) bool {
		ri, rj := sevRank(res.Findings[i].Severity), sevRank(res.Findings[j].Severity)
		if ri != rj {
			return ri > rj
		}
		return res.Findings[i].Handle < res.Findings[j].Handle
	})

	if formatIsJSON() {
		return emitJSON(res)
	}

	fmt.Printf("# %s assessment - %s\n", res.Test, res.Address)
	if res.Summary != "" {
		fmt.Printf("%s\n", res.Summary)
	}
	if len(res.Findings) == 0 {
		fmt.Println("no findings")
		return nil
	}
	t := newTable()
	t.AppendHeader(table.Row{"SEV", "HANDLE", "UUID", "FINDING", "EVIDENCE"})

	// On a terminal, bound the wrappable columns so the box fits the width.
	// Evidence is never truncated - it is the point of the finding - so when
	// space is tight the FINDING (title) and UUID columns wrap instead, and
	// evidence gets the larger share of what remains. Piped output (width 0)
	// is left unconstrained so evidence stays on one line for grep.
	if w := termWidth(); w > 0 {
		avail := w - 35 // SEV(8) + HANDLE(8) + 5-column decoration(17), with margin
		if avail < 24 {
			avail = 24
		}
		uuidW := avail * 18 / 100
		if uuidW < 8 {
			uuidW = 8
		} else if uuidW > 20 {
			uuidW = 20
		}
		rem := avail - uuidW
		evidenceW := rem * 3 / 5 // evidence prioritised over the finding text
		findingW := rem - evidenceW
		t.SetColumnConfigs([]table.ColumnConfig{
			{Number: 3, WidthMax: uuidW, WidthMaxEnforcer: text.WrapText},
			{Number: 4, WidthMax: findingW, WidthMaxEnforcer: text.WrapText},
			{Number: 5, WidthMax: evidenceW, WidthMaxEnforcer: text.WrapText},
		})
		t.SetAllowedRowLength(w)
	}

	for _, f := range res.Findings {
		h := ""
		if f.Handle != 0 {
			h = fmt.Sprintf("0x%04x", f.Handle)
		}
		t.AppendRow(table.Row{
			strings.ToUpper(string(f.Severity)),
			h,
			shortUUID(f.UUID),
			f.Title,
			f.Evidence,
		})
	}
	t.Render()
	return nil
}
