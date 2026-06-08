package cli

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/spf13/cobra"

	"caeruleus/internal/bluez"
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
		Short: "Security-assessment workflows over BLE primitives (recon lives at top level)",
		Long: `assess groups the active security tests that compose the read / write /
pair / listen primitives into a single deterministic pass and emit structured
findings (use -o json for the skill / report layer).

Subcommands:
  auth-bypass   what an unpaired attacker can read (and optionally write)
  encryption    whether pairing changes what is exposed (enforcement / fallback)
  wwr           write-without-response overflow + rapid-fire resilience
  dfu           detect a DFU service and whether entry is unauthenticated

Findings are data, not command failure: these exit 0 even when issues are
found. See 'caeruleus recon' for the passive profile + GATT audit.`,
	}
	c.AddCommand(
		newAssessAuthBypassCmd(),
		newAssessEncryptionCmd(),
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

// looksSensitive flags decoded values that resemble secrets, so a plain
// readable characteristic can be escalated above informational.
func looksSensitive(ascii string) bool {
	l := strings.ToLower(ascii)
	for _, k := range []string{"pass", "passwd", "password", "secret", "token",
		"admin", "cred", "flag{", "ble{", "apikey", "api_key", "bearer", "privkey", "private"} {
		if strings.Contains(l, k) {
			return true
		}
	}
	return false
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

// charByHandle resolves an ATT handle to a typed Characteristic within a
// session's enumerated tree, or nil when the handle is unknown.
func (s *session) charByHandle(h uint16) *bluez.Characteristic {
	if obj, ok := s.tree.ByHandle[h]; ok {
		return s.conn.Characteristic(obj.Path)
	}
	return nil
}

// charValuePreview reads a characteristic and returns a compact
// "hex (\"ascii\")" preview for use as finding evidence.
func charValuePreview(c *bluez.Characteristic) (string, []byte, error) {
	v, err := c.ReadValue(0)
	if err != nil {
		return "", nil, err
	}
	hexs := truncate(fmt.Sprintf("%x", v), 64)
	return fmt.Sprintf("%s (%q)", hexs, truncate(asciiize(v), 32)), v, nil
}

// --- shared output ------------------------------------------------------

// emitAssess renders an assessResult as JSON (machine path) or a sorted
// severity table (human path). Always returns nil for a clean exit code —
// findings are observations, not a failed command.
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

	fmt.Printf("# %s assessment — %s\n", res.Test, res.Address)
	if res.Summary != "" {
		fmt.Printf("%s\n", res.Summary)
	}
	if len(res.Findings) == 0 {
		fmt.Println("no findings")
		return nil
	}
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"SEV", "HANDLE", "UUID", "FINDING", "EVIDENCE"})
	for _, f := range res.Findings {
		h := ""
		if f.Handle != 0 {
			h = fmt.Sprintf("0x%04x", f.Handle)
		}
		t.AppendRow(table.Row{
			strings.ToUpper(string(f.Severity)),
			h,
			truncate(f.UUID, 36),
			f.Title,
			truncate(f.Evidence, 40),
		})
	}
	t.Render()
	return nil
}
