package cli

import (
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"unicode"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
	"github.com/spf13/cobra"

	"github.com/praetorian-inc/caeruleus/internal/bluez"
)

var enumerateFlags struct {
	readValues bool
	maxLen     int
	compact    bool
}

func newEnumerateCmd() *cobra.Command {
	c := &cobra.Command{
		Use:     "enumerate",
		Aliases: []string{"enum"},
		Short:   "Print a device's full GATT tree as a table (--values also reads each characteristic)",
		RunE:    runEnumerate,
	}
	c.Flags().BoolVar(&enumerateFlags.readValues, "values", false, "read each readable characteristic and include its value (slow; opt in only)")
	c.Flags().IntVar(&enumerateFlags.maxLen, "max-len", 64, "truncate displayed values to this many bytes")
	c.Flags().BoolVar(&enumerateFlags.compact, "compact", false, "emit one key=value line per characteristic instead of the wide table (token-efficient for scripts / LLMs)")
	return c
}

type enumRow struct {
	Service        string    `json:"service"`
	ServiceHandle  uint16    `json:"service_handle"`
	CharHandle     uint16    `json:"char_handle"`
	CharUUID       string    `json:"char_uuid"`
	Properties     string    `json:"properties"`
	ValueHex       string    `json:"value_hex,omitempty"`
	ValueASCII     string    `json:"value_ascii,omitempty"`
	DescriptorRows []descRow `json:"descriptors,omitempty"`
}

type descRow struct {
	Handle uint16 `json:"handle"`
	UUID   string `json:"uuid"`
	Value  string `json:"value,omitempty"`
}

func runEnumerate(cmd *cobra.Command, args []string) error {
	addr, err := requireBdaddr()
	if err != nil {
		return err
	}
	logf("enumerate %s (values=%v, compact=%v, max-len=%d)",
		addr, enumerateFlags.readValues, enumerateFlags.compact, enumerateFlags.maxLen)
	ctx, cancel := ctxWithRootTimeout()
	defer cancel()

	s, err := openSession(ctx, addr, true)
	if err != nil {
		return err
	}
	defer s.close()

	logf("building enumeration rows (read values=%v)", enumerateFlags.readValues)
	rows := buildEnumRows(s, enumerateFlags.readValues)
	logf("enumerated %d characteristics", len(rows))
	if formatIsJSON() {
		return emitJSON(rows)
	}

	if enumerateFlags.compact {
		// One key=value line per characteristic; descriptors prefixed.
		// Cuts the per-row width from ~150 chars (table) to ~60-90 chars
		// (line) and removes column borders entirely. Better for grep,
		// pipes, and LLM consumption.
		for _, r := range rows {
			line := fmt.Sprintf("svc=0x%04x chr=0x%04x uuid=%s props=%s",
				r.ServiceHandle, r.CharHandle, r.CharUUID, r.Properties)
			if r.ValueHex != "" {
				line += fmt.Sprintf(" hex=%s ascii=%q",
					truncate(r.ValueHex, enumerateFlags.maxLen*2),
					truncate(r.ValueASCII, enumerateFlags.maxLen))
			}
			fmt.Println(line)
			for _, d := range r.DescriptorRows {
				dline := fmt.Sprintf("  desc=0x%04x uuid=%s", d.Handle, d.UUID)
				if d.Value != "" {
					dline += fmt.Sprintf(" hex=%s", d.Value)
				}
				fmt.Println(dline)
			}
		}
		return nil
	}

	t := newTable()
	t.AppendHeader(table.Row{"SVC HND", "CHR HND", "CHR UUID", "PROPS", "HEX", "ASCII"})

	// On a real terminal, bound the wide columns so the rendered box never
	// exceeds the terminal width - otherwise the terminal hard-wraps each line
	// and the box borders shatter. Piped/redirected output (width 0) is left
	// unconstrained so files and grep get full, single-line values.
	if w := termWidth(); w > 0 {
		// Size the wrappable columns so the natural table width fits inside w
		// (otherwise SetAllowedRowLength would chop the right border off).
		// Budget: SVC HND(7) + CHR HND(10) + PROPS(9) + 6-column decoration(19)
		// = 45, with a 2-col safety margin. Whatever's left is split across the
		// UUID / HEX / ASCII columns, which wrap rather than overflow.
		avail := w - 47
		if avail < 18 {
			avail = 18
		}
		// UUID ~30% (adopted shrink to 0xXXXX; custom 128-bit wraps), clamped to
		// the header width .. full-UUID range.
		uuidW := avail * 3 / 10
		if uuidW < 8 {
			uuidW = 8
		} else if uuidW > 36 {
			uuidW = 36
		}
		// Split the remainder favouring ASCII over HEX: keep the decoded text
		// readable on one line and let the hex dump (twice as wide per byte, so
		// the cheapest to wrap) absorb the squeeze.
		valSpace := avail - uuidW
		if valSpace < 10 {
			valSpace = 10
		}
		asciiW := valSpace * 2 / 3
		hexW := valSpace - asciiW
		t.SetColumnConfigs([]table.ColumnConfig{
			{Number: 3, WidthMax: uuidW, WidthMaxEnforcer: text.WrapText},
			{Number: 4, WidthMax: 9, WidthMaxEnforcer: text.WrapText},
			{Number: 5, WidthMax: hexW, WidthMaxEnforcer: text.WrapText},
			{Number: 6, WidthMax: asciiW, WidthMaxEnforcer: text.WrapText},
		})
		t.SetAllowedRowLength(w)
	}

	for _, r := range rows {
		t.AppendRow(table.Row{
			fmt.Sprintf("0x%04x", r.ServiceHandle),
			fmt.Sprintf("0x%04x", r.CharHandle),
			shortUUID(r.CharUUID),
			r.Properties,
			truncate(r.ValueHex, enumerateFlags.maxLen*3),
			truncate(r.ValueASCII, enumerateFlags.maxLen),
		})
		for _, d := range r.DescriptorRows {
			t.AppendRow(table.Row{
				"",
				fmt.Sprintf("  ↳ 0x%04x", d.Handle),
				text.FgHiBlack.Sprint(shortUUID(d.UUID)),
				text.FgHiBlack.Sprint("desc"),
				text.FgHiBlack.Sprint(d.Value),
				"",
			})
		}
	}
	t.Render()
	return nil
}

func buildEnumRows(s *session, readValues bool) []enumRow {
	// Build service-by-path map so we can locate the owning service of a char.
	svcs := map[string]bluez.GattObject{}
	for _, sv := range s.tree.Services {
		svcs[string(sv.Path)] = sv
	}

	// Descriptors keyed by parent characteristic path.
	descs := map[string][]bluez.GattObject{}
	for _, d := range s.tree.Descriptors {
		descs[string(d.Parent)] = append(descs[string(d.Parent)], d)
	}

	// Sort characteristics by handle for stable output.
	chars := append([]bluez.GattObject(nil), s.tree.Characteristics...)
	sort.Slice(chars, func(i, j int) bool { return chars[i].Handle < chars[j].Handle })

	var rows []enumRow
	for _, ch := range chars {
		parent := svcs[string(ch.Parent)]
		row := enumRow{
			Service:       parent.UUID,
			ServiceHandle: parent.Handle,
			CharHandle:    ch.Handle,
			CharUUID:      ch.UUID,
			Properties:    formatProps(ch.Flags),
		}
		if readValues && propsCan(ch.Flags, "read") {
			logf("reading characteristic 0x%04x (%s)", ch.Handle, ch.UUID)
			c := s.conn.Characteristic(ch.Path)
			if v, err := c.ReadValue(0); err == nil {
				row.ValueHex = hex.EncodeToString(v)
				row.ValueASCII = asciiize(v)
				logf("read 0x%04x: %d bytes", ch.Handle, len(v))
			} else {
				logf("read 0x%04x failed: %v", ch.Handle, err)
			}
		}
		for _, d := range descs[string(ch.Path)] {
			dr := descRow{Handle: d.Handle, UUID: d.UUID}
			desc := s.conn.Descriptor(d.Path)
			if v, err := desc.ReadValue(0); err == nil && len(v) > 0 {
				dr.Value = hex.EncodeToString(v)
			}
			row.DescriptorRows = append(row.DescriptorRows, dr)
		}
		rows = append(rows, row)
	}
	return rows
}

func formatProps(flags []string) string {
	if len(flags) == 0 {
		return ""
	}
	short := []string{}
	for _, f := range flags {
		switch f {
		case "read":
			short = append(short, "R")
		case "write":
			short = append(short, "W")
		case "write-without-response":
			short = append(short, "WC")
		case "notify":
			short = append(short, "N")
		case "indicate":
			short = append(short, "I")
		case "broadcast":
			short = append(short, "B")
		case "authenticated-signed-writes":
			short = append(short, "AS")
		case "reliable-write":
			short = append(short, "RW")
		case "writable-auxiliaries":
			short = append(short, "WA")
		case "encrypt-read":
			short = append(short, "ER")
		case "encrypt-write":
			short = append(short, "EW")
		case "encrypt-authenticated-read":
			short = append(short, "EAR")
		case "encrypt-authenticated-write":
			short = append(short, "EAW")
		default:
			short = append(short, f)
		}
	}
	return strings.Join(short, ",")
}

// shortUUID renders adopted (SIG-base) 128-bit UUIDs in their compact 0xXXXX
// form for display; custom/vendor UUIDs are returned unchanged. Display-only - // the JSON output keeps the full canonical UUID.
func shortUUID(u string) string {
	if len(u) >= 8 && isSIGBaseUUID(u) {
		return "0x" + strings.ToUpper(u[4:8])
	}
	return u
}

func propsCan(flags []string, target string) bool {
	for _, f := range flags {
		if f == target {
			return true
		}
	}
	return false
}

func asciiize(b []byte) string {
	var out strings.Builder
	for _, c := range b {
		r := rune(c)
		if c == '\n' || c == '\r' || c == '\t' {
			out.WriteByte(' ')
			continue
		}
		if c >= 0x20 && c < 0x7f && unicode.IsPrint(r) {
			out.WriteRune(r)
		} else {
			out.WriteByte('.')
		}
	}
	return out.String()
}

func truncate(s string, n int) string {
	if n <= 0 || len(s) <= n {
		return s
	}
	if n <= 1 {
		return "…"
	}
	return s[:n-1] + "…"
}
