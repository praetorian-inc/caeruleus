package cli

import (
	"fmt"
	"sort"

	"github.com/spf13/cobra"

	"caeruleus/internal/bluez"
)

var authBypassFlags struct {
	probeWrite bool
}

func newAssessAuthBypassCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "auth-bypass",
		Short: "What an unpaired attacker can read (and optionally write) on -b BDADDR",
		Long: `Drops any existing bond, connects unauthenticated, and attempts to read
every characteristic - classifying each as readable-without-auth,
auth-required, denied, or error. Values that look like secrets
(passwords, tokens, keys, flags) are escalated.

By default this is read-only and safe. With --probe-write it also writes
each characteristic's just-read value back to itself to test whether writes
are accepted without authentication; that is minimally invasive (same bytes)
but still exercises the write path, so it is opt-in.`,
		RunE: runAuthBypass,
	}
	c.Flags().BoolVar(&authBypassFlags.probeWrite, "probe-write", false,
		"also test writes by writing each readable value back to itself (opt-in; exercises the write path)")
	return c
}

func runAuthBypass(cmd *cobra.Command, args []string) error {
	addr, err := requireBdaddr()
	if err != nil {
		return err
	}
	ctx, cancel := ctxWithRootTimeout()
	defer cancel()

	// Guarantee an unauthenticated context: purge any stored bond so the
	// link below is unencrypted. Best-effort - a missing device is fine.
	if c, e := bluez.Dial(root.adapter); e == nil {
		_ = c.RemoveDevice(c.DevicePath(addr))
		c.Close()
	}

	s, err := openSession(ctx, addr, true)
	if err != nil {
		return err
	}
	defer s.close()

	res := assessResult{Address: addr, Test: "auth-bypass"}
	var readOK, authReq, denied, writeOK int

	chars := append([]bluez.GattObject(nil), s.tree.Characteristics...)
	sort.Slice(chars, func(i, j int) bool { return chars[i].Handle < chars[j].Handle })

	for _, ch := range chars {
		c := s.conn.Characteristic(ch.Path)
		canRead := propsCan(ch.Flags, "read")
		canWrite := propsCan(ch.Flags, "write") || propsCan(ch.Flags, "write-without-response")

		// --- read probe ---
		var lastValue []byte
		if canRead {
			preview, v, rerr := charValuePreview(c)
			switch classifyAccessErr(rerr) {
			case accessOK:
				readOK++
				lastValue = v
				sev := SevLow
				ascii := asciiize(v)
				if looksSensitive(ascii) {
					sev = SevHigh
				}
				res.Findings = append(res.Findings, Finding{
					Title:    "Characteristic readable without authentication",
					Severity: sev,
					Handle:   ch.Handle,
					UUID:     ch.UUID,
					Evidence: preview,
					Detail:   "Value retrieved over an unpaired, unencrypted link.",
				})
			case accessAuth:
				authReq++
			case accessDenied:
				denied++
			}
		}

		// --- write-back probe (opt-in) ---
		if authBypassFlags.probeWrite && canWrite && lastValue != nil {
			wt := bluez.WriteRequest
			if !propsCan(ch.Flags, "write") {
				wt = bluez.WriteCommand
			}
			werr := c.WriteValue(lastValue, wt)
			if classifyAccessErr(werr) == accessOK {
				writeOK++
				res.Findings = append(res.Findings, Finding{
					Title:    "Characteristic writable without authentication",
					Severity: SevMedium,
					Handle:   ch.Handle,
					UUID:     ch.UUID,
					Evidence: "write-back of current value accepted",
					Detail:   "An unpaired attacker can write this attribute (tested with its own value).",
				})
			}
		}
	}

	res.Summary = fmt.Sprintf("readable-unauth=%d auth-required=%d denied=%d writable-unauth=%d (of %d characteristics)",
		readOK, authReq, denied, writeOK, len(chars))
	return emitAssess(res)
}
