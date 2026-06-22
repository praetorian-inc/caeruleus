package cli

import (
	"fmt"
	"sort"

	"github.com/spf13/cobra"

	"caeruleus/internal/bluez"
)

var checkAuthFlags struct {
	probeWrite bool
}

func newAssessCheckAuthCmd() *cobra.Command {
	c := &cobra.Command{
		Use:     "check-auth",
		Aliases: []string{"auth-bypass"},
		Short:   "Read-only by default: what an unpaired attacker can read on -b BDADDR (add --probe-write for write checks)",
		Long: `Drops any existing bond, connects unauthenticated, and attempts to read
every characteristic - classifying each as readable-without-auth,
auth-required, denied, or error. Read values are scanned with Praetorian
Titus; a value that matches a secret rule (API key, token, private key, ...)
is escalated to high.

By default this is read-only and safe. With --probe-write it also writes
each characteristic's just-read value back to itself to test whether writes
are accepted without authentication; that is minimally invasive (same bytes)
but still exercises the write path, so it is opt-in.`,
		RunE: runCheckAuth,
	}
	c.Flags().BoolVar(&checkAuthFlags.probeWrite, "probe-write", false,
		"also test writes by writing each readable value back to itself (opt-in; exercises the write path)")
	return c
}

func runCheckAuth(cmd *cobra.Command, args []string) error {
	addr, err := requireBdaddr()
	if err != nil {
		return err
	}
	ctx, cancel := ctxWithRootTimeout()
	defer cancel()

	if checkAuthFlags.probeWrite {
		statusf("check-auth: read + write probes (--probe-write)")
	} else {
		statusf("check-auth: read-only (add --probe-write to also test writes)")
	}

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

	res := assessResult{Address: addr, Test: "check-auth"}
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
				title := "Characteristic readable without authentication"
				detail := "Value retrieved over an unpaired, unencrypted link."
				if rule, ok := detectSecret(v); ok {
					sev = SevHigh
					title = "Secret readable without authentication"
					detail = fmt.Sprintf("Titus matched rule %q; value read over an unpaired, unencrypted link.", rule)
				} else if looksLikeCredential(asciiize(v)) {
					sev = SevHigh
					title = "Likely-sensitive value readable without authentication"
					detail = "Value matches a credential/secret pattern (heuristic); read over an unpaired, unencrypted link."
				}
				res.Findings = append(res.Findings, Finding{
					Title:    title,
					Severity: sev,
					Handle:   ch.Handle,
					UUID:     ch.UUID,
					Evidence: preview,
					Detail:   detail,
				})
			case accessAuth:
				authReq++
			case accessDenied:
				denied++
			}
		}

		// --- write-back probe (opt-in) ---
		if checkAuthFlags.probeWrite && canWrite && lastValue != nil {
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
