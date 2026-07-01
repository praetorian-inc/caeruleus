package cli

import (
	"fmt"
	"sort"

	"github.com/spf13/cobra"

	"github.com/praetorian-inc/caeruleus/internal/bluez"
)

func newAssessEncryptionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "encryption",
		Short: "Whether pairing changes what -b BDADDR exposes (enforcement / fallback)",
		Long: `Three-phase encryption-enforcement test:

  A. Baseline: drop any bond and read every readable characteristic over an
     unauthenticated link, recording which succeed vs require authentication.
  B. Pairing: attempt to pair. If the peripheral refuses pairing, it has no
     way to enforce link encryption - everything readable in A is permanently
     exposed (reported here).
  C. Enforcement / fallback: if pairing succeeded, re-read the characteristics
     that required auth (they should now succeed = enforcement), then unpair
     and re-read them - anything still readable is a legacy-fallback weakness.`,
		RunE: runAssessEncryption,
	}
}

func runAssessEncryption(cmd *cobra.Command, args []string) error {
	addr, err := requireBdaddr()
	if err != nil {
		return err
	}
	res := assessResult{Address: addr, Test: "encryption"}

	// --- Phase A: unauthenticated baseline ---
	forgetDevice(addr) // ensure no bond
	baseline, uuidByHandle, err := readBaseline(addr)
	if err != nil {
		return err
	}
	var okCount, authCount int
	for _, cl := range baseline {
		switch cl {
		case accessOK:
			okCount++
		case accessAuth:
			authCount++
		}
	}

	// --- Phase B: attempt pairing (Just Works; the automated flow does not
	// supply a passkey) ---
	ctx, cancel := ctxWithRootTimeout()
	defer cancel()
	// Pair against the device object the baseline already populated - do NOT
	// RemoveDevice first, or the connect-before-pair has to rediscover it via a
	// scan (which is flaky right after the baseline disconnect). Only if the
	// peripheral rejects pairing do we drop our record and retry once from a
	// clean slate: a rejection can mean a retained half-bond from a prior
	// session, which RemoveDevice clears.
	pa, err := attemptPair(ctx, addr, bluez.CapNoInputNoOutput, nil, "auto", nil)
	if err != nil {
		return err
	}
	if !pa.paired {
		forgetDevice(addr)
		if pa2, e := attemptPair(ctx, addr, bluez.CapNoInputNoOutput, nil, "auto", nil); e == nil {
			pa = pa2
		}
	}

	if !pa.paired {
		detail := "peripheral did not complete pairing"
		if pa.pairErr != nil {
			detail = pa.pairErr.Error()
		}
		res.Findings = append(res.Findings, Finding{
			Title:    "Pairing did not complete - encryption enforcement unverified",
			Severity: SevMedium,
			Detail:   "Device1.Pair did not succeed after a retry: " + detail + ". The peripheral may not support pairing at all (any readable characteristic is then exposed over a plaintext link with no path to encryption), or it is rejecting because it retains a bond from a prior session - reboot the device and rerun to distinguish the two. Auth-required characteristics could not be confirmed as enforced.",
		})
		if okCount > 0 {
			res.Findings = append(res.Findings, Finding{
				Title:    fmt.Sprintf("%d characteristic(s) readable over an unauthenticated link", okCount),
				Severity: SevMedium,
				Detail:   "These were read in the baseline phase without pairing; pairing could not be completed to confirm whether encryption is available to protect them.",
			})
		}
		res.Summary = fmt.Sprintf("baseline readable=%d auth-required=%d; pairing did not complete", okCount, authCount)
		return emitAssess(res)
	}

	// --- Phase C: enforcement (paired) then fallback (unpaired) ---
	// Re-read the auth-gated handles over the now-encrypted link.
	if sB, e := openSession(ctx, addr, true); e == nil {
		for h, cl := range baseline {
			if cl != accessAuth {
				continue
			}
			c := sB.charByHandle(h)
			if c == nil {
				continue
			}
			if _, _, rerr := charValuePreview(c); rerr == nil {
				res.Findings = append(res.Findings, Finding{
					Title:    "Encryption enforced (readable only after pairing)",
					Severity: SevInfo,
					Handle:   h,
					UUID:     uuidByHandle[h],
					Detail:   "Characteristic required authentication unpaired and succeeded once bonded - correct enforcement.",
				})
			}
		}
		sB.close()
	}

	// Drop the bond and re-test the same handles.
	forgetDevice(addr)
	if sC, e := openSession(ctx, addr, true); e == nil {
		for h, cl := range baseline {
			if cl != accessAuth {
				continue
			}
			c := sC.charByHandle(h)
			if c == nil {
				continue
			}
			if _, _, rerr := charValuePreview(c); rerr == nil {
				res.Findings = append(res.Findings, Finding{
					Title:    "Legacy fallback: characteristic readable after unpairing",
					Severity: SevHigh,
					Handle:   h,
					UUID:     uuidByHandle[h],
					Detail:   "Characteristic enforced auth before pairing but stayed readable after the bond was removed.",
				})
			}
		}
		sC.close()
	}

	res.Summary = fmt.Sprintf("baseline readable=%d auth-required=%d; paired=%v", okCount, authCount, pa.paired)
	return emitAssess(res)
}

// readBaseline classifies an unauthenticated read of every readable
// characteristic. Returns handle->class and handle->uuid maps.
//
// No pairing agent is registered, so a read of an encryption-gated attribute
// makes BlueZ attempt a security elevation that simply FAILS (it never bonds:
// without an agent there is nothing to complete Just Works, and BlueZ discards
// the transient device on disconnect). The read therefore classifies cleanly
// as auth-required. The catch is that a failed elevation leaves the link
// mid-handshake and poisons the NEXT read on the same connection (it comes back
// as in-progress / deadline-exceeded and would misclassify). To avoid that we
// reconnect on a clean link after any non-OK read, so each characteristic is
// judged on its own.
func readBaseline(addr string) (map[uint16]accessClass, map[uint16]string, error) {
	ctx, cancel := ctxWithRootTimeout()
	defer cancel()
	s, err := openSession(ctx, addr, true)
	if err != nil {
		return nil, nil, err
	}

	uuids := map[uint16]string{}
	var readable []uint16
	for _, ch := range s.tree.Characteristics {
		uuids[ch.Handle] = ch.UUID
		if propsCan(ch.Flags, "read") {
			readable = append(readable, ch.Handle)
		}
	}
	sort.Slice(readable, func(i, j int) bool { return readable[i] < readable[j] })

	classes := map[uint16]accessClass{}
	for i, h := range readable {
		c := s.charByHandle(h)
		if c == nil {
			classes[h] = accessError
			continue
		}
		_, rerr := c.ReadValue(0)
		cl := classifyAccessErr(rerr)
		classes[h] = cl
		logf("baseline read handle=0x%04x -> class=%s", h, cl)
		if cl == accessOK {
			continue
		}
		// A blocked read left the link mid-elevation; reconnect for a clean
		// slate before the next read. Require the fresh tree to still expose
		// every not-yet-read handle, retrying past the BlueZ race where
		// ServicesResolved flips true before all characteristic objects appear.
		s.close()
		remaining := readable[i+1:]
		if len(remaining) == 0 {
			return classes, uuids, nil
		}
		ns, e := reconnectComplete(addr, remaining)
		if e != nil {
			logf("baseline reconnect failed (remaining=%d): %v", len(remaining), e)
			return classes, uuids, nil // return what we have rather than misclassify
		}
		s = ns
	}
	s.close()
	return classes, uuids, nil
}

// reconnectComplete returns a freshly connected session whose GATT tree exposes
// every handle in need, retrying a few times to ride out the BlueZ
// post-reconnect race where ServicesResolved reports true before every
// characteristic D-Bus object has been exported (which yields a partial tree
// and silently drops characteristics from the assessment).
func reconnectComplete(addr string, need []uint16) (*session, error) {
	var last error
	for attempt := 0; attempt < 4; attempt++ {
		// Fresh timeout budget per attempt: the caller's context is shared
		// across the whole baseline and is typically exhausted by the blocked
		// elevations that triggered this reconnect.
		ctx, cancel := ctxWithRootTimeout()
		s, err := openSession(ctx, addr, true)
		cancel() // ctx only governs connect/enumerate; reads use CallTimeout
		if err != nil {
			last = err
			continue
		}
		complete := true
		var missing uint16
		for _, h := range need {
			if s.charByHandle(h) == nil {
				complete = false
				missing = h
				break
			}
		}
		if complete {
			return s, nil
		}
		logf("reconnect attempt %d: tree has %d chars, missing 0x%04x", attempt, len(s.tree.Characteristics), missing)
		s.close()
		last = fmt.Errorf("incomplete GATT tree after reconnect (missing 0x%04x)", missing)
	}
	return nil, last
}

// forgetDevice best-effort drops any BlueZ device record / bond for addr so a
// phase starts from a known-unpaired state. Errors are ignored: the common
// case is "device not known", which is exactly the state we want.
func forgetDevice(addr string) {
	if c, e := bluez.Dial(root.adapter); e == nil {
		_ = c.RemoveDevice(c.DevicePath(addr))
		c.Close()
	}
}
