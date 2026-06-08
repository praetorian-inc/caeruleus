package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"caeruleus/internal/bluez"
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
	if c, e := bluez.Dial(root.adapter); e == nil {
		_ = c.RemoveDevice(c.DevicePath(addr)) // ensure no bond
		c.Close()
	}
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
	pa, err := attemptPair(ctx, addr, bluez.CapNoInputNoOutput, nil)
	if err != nil {
		return err
	}

	if !pa.paired {
		detail := "peripheral did not complete pairing"
		if pa.pairErr != nil {
			detail = pa.pairErr.Error()
		}
		res.Findings = append(res.Findings, Finding{
			Title:    "No pairing support - link encryption cannot be enforced",
			Severity: SevMedium,
			Detail:   "Device1.Pair did not succeed: " + detail + ". Any readable characteristic is exposed over a plaintext link with no path to encryption.",
		})
		if okCount > 0 {
			res.Findings = append(res.Findings, Finding{
				Title:    fmt.Sprintf("%d characteristic(s) readable with no encryption available", okCount),
				Severity: SevMedium,
				Detail:   "These were read over an unauthenticated link and the device offers no pairing to protect them.",
			})
		}
		res.Summary = fmt.Sprintf("baseline readable=%d auth-required=%d; pairing unsupported", okCount, authCount)
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
	if c, e := bluez.Dial(root.adapter); e == nil {
		_ = c.RemoveDevice(c.DevicePath(addr))
		c.Close()
	}
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

// readBaseline connects unauthenticated and classifies a read of every
// readable characteristic. Returns handle->class and handle->uuid maps.
func readBaseline(addr string) (map[uint16]accessClass, map[uint16]string, error) {
	ctx, cancel := ctxWithRootTimeout()
	defer cancel()
	s, err := openSession(ctx, addr, true)
	if err != nil {
		return nil, nil, err
	}
	defer s.close()

	classes := map[uint16]accessClass{}
	uuids := map[uint16]string{}
	for _, ch := range s.tree.Characteristics {
		uuids[ch.Handle] = ch.UUID
		if !propsCan(ch.Flags, "read") {
			continue
		}
		_, rerr := s.conn.Characteristic(ch.Path).ReadValue(0)
		classes[ch.Handle] = classifyAccessErr(rerr)
	}
	return classes, uuids, nil
}
