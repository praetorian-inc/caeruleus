package cli

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"caeruleus/internal/smp"
)

func newAssessPairingCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "pairing",
		Short: "Probe the SMP pairing feature exchange + downgrade resistance (root; takes over the adapter)",
		Long: `Drives the Security Manager Protocol directly over a raw HCI user channel,
bypassing BlueZ, to inspect and stress the pairing Feature Exchange without
completing a bond. It reports what the peripheral demands (IO capability,
MITM, LE Secure Connections, bonding, max key size) and tests downgrade
resistance by offering deliberately weak Pairing Requests:

  - reduced encryption key size (request 7 bytes)
  - LE legacy pairing (Secure Connections bit cleared)
  - no MITM (Just Works)

A peripheral that still responds to a weakened request - especially one that
otherwise advertises MITM / Secure Connections - is a downgrade-acceptance
finding.

This is the only path with full control of the Pairing Request, because Linux
handles SMP in-kernel. It requires root and TAKES OVER the adapter: the
controller is detached from BlueZ for the duration (stop bluetoothd first if it
keeps reclaiming the adapter), so other (BlueZ-based) caeruleus commands cannot
run on it meanwhile. Supply --addr-type (defaults to random) since BlueZ
discovery is unavailable while the adapter is taken over.`,
		RunE: runAssessPairing,
	}
}

func runAssessPairing(cmd *cobra.Command, args []string) error {
	if err := requireRoot("assess pairing"); err != nil {
		return err
	}
	addr, err := requireBdaddr()
	if err != nil {
		return err
	}
	idx, err := adapterIndex(root.adapter)
	if err != nil {
		return err
	}
	addrType := root.addrType
	if addrType == "" {
		addrType = "random"
		logf("no --addr-type given; assuming random (BlueZ discovery is unavailable on a taken-over adapter)")
	}
	timeout := time.Duration(root.timeout) * time.Second

	dev, err := smp.Open(idx)
	if err != nil {
		return err
	}
	defer dev.Close()

	res := assessResult{Address: addr, Test: "pairing"}

	// 1. Capable probe: learn what the peripheral declares.
	cap, err := probeOnce(dev, addr, addrType, smp.CapableRequest(), timeout)
	if err != nil {
		return fmt.Errorf("feature-exchange probe: %w", err)
	}
	if cap.Failed {
		res.Summary = fmt.Sprintf("peripheral refused pairing: %s", smp.FailReason(cap.FailReason))
		res.Findings = append(res.Findings, Finding{
			Title:    "Peripheral refuses pairing",
			Severity: SevInfo,
			Detail:   "Pairing Request rejected with: " + smp.FailReason(cap.FailReason),
		})
		return emitAssess(res)
	}
	peer := cap.Peer
	res.Summary = fmt.Sprintf("peer io=%s %s max_key=%d", smp.IOCapName(peer.IOCap), peer.AuthReq, peer.MaxKeySize)

	if !peer.AuthReq.MITM {
		res.Findings = append(res.Findings, Finding{
			Title:    "Peripheral does not require MITM protection (Just Works acceptable)",
			Severity: SevMedium,
			Evidence: "io=" + smp.IOCapName(peer.IOCap),
			Detail:   "The peripheral's Authentication Requirements do not set the MITM bit, so pairing has no man-in-the-middle protection.",
		})
	}
	if !peer.AuthReq.SC {
		res.Findings = append(res.Findings, Finding{
			Title:    "No LE Secure Connections (legacy pairing)",
			Severity: SevMedium,
			Detail:   "The peripheral does not set the Secure Connections bit; pairing falls back to weaker LE legacy key agreement.",
		})
	}
	if peer.MaxKeySize < 16 {
		res.Findings = append(res.Findings, Finding{
			Title:    fmt.Sprintf("Reduced maximum encryption key size: %d bytes", peer.MaxKeySize),
			Severity: SevLow,
			Detail:   "The peripheral advertises a maximum key size below the 16-byte maximum.",
		})
	}

	// 2. Key-size downgrade: offer 7 bytes.
	smallKey := smp.CapableRequest()
	smallKey.MaxKeySize = 7
	if r, e := probeOnce(dev, addr, addrType, smallKey, timeout); e == nil && r.Responded {
		res.Findings = append(res.Findings, Finding{
			Title:    "Accepts a 7-byte encryption key (key-size downgrade)",
			Severity: SevHigh,
			Detail:   "The peripheral responded to a Pairing Request offering the minimum 7-byte key instead of rejecting with Encryption Key Size.",
		})
	}

	// 3. Legacy downgrade: clear Secure Connections.
	if peer.AuthReq.SC {
		legacy := smp.CapableRequest()
		legacy.AuthReq.SC = false
		if r, e := probeOnce(dev, addr, addrType, legacy, timeout); e == nil && r.Responded {
			res.Findings = append(res.Findings, Finding{
				Title:    "Accepts LE legacy pairing despite supporting Secure Connections (downgrade)",
				Severity: SevHigh,
				Detail:   "The peripheral advertises Secure Connections but still responded to a legacy (SC=0) Pairing Request.",
			})
		}
	}

	// 4. No-MITM (Just Works) acceptance - preliminary (not completed).
	if peer.AuthReq.MITM {
		jw := smp.CapableRequest()
		jw.IOCap = smp.IONoInputNoOutput
		jw.AuthReq.MITM = false
		if r, e := probeOnce(dev, addr, addrType, jw, timeout); e == nil && r.Responded {
			res.Findings = append(res.Findings, Finding{
				Title:    "Responds to a no-MITM (Just Works) request despite advertising MITM",
				Severity: SevMedium,
				Detail:   "Preliminary: the peripheral did not immediately reject a Just Works request. Confirming a true downgrade requires completing pairing.",
			})
		}
	}

	return emitAssess(res)
}

// probeOnce connects, runs one pairing feature-exchange probe, and disconnects.
// (adapterIndex lives in bdaddr_cmd.go.)
func probeOnce(dev *smp.Dev, addr, addrType string, req smp.PairingPDU, timeout time.Duration) (smp.ProbeResult, error) {
	if err := dev.Connect(addr, addrType, timeout); err != nil {
		return smp.ProbeResult{}, err
	}
	defer dev.Disconnect()
	return smp.Probe(dev, req, timeout)
}
