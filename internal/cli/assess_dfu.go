package cli

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"caeruleus/internal/bluez"
)

var dfuFlags struct {
	probeEntry bool
}

// Nordic DFU UUIDs. The secure-DFU service is 0xFE59; the buttonless entry
// characteristics live inside it. Matching is done on the embedded substrings
// so both 16-bit-folded and full 128-bit forms are caught.
const (
	dfuServiceFrag        = "fe59"
	dfuButtonlessUnbonded = "8ec90003" // buttonless DFU without bonds
	dfuButtonlessBonded   = "8ec90004" // buttonless DFU with bonds
	dfuControlPointFrag   = "8ec90001" // legacy DFU control point
)

func newAssessDFUCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "dfu",
		Short: "Detect a DFU service on -b BDADDR and whether entry is unauthenticated",
		Long: `Detects a Nordic-style Device Firmware Update service (0xFE59) and reports
its control / buttonless-entry characteristics and whether they are writable
over an unauthenticated link - an unauthenticated buttonless-DFU entry point
lets an attacker reboot the device into its bootloader.

Detection only by default - it never writes a DFU opcode, because triggering
buttonless DFU reboots the target into its bootloader. --probe-entry opts in
to actually writing the enter-bootloader opcode (DESTRUCTIVE: reboots the
device); it prompts on a TTY unless -y is given.`,
		RunE: runAssessDFU,
	}
	c.Flags().BoolVar(&dfuFlags.probeEntry, "probe-entry", false,
		"actually write the buttonless enter-DFU opcode (DESTRUCTIVE: reboots the device)")
	c.Flags().BoolVarP(&assessYes, "yes", "y", false, "skip the confirmation prompt for --probe-entry")
	return c
}

// assessYes is shared by destructive assess subcommands needing confirmation.
var assessYes bool

func runAssessDFU(cmd *cobra.Command, args []string) error {
	addr, err := requireBdaddr()
	if err != nil {
		return err
	}
	ctx, cancel := ctxWithRootTimeout()
	defer cancel()

	// Unauthenticated context, so "writable" means writable to anyone.
	if c, e := bluez.Dial(root.adapter); e == nil {
		_ = c.RemoveDevice(c.DevicePath(addr))
		c.Close()
	}

	s, err := openSession(ctx, addr, true)
	if err != nil {
		return err
	}
	defer s.close()

	res := assessResult{Address: addr, Test: "dfu"}

	// Is a DFU service present?
	dfuPresent := false
	for _, sv := range s.tree.Services {
		if strings.Contains(strings.ToLower(sv.UUID), dfuServiceFrag) {
			dfuPresent = true
			break
		}
	}
	if !dfuPresent {
		res.Summary = "no DFU service (0xFE59) present"
		res.Findings = append(res.Findings, Finding{
			Title:    "No DFU service detected",
			Severity: SevInfo,
			Detail:   "No 0xFE59 service was found in the GATT tree.",
		})
		return emitAssess(res)
	}

	// Classify the DFU characteristics.
	var entryChar *bluez.GattObject
	for i := range s.tree.Characteristics {
		ch := &s.tree.Characteristics[i]
		u := strings.ToLower(ch.UUID)
		isEntry := strings.Contains(u, dfuButtonlessUnbonded) ||
			strings.Contains(u, dfuButtonlessBonded) ||
			strings.Contains(u, dfuControlPointFrag)
		if !isEntry {
			continue
		}
		writable := propsCan(ch.Flags, "write") || propsCan(ch.Flags, "write-without-response")
		sev := SevMedium
		title := "DFU entry characteristic present"
		if writable {
			sev = SevHigh
			title = "Unauthenticated DFU entry point (writable, no pairing)"
			entryChar = ch
		}
		res.Findings = append(res.Findings, Finding{
			Title:    title,
			Severity: sev,
			Handle:   ch.Handle,
			UUID:     ch.UUID,
			Evidence: "props=" + formatProps(ch.Flags),
			Detail:   "Buttonless/secure DFU control characteristic reachable over an unauthenticated link.",
		})
	}

	// Optional destructive probe: actually write the enter-DFU opcode.
	if dfuFlags.probeEntry && entryChar != nil {
		if !assessYes {
			if err := confirmDisruptive(fmt.Sprintf(
				"--probe-entry will write the enter-bootloader opcode to 0x%04x and REBOOT %s. Continue?",
				entryChar.Handle, addr)); err != nil {
				return err
			}
		}
		// Nordic buttonless "Enter bootloader" opcode is 0x01.
		c := s.conn.Characteristic(entryChar.Path)
		werr := c.WriteValue([]byte{0x01}, bluez.WriteRequest)
		if werr == nil {
			res.Findings = append(res.Findings, Finding{
				Title:    "Buttonless DFU entry accepted without authentication",
				Severity: SevCritical,
				Handle:   entryChar.Handle,
				UUID:     entryChar.UUID,
				Evidence: "enter-bootloader opcode (0x01) accepted",
				Detail:   "The device accepted the enter-bootloader command over an unauthenticated link.",
			})
		}
	}

	res.Summary = fmt.Sprintf("DFU service present; %d DFU characteristic finding(s)", len(res.Findings))
	return emitAssess(res)
}
