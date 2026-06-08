package cli

import (
	"bytes"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"caeruleus/internal/bluez"
)

var wwrFlags struct {
	sizes []int
	burst int
}

func newAssessWWRCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "wwr",
		Short: "Write-without-response overflow + rapid-fire resilience on -b BDADDR",
		Long: `Stress-tests every characteristic that advertises Write-Without-Response:

  1. Size sweep — sends increasingly large 0x41-filled payloads; a disconnect
     after a given size suggests a buffer-overflow / oversized-write crash.
  2. Rapid-fire — sends a burst of small write-commands back-to-back to probe
     for resource exhaustion / queue overrun.

Liveness is checked after each step by reading a known-readable handle. This
is an active stress test: a vulnerable peripheral may reset or wedge. On the
first detected crash, testing stops and the trigger is reported.`,
		RunE: runAssessWWR,
	}
	c.Flags().IntSliceVar(&wwrFlags.sizes, "sizes", []int{20, 50, 100, 200, 512},
		"payload sizes (bytes) for the overflow sweep")
	c.Flags().IntVar(&wwrFlags.burst, "burst", 100, "number of rapid-fire writes for the exhaustion test")
	return c
}

func runAssessWWR(cmd *cobra.Command, args []string) error {
	addr, err := requireBdaddr()
	if err != nil {
		return err
	}
	ctx, cancel := ctxWithRootTimeout()
	defer cancel()

	s, err := openSession(ctx, addr, true)
	if err != nil {
		return err
	}
	defer s.close()

	res := assessResult{Address: addr, Test: "wwr"}

	// Pick a liveness probe: the first readable characteristic.
	liveness := s.firstReadable()
	if liveness == nil {
		res.Summary = "no readable characteristic available for a liveness probe; results are best-effort"
	}

	var targets []bluez.GattObject
	for _, ch := range s.tree.Characteristics {
		if propsCan(ch.Flags, "write-without-response") {
			targets = append(targets, ch)
		}
	}
	if len(targets) == 0 {
		res.Summary = "no write-without-response characteristics found"
		return emitAssess(res)
	}

	crashed := false
sweep:
	for _, ch := range targets {
		c := s.conn.Characteristic(ch.Path)

		// Overflow sweep.
		for _, sz := range wwrFlags.sizes {
			if sz <= 0 {
				continue
			}
			_ = c.WriteValue(bytes.Repeat([]byte{0x41}, sz), bluez.WriteCommand)
			if !s.alive(liveness) {
				res.Findings = append(res.Findings, Finding{
					Title:    "Device crashed during write-without-response overflow",
					Severity: SevHigh,
					Handle:   ch.Handle,
					UUID:     ch.UUID,
					Evidence: fmt.Sprintf("disconnected after a %d-byte write-command", sz),
					Detail:   "Liveness probe failed immediately after an oversized write-without-response.",
				})
				crashed = true
				break sweep
			}
		}

		// Rapid-fire exhaustion.
		for i := 0; i < wwrFlags.burst; i++ {
			_ = c.WriteValue([]byte{0x41}, bluez.WriteCommand)
		}
		if !s.alive(liveness) {
			res.Findings = append(res.Findings, Finding{
				Title:    "Device crashed during rapid-fire write-without-response",
				Severity: SevHigh,
				Handle:   ch.Handle,
				UUID:     ch.UUID,
				Evidence: fmt.Sprintf("disconnected after a burst of %d write-commands", wwrFlags.burst),
				Detail:   "Liveness probe failed after a back-to-back burst — possible resource exhaustion.",
			})
			crashed = true
			break sweep
		}
	}

	if !crashed {
		res.Summary = fmt.Sprintf("survived overflow sweep + %d-write burst on %d WWR characteristic(s)", wwrFlags.burst, len(targets))
	} else {
		res.Summary = "stopped on first detected crash"
	}
	return emitAssess(res)
}

// firstReadable returns the first readable characteristic in the tree, or nil.
func (s *session) firstReadable() *bluez.GattObject {
	for i := range s.tree.Characteristics {
		if propsCan(s.tree.Characteristics[i].Flags, "read") {
			return &s.tree.Characteristics[i]
		}
	}
	return nil
}

// alive reports whether the peripheral still answers. It prefers a read of the
// supplied liveness characteristic; if none was found, it falls back to the
// BlueZ Connected property. A short settle delay lets a crash surface.
func (s *session) alive(liveness *bluez.GattObject) bool {
	time.Sleep(150 * time.Millisecond)
	if liveness != nil {
		_, err := s.conn.Characteristic(liveness.Path).ReadValue(0)
		if err == nil {
			return true
		}
		if classifyAccessErr(err) == accessAuth {
			return true // gated, but the link is clearly alive
		}
		return false
	}
	c, err := s.device.Connected()
	return err == nil && c
}
