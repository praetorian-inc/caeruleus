package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// clearStuckINQUIRY detects whether the controller is in BR/EDR INQUIRY
// mode and, if so, runs a soft power-cycle to clear it. The detection
// uses /sys/class/bluetooth/hciN/inquiry_mode-adjacent state - we look
// at the "state" file under /sys/kernel/debug or fall back to parsing
// hciconfig output if debug fs isn't mounted.
//
// We only power-cycle when INQUIRY is actually detected, so callers like
// bdaddr that depend on the controller's volatile state (e.g. a vendor
// BD_ADDR write) keep their state intact in the common case. When INQUIRY
// is present, the power-cycle does wipe volatile state - that's the
// trade-off, but it leaves the user in a consistent, scannable state
// rather than mysteriously broken.
func clearStuckINQUIRY() error {
	in, err := adapterInINQUIRY()
	if err != nil {
		return err
	}
	if !in {
		return nil
	}
	logf("controller stuck in BR/EDR INQUIRY mode after reset - power-cycling to clear (volatile state will be lost)")
	return cyclePower()
}

// adapterInINQUIRY parses /sys/class/bluetooth/<adapter>/.../state-equivalent
// to determine if INQUIRY mode is active. We use the kernel's class file
// when available; otherwise fall back to reading hciconfig output via the
// sysfs-backed flags.
//
// On 6.x kernels there is no single "state" file; the practical proxy is
// reading /proc/bluetooth/<adapter>/flags (not always present) or running
// hciconfig. Easiest portable check: shell out to hciconfig and look for
// the INQUIRY substring on the state line. Returns true if INQUIRY is set.
func adapterInINQUIRY() (bool, error) {
	// Try hciconfig first - it's stable across kernels and always present
	// when bluetoothd is installed.
	if out, err := runHciconfig(root.adapter); err == nil {
		return strings.Contains(out, " INQUIRY"), nil
	}
	// Fallback: try the kernel-visible flags file. Not always there but
	// when it is, the format is one integer per line.
	flagsPath := filepath.Join("/sys/class/bluetooth", root.adapter, "device/flags")
	if data, err := os.ReadFile(flagsPath); err == nil {
		// Bit 5 = HCI_INQUIRY (per kernel net/bluetooth/hci.h). Brittle.
		s := strings.TrimSpace(string(data))
		var n int
		if _, err := fmt.Sscanf(s, "%d", &n); err == nil {
			return n&(1<<5) != 0, nil
		}
	}
	// Couldn't determine - assume not stuck.
	return false, nil
}

// runHciconfig shells out to /usr/bin/hciconfig <adapter> and returns
// stdout. Used purely for state detection; we never depend on hciconfig
// for actual changes.
func runHciconfig(adapter string) (string, error) {
	return runCmdCombined("hciconfig", adapter)
}

// runCmdCombined runs a command and returns combined stdout+stderr.
// Tiny wrapper kept here rather than at package scope so it stays local
// to the INQUIRY-detection code path.
func runCmdCombined(name string, args ...string) (string, error) {
	out, err := execCommandCombined(name, args...)
	return string(out), err
}
