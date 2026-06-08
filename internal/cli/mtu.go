package cli

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"caeruleus/internal/bluez"
)

var mtuFlags struct {
	set            int
	show           bool
	reset          bool
	revert         bool
	toSpecDefault  bool
	confDir        string
	dryRun         bool
	noWait         bool
	force          bool
	yes            bool
}

// MTU bounds. Spec says 23..517 but BlueZ in practice rejects values below
// ~64 and small peripherals often can't negotiate values much above 247.
// We warn outside the safe band but still accept it if --force is set.
//
// mtuDefault is the value `mtu --reset` writes — intentionally not 517
// (BLE spec max). The BLE CTF firmware and many small-MCU peripherals
// refuse MTU > ~247 during ExchangeMTU. 247 is the de-facto floor; use
// `mtu --reset --to-spec-default` to get the literal 517.
const (
	mtuSpecMin     = 23
	mtuSpecMax     = 517
	mtuSafeMin     = 247
	mtuSafeMax     = 517
	mtuDefault     = 247
	mtuSpecDefault = 517
)

func newMTUCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "mtu",
		Short: "Read or set the requested ATT MTU (set/reset require root + bluetoothd restart)",
		Long: `mtu shows the negotiated ATT MTU for an active connection, or — with
--set / --reset — edits /etc/bluetooth/main.conf and restarts bluetoothd
so the next connection exchanges a different MTU.

Notes:
  - --set / --reset affect every BLE connection on this host.
  - BlueZ does not expose a per-connection ExchangeMTU. main.conf is the
    only knob the D-Bus API gives us.
  - --set / --reset require root (config edit + systemctl restart bluetooth).
  - If bluetoothd fails to come back up after the edit, the previous
    main.conf is restored from a sidecar backup automatically.
  - Values outside ` + fmt.Sprintf("%d..%d", mtuSafeMin, mtuSafeMax) + ` warn unless --force; many peripherals
    can't negotiate large MTUs, and BlueZ rejects very small ones.`,
		RunE: runMTU,
	}
	c.Flags().IntVar(&mtuFlags.set, "set", 0, fmt.Sprintf("request this ATT MTU on the next connection (%d..%d). PROMPTS on TTY; pair with -y for scripts.", mtuSpecMin, mtuSpecMax))
	c.Flags().BoolVar(&mtuFlags.reset, "reset", false, fmt.Sprintf("restore ExchangeMTU to a safe interoperable default (%d). Combine with --to-spec-default for %d. PROMPTS on TTY; pair with -y for scripts.", mtuDefault, mtuSpecDefault))
	c.Flags().BoolVar(&mtuFlags.toSpecDefault, "to-spec-default", false, fmt.Sprintf("with --reset, write %d (BLE spec max) instead of the interoperable default (%d)", mtuSpecDefault, mtuDefault))
	c.Flags().BoolVar(&mtuFlags.revert, "revert", false, "restore the value snapshotted before the last --set/--reset")
	c.Flags().BoolVar(&mtuFlags.show, "show", false, "show the current connection's negotiated MTU")
	c.Flags().StringVar(&mtuFlags.confDir, "conf-dir", "/etc/bluetooth", "bluetooth config directory")
	c.Flags().BoolVar(&mtuFlags.dryRun, "dry-run", false, "print the planned edit without writing or restarting")
	c.Flags().BoolVar(&mtuFlags.noWait, "no-wait", false, "do not wait for bluetoothd to come back up after restart")
	c.Flags().BoolVar(&mtuFlags.force, "force", false, "accept --set values outside the safe band without prompting")
	c.Flags().BoolVarP(&mtuFlags.yes, "yes", "y", false, "skip the disruptive-op confirmation prompt")
	return c
}

func runMTU(cmd *cobra.Command, args []string) error {
	// Reject conflicting flags up front.
	exclusive := 0
	if mtuFlags.set != 0 {
		exclusive++
	}
	if mtuFlags.reset {
		exclusive++
	}
	if mtuFlags.revert {
		exclusive++
	}
	if exclusive > 1 {
		return fmt.Errorf("--set, --reset, and --revert are mutually exclusive")
	}
	if exclusive == 0 && !mtuFlags.show {
		mtuFlags.show = true
	}

	if mtuFlags.show {
		if err := showMTU(); err != nil {
			return err
		}
	}

	target := 0
	switch {
	case mtuFlags.reset:
		if mtuFlags.toSpecDefault {
			target = mtuSpecDefault
		} else {
			target = mtuDefault
		}
	case mtuFlags.set != 0:
		target = mtuFlags.set
	case mtuFlags.revert:
		// Pull the snapshot taken before the last --set/--reset.
		prev, err := readSnapshotMTU(filepath.Join(mtuFlags.confDir, "main.conf.caeruleus.prev"))
		if err != nil {
			return fmt.Errorf("--revert: %w", err)
		}
		target = int(prev)
		logf("--revert: restoring previous ExchangeMTU=%d", target)
	default:
		return nil
	}

	if target < mtuSpecMin || target > mtuSpecMax {
		return fmt.Errorf("MTU %d is outside the BLE valid range %d..%d", target, mtuSpecMin, mtuSpecMax)
	}
	if (target < mtuSafeMin || target > mtuSafeMax) && !mtuFlags.force {
		return fmt.Errorf("MTU %d is outside the safe band %d..%d "+
			"(small values can prevent bluetoothd from starting; large values "+
			"may fail ExchangeMTU on small peripherals). Re-run with --force "+
			"to accept, or --reset to restore the safe default.",
			target, mtuSafeMin, mtuSafeMax)
	}
	// Check root before touching main.conf or systemctl — partial state
	// here (file edited but restart denied) is worse than a clean refusal.
	if !mtuFlags.dryRun {
		if err := requireRoot("mtu --set/--reset/--revert"); err != nil {
			return err
		}
	}
	// Confirmation prompt (F9) — disruptive op, big hammer.
	if !mtuFlags.dryRun && !mtuFlags.yes {
		if err := confirmDisruptive(fmt.Sprintf("Set ExchangeMTU=%d, disconnect active peripherals, restart bluetoothd?", target)); err != nil {
			return err
		}
	}
	return applyMTU(uint16(target))
}

func showMTU() error {
	addr, err := requireBdaddr()
	if err != nil {
		// Allow --show without a bdaddr by falling back to printing the
		// configured request value from main.conf.
		req, perr := readMainConfMTU(filepath.Join(mtuFlags.confDir, "main.conf"))
		if perr == nil {
			fmt.Printf("configured ExchangeMTU = %d (next connection)\n", req)
			return nil
		}
		return fmt.Errorf("--show needs -b BDADDR or a readable main.conf")
	}
	ctx, cancel := ctxWithRootTimeout()
	defer cancel()
	s, err := openSession(ctx, addr, true)
	if err != nil {
		return err
	}
	defer s.close()
	for _, ch := range s.tree.Characteristics {
		c := s.conn.Characteristic(ch.Path)
		if m, err := c.MTU(); err == nil && m > 0 {
			fmt.Printf("negotiated MTU = %d\n", m)
			return nil
		}
	}
	fmt.Println("MTU property unavailable on this BlueZ build")
	return nil
}

// applyMTU edits main.conf so that the [GATT] ExchangeMTU= matches mtu, then
// restarts bluetoothd. Before writing, the current effective ExchangeMTU is
// snapshotted to main.conf.caeruleus.prev so `mtu --revert` can undo. If
// --dry-run is set the file is not written. If bluetoothd refuses to come
// back up, the previous main.conf is restored from the rollback backup and
// another restart is attempted so we never leave the system unusable.
func applyMTU(mtu uint16) error {
	confPath := filepath.Join(mtuFlags.confDir, "main.conf")
	prevPath := filepath.Join(mtuFlags.confDir, "main.conf.caeruleus.prev")

	original, err := os.ReadFile(confPath)
	if err != nil {
		return fmt.Errorf("read %s: %w (run with sudo?)", confPath, err)
	}

	// Snapshot the current effective ExchangeMTU for --revert. We write
	// the integer (not the whole config) so --revert is a single value
	// lookup, not a full config diff.
	if curMTU, err := readMainConfMTU(confPath); err == nil && uint16(curMTU) != mtu {
		// Best-effort; if we can't write the snapshot, the --revert path
		// will fail later with a clear message but the --set still works.
		_ = os.WriteFile(prevPath, []byte(fmt.Sprintf("%d\n", curMTU)), 0o644)
	}

	updated, changed, err := patchExchangeMTU(string(original), mtu)
	if err != nil {
		return err
	}

	if mtuFlags.dryRun {
		fmt.Println("--- would patch", confPath, "---")
		fmt.Print(updated)
		fmt.Println("--- end ---")
		return nil
	}

	if changed {
		// Keep a sidecar backup we can revert to if bluetoothd refuses
		// to start with the new config.
		backupPath := confPath + ".caeruleus.bak"
		if err := os.WriteFile(backupPath, original, 0o644); err != nil {
			return fmt.Errorf("write backup %s: %w (run with sudo?)", backupPath, err)
		}

		if err := atomicWrite(confPath, updated); err != nil {
			os.Remove(backupPath)
			return err
		}
		logf("updated %s ([GATT] ExchangeMTU = %d), backup at %s", confPath, mtu, backupPath)
		defer os.Remove(backupPath) // best-effort cleanup on success
	} else {
		logf("%s already requests ExchangeMTU = %d, skipping write", confPath, mtu)
	}

	// Cleanly disconnect any active peripherals BEFORE killing bluetoothd —
	// otherwise the remote side keeps its half-link alive until supervision
	// timeout and won't re-advertise for several seconds.
	if err := drainConnectedPeripherals(); err != nil {
		failf("could not drain peripherals before restart: %v", err)
	}

	logf("restarting bluetoothd…")
	if err := exec.Command("systemctl", "restart", "bluetooth").Run(); err != nil {
		return rollbackOrFail(confPath, original, fmt.Errorf("systemctl restart bluetooth: %w (run with sudo?)", err))
	}

	if mtuFlags.noWait {
		return nil
	}
	// Wait for the bus to come back.
	err = pollUntil(context.Background(), func() bool {
		c, err := bluez.Dial(root.adapter)
		if err == nil {
			c.Close()
			return true
		}
		return false
	}, 300*time.Millisecond, 15*time.Second)
	if err != nil {
		return rollbackOrFail(confPath, original,
			fmt.Errorf("bluetoothd did not come back within 15s — likely rejected MTU=%d", mtu))
	}
	fmt.Printf("ExchangeMTU set to %d on adapter %s — reconnect to take effect.\n", mtu, root.adapter)
	return nil
}

// atomicWrite writes content to path via a temp file + rename so an error
// during write can't leave a half-finished config file.
func atomicWrite(path, content string) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".caeruleus.*")
	if err != nil {
		return fmt.Errorf("write tempfile: %w (run with sudo?)", err)
	}
	if _, err := tmp.WriteString(content); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return fmt.Errorf("write tempfile: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	if st, err := os.Stat(path); err == nil {
		_ = os.Chmod(tmp.Name(), st.Mode())
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		os.Remove(tmp.Name())
		return fmt.Errorf("rename into place: %w", err)
	}
	return nil
}

// rollbackOrFail restores the original main.conf and tries to bring
// bluetoothd back. It returns the underlying error from the caller plus
// a note about the rollback. We do this rather than panicking so a bad
// --set value doesn't strand the host without Bluetooth.
func rollbackOrFail(path string, original []byte, cause error) error {
	logf("rolling back %s to pre-edit contents", path)
	if werr := os.WriteFile(path, original, 0o644); werr != nil {
		return fmt.Errorf("%w; ALSO failed to restore %s: %v (manual recovery required)", cause, path, werr)
	}
	if rerr := exec.Command("systemctl", "restart", "bluetooth").Run(); rerr != nil {
		return fmt.Errorf("%w; restored %s but systemctl restart still failed: %v", cause, path, rerr)
	}
	return fmt.Errorf("%w (config rolled back; bluetoothd back on previous ExchangeMTU)", cause)
}

// patchExchangeMTU rewrites the [GATT] ExchangeMTU= line in main.conf. If the
// [GATT] section is absent it is appended. Returns (newText, didChange, err).
func patchExchangeMTU(text string, mtu uint16) (string, bool, error) {
	lines := strings.Split(text, "\n")
	want := fmt.Sprintf("ExchangeMTU = %d", mtu)
	wantRe := regexp.MustCompile(`(?i)^\s*#?\s*ExchangeMTU\s*=\s*\d+\s*$`)
	sectionRe := regexp.MustCompile(`^\s*\[([^\]]+)\]\s*$`)

	currentSection := ""
	inGatt := false
	patched := false
	changed := false
	out := make([]string, 0, len(lines)+2)
	for _, l := range lines {
		if m := sectionRe.FindStringSubmatch(l); m != nil {
			currentSection = strings.ToLower(strings.TrimSpace(m[1]))
			inGatt = currentSection == "gatt"
			out = append(out, l)
			continue
		}
		if inGatt && wantRe.MatchString(l) {
			if strings.TrimSpace(l) != want {
				changed = true
			}
			out = append(out, want)
			patched = true
			continue
		}
		out = append(out, l)
	}
	if !patched {
		if !sectionRe.MatchString(strings.Join(lines, "\n")) || !containsSection(lines, "GATT") {
			out = append(out, "", "[GATT]", want)
		} else {
			// [GATT] section exists but no MTU key — append the key under it.
			out = appendUnderSection(out, "GATT", want)
		}
		changed = true
	}
	return strings.Join(out, "\n"), changed, nil
}

func containsSection(lines []string, name string) bool {
	want := strings.ToLower(name)
	for _, l := range lines {
		l = strings.ToLower(strings.TrimSpace(l))
		if l == "["+want+"]" {
			return true
		}
	}
	return false
}

func appendUnderSection(lines []string, section, line string) []string {
	want := strings.ToLower(section)
	out := make([]string, 0, len(lines)+1)
	inSection := false
	inserted := false
	for _, l := range lines {
		trimmed := strings.ToLower(strings.TrimSpace(l))
		if !inserted && inSection && strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			// Hit the next section — insert before it.
			out = append(out, line)
			inserted = true
		}
		out = append(out, l)
		if trimmed == "["+want+"]" {
			inSection = true
		}
	}
	if !inserted && inSection {
		out = append(out, line)
	}
	return out
}

// readSnapshotMTU loads the integer ExchangeMTU value that applyMTU saved
// before the most recent change, used by `mtu --revert`.
func readSnapshotMTU(path string) (uint16, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, fmt.Errorf("no previous-MTU snapshot at %s (nothing to revert to)", path)
		}
		return 0, fmt.Errorf("read snapshot %s: %w", path, err)
	}
	s := strings.TrimSpace(string(b))
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("snapshot %s: not an integer (%q)", path, s)
	}
	if n < mtuSpecMin || n > mtuSpecMax {
		return 0, fmt.Errorf("snapshot %s: value %d out of valid range", path, n)
	}
	return uint16(n), nil
}

// readMainConfMTU returns the [GATT] ExchangeMTU value if present.
func readMainConfMTU(path string) (uint16, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	inGatt := false
	for scanner.Scan() {
		l := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(l, "[") && strings.HasSuffix(l, "]") {
			inGatt = strings.EqualFold(l, "[GATT]")
			continue
		}
		if !inGatt {
			continue
		}
		if strings.HasPrefix(l, "#") {
			continue
		}
		parts := strings.SplitN(l, "=", 2)
		if len(parts) != 2 {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(parts[0]), "ExchangeMTU") {
			n, err := strconv.Atoi(strings.TrimSpace(parts[1]))
			if err != nil {
				return 0, err
			}
			return uint16(n), nil
		}
	}
	return 0, fmt.Errorf("ExchangeMTU not set in %s", path)
}
