package cli

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
	"golang.org/x/sys/unix"

	"github.com/praetorian-inc/caeruleus/internal/bluez"
)

// session bundles a connected device + its discovered GATT tree.
type session struct {
	conn   *bluez.Conn
	device *bluez.Device
	tree   *bluez.GattTree
}

// openSession dials BlueZ, optionally connects to bdaddr, and enumerates GATT.
// If addr is "", no Device is attached.
func openSession(ctx context.Context, addr string, connect bool) (*session, error) {
	conn, err := bluez.Dial(root.adapter)
	if err != nil {
		return nil, err
	}
	s := &session{conn: conn}
	if addr == "" {
		return s, nil
	}
	s.device = conn.Device(addr)
	if root.addrType != "" {
		// best-effort; old kernels don't expose this on unknown devices
		_ = s.device.SetAddressType(root.addrType)
	}
	if connect {
		timeout := time.Duration(root.timeout) * time.Second
		if err := s.device.Connect(ctx, timeout); err != nil {
			conn.Close()
			return nil, err
		}
		t, err := conn.EnumerateGatt(s.device.Path)
		if err != nil {
			_ = s.device.Disconnect()
			conn.Close()
			return nil, err
		}
		s.tree = t
	}
	return s, nil
}

func (s *session) close() {
	if s.device != nil {
		// Best-effort: only call Disconnect if the device is still around AND
		// reports Connected=true. Ignore the error but block briefly so BlueZ
		// has time to actually emit the disconnect on the air; otherwise we
		// can race off the process while the peripheral still thinks the
		// link is up, leaving it unable to re-advertise until its supervision
		// timeout fires.
		if connected, err := s.device.Connected(); err == nil && connected {
			_ = s.device.Disconnect()
			_ = pollUntil(context.Background(), func() bool {
				c, err := s.device.Connected()
				return err != nil || !c
			}, 50*time.Millisecond, 2*time.Second)
		}
	}
	if s.conn != nil {
		_ = s.conn.Close()
	}
}

// requireBdaddr enforces -b/--bdaddr at command entry.
func requireBdaddr() (string, error) {
	if root.bdaddr == "" {
		return "", errors.New("-b/--bdaddr is required")
	}
	if !validMAC(root.bdaddr) {
		return "", fmt.Errorf("invalid BD_ADDR %q", root.bdaddr)
	}
	return strings.ToUpper(root.bdaddr), nil
}

func validMAC(s string) bool {
	parts := strings.Split(s, ":")
	if len(parts) != 6 {
		return false
	}
	for _, p := range parts {
		if len(p) != 2 {
			return false
		}
		if _, err := strconv.ParseUint(p, 16, 8); err != nil {
			return false
		}
	}
	return true
}

// parseHandle accepts "0x002a", "0X2A", "42" (decimal), etc.
func parseHandle(s string) (uint16, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, errors.New("empty handle")
	}
	base := 10
	if strings.HasPrefix(strings.ToLower(s), "0x") {
		s = s[2:]
		base = 16
	}
	n, err := strconv.ParseUint(s, base, 16)
	if err != nil {
		return 0, fmt.Errorf("handle %q: %w", s, err)
	}
	return uint16(n), nil
}

// parseHexBytes accepts "deadbeef" or "de:ad:be:ef" or "de ad be ef".
func parseHexBytes(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	s = strings.ReplaceAll(s, ":", "")
	s = strings.ReplaceAll(s, " ", "")
	if strings.HasPrefix(strings.ToLower(s), "0x") {
		s = s[2:]
	}
	if len(s)%2 != 0 {
		return nil, fmt.Errorf("hex value has odd length: %q", s)
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("hex decode: %w", err)
	}
	return b, nil
}

// logf prints a diagnostic to stderr when --verbose is set. Prefix mirrors
// the [*] / [+] / [-] convention shared by brutus and other Praetorian
// CLIs - [*] means "informational, may or may not be actionable".
func logf(format string, args ...interface{}) {
	if !root.verbose {
		return
	}
	fmt.Fprintf(os.Stderr, "[*] "+format+"\n", args...)
}

// ctxWithRootTimeout produces a context capped by --timeout.
func ctxWithRootTimeout() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), time.Duration(root.timeout)*time.Second)
}

// execCommandCombined runs `name args…` and returns combined stdout+stderr.
// Used by INQUIRY-state detection (hciconfig).
func execCommandCombined(name string, args ...string) ([]byte, error) {
	return exec.Command(name, args...).CombinedOutput()
}

// ExitError carries a specific exit code out of a RunE function so the
// program's main can surface it to the shell. Cobra's default error path
// always exits 1; we use this when a subcommand wants a different code
// (e.g. `doctor` returns 2 when one of its checks fails - the convention
// among shell-friendly tools like grep / diff to distinguish "command
// itself failed" from "command ran but found a problem").
type ExitError struct {
	Code int
	Err  error
}

func (e *ExitError) Error() string {
	if e.Err == nil {
		return fmt.Sprintf("exit code %d", e.Code)
	}
	return e.Err.Error()
}

func (e *ExitError) Unwrap() error { return e.Err }

// confirmDisruptive prompts on a TTY for a y/N answer; returns nil to
// proceed, an error to abort. When stdin isn't a TTY (scripts, batch
// mode) it auto-confirms - caller scripts are assumed to want headless
// operation. Use the -y/--yes flag on a subcommand to skip even on TTY.
func confirmDisruptive(question string) error {
	fi, err := os.Stdin.Stat()
	if err != nil || (fi.Mode()&os.ModeCharDevice) == 0 {
		// non-TTY (pipe / redirect / batch); proceed without prompting.
		return nil
	}
	fmt.Fprintf(os.Stderr, "%s [y/N] ", question)
	var resp string
	if _, err := fmt.Fscanln(os.Stdin, &resp); err != nil {
		// EOF / empty line counts as N.
		return fmt.Errorf("aborted by user (pass -y to skip the confirmation prompt)")
	}
	resp = strings.TrimSpace(strings.ToLower(resp))
	if resp == "y" || resp == "yes" {
		return nil
	}
	return fmt.Errorf("aborted by user (pass -y to skip the confirmation prompt)")
}

// requireRoot returns an error before any side effect when the calling
// process is not root (euid != 0). setcap'd binaries that don't need
// file-write/systemctl access can use it as a pre-flight check too - // they'll fail here, but the alternative is partially-applied state
// (e.g. main.conf edited but bluetoothd restart denied) which is worse.
// op is the subcommand or operation name used in the error message.
func requireRoot(op string) error {
	if os.Geteuid() == 0 {
		return nil
	}
	return fmt.Errorf("%s requires root (re-run with sudo)", op)
}

// formatIsJSON reports whether the user asked for any flavor of JSON
// output (either pretty `json` or one-obj-per-line `jsonl`). Subcommands
// use it to bypass their human-readable rendering path.
func formatIsJSON() bool {
	return root.format == "json" || root.format == "jsonl"
}

// emitJSON encodes v to stdout in the user-selected JSON variant. Slices
// and arrays follow the org convention: under `json` they emit as a
// single indented array; under `jsonl` they emit one element per line
// with no array wrapper. Scalars / structs emit as one object either
// way - only the whitespace differs.
func emitJSON(v interface{}) error {
	rv := reflect.ValueOf(v)
	if rv.Kind() == reflect.Slice || rv.Kind() == reflect.Array {
		if root.format == "json" {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(v)
		}
		enc := json.NewEncoder(os.Stdout) // jsonl: one obj per line
		for i := 0; i < rv.Len(); i++ {
			if err := enc.Encode(rv.Index(i).Interface()); err != nil {
				return err
			}
		}
		return nil
	}
	enc := json.NewEncoder(os.Stdout)
	if root.format == "json" {
		enc.SetIndent("", "  ")
	}
	return enc.Encode(v)
}

// emitJSONEvent encodes one event for streaming subcommands (listen,
// monitor) where events arrive over time. `json` and `jsonl` both emit
// one object per call; only the whitespace differs.
func emitJSONEvent(v interface{}) error {
	enc := json.NewEncoder(os.Stdout)
	if root.format == "json" {
		enc.SetIndent("", "  ")
	}
	return enc.Encode(v)
}

// statusf prints a success-shaped status line to stderr unless --quiet
// is set. Prefix [+] follows the brutus / wider Praetorian-CLI convention
// for "the thing I was asked to do happened." Use for "connected in
// 800ms", "ExchangeMTU set to N", and similar one-shot user feedback
// that isn't program-data output. --verbose doesn't change behaviour;
// logf is the verbose-gated channel.
func statusf(format string, args ...interface{}) {
	if root.quiet {
		return
	}
	fmt.Fprintf(os.Stderr, "[+] "+format+"\n", args...)
}

// failf prints a non-fatal failure line to stderr unless --quiet is set.
// Prefix [-] follows the same convention. Use for "could not drain
// peripherals", "MGMT read failed", and other cases where the program
// surfaces a partial failure but continues running. Fatal errors should
// be returned up to main.go, which prints them prefixed with "error:".
func failf(format string, args ...interface{}) {
	if root.quiet {
		return
	}
	fmt.Fprintf(os.Stderr, "[-] "+format+"\n", args...)
}

// termWidth returns the column width of the terminal on stdout, or 0 when
// stdout is not a terminal (piped/redirected) or the size can't be read.
// Callers use 0 to mean "don't constrain output" - piping to a file or grep
// wants the full, unwrapped width.
func termWidth() int {
	if ws, err := unix.IoctlGetWinsize(int(os.Stdout.Fd()), unix.TIOCGWINSZ); err == nil && ws != nil && ws.Col > 0 {
		return int(ws.Col)
	}
	// Not a TTY (piped/redirected): leave output unconstrained unless the
	// caller explicitly sets COLUMNS - useful as an override and for tests.
	if c := os.Getenv("COLUMNS"); c != "" {
		if n, err := strconv.Atoi(strings.TrimSpace(c)); err == nil && n > 0 {
			return n
		}
	}
	return 0
}

// pollUntil polls pred at the given interval until it returns true or
// the max duration elapses, returning nil in the former case and an
// error wrapping the last context (when ctx is canceled) otherwise.
// Use this instead of hand-rolled sleep-and-recheck loops for
// "wait for X to become true" state transitions - disconnect
// confirmation, Powered toggle, bluetoothd-back-up after restart, etc.
func pollUntil(ctx context.Context, pred func() bool, interval, max time.Duration) error {
	deadline := time.Now().Add(max)
	if pred() {
		return nil
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			if pred() {
				return nil
			}
			if time.Now().After(deadline) {
				return fmt.Errorf("pollUntil: condition not met within %s", max)
			}
		}
	}
}

// retryable runs op up to retry+1 times (so retry=0 means "run once").
// Between attempts it sleeps delay. Non-transient errors short-circuit;
// only bluez.IsTransientError matches retry.
func retryable(retry int, delay time.Duration, op func() error) error {
	var err error
	for attempt := 0; attempt <= retry; attempt++ {
		if attempt > 0 {
			logf("retry %d/%d after transient error: %v", attempt, retry, err)
			time.Sleep(delay)
		}
		err = op()
		if err == nil {
			return nil
		}
		if !bluez.IsTransientError(err) {
			return err
		}
	}
	return err
}

// newTable returns a table.Writer with a borderless, space-padded style
// so that individual cell values (MAC addresses, handles, UUIDs) are
// double-click-selectable in terminals like Ghostty, iTerm2, and gnome-terminal.
func newTable() table.Writer {
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.SetStyle(table.Style{
		Name: "copy-friendly",
		Box: table.BoxStyle{
			MiddleHorizontal: "-",
			PaddingLeft:      "",
			PaddingRight:     "  ",
		},
		Format: table.FormatOptions{
			Header: text.FormatUpper,
		},
		Options: table.Options{
			DrawBorder:      false,
			SeparateColumns: false,
			SeparateHeader:  true,
			SeparateRows:    false,
		},
	})
	return t
}

// drainConnectedPeripherals walks every Device1 reported by BlueZ on the
// active adapter and disconnects anything currently connected, waiting up
// to 2s per device for Connected=false. Use before disruptive operations
// (bluetoothd restart, Adapter1.Powered cycle) so peripherals see a clean
// shutdown and start re-advertising immediately instead of waiting on
// their supervision timeout (~6s) to realise we're gone.
func drainConnectedPeripherals() error {
	c, err := bluez.Dial(root.adapter)
	if err != nil {
		return err
	}
	defer c.Close()
	devs, err := c.Devices()
	if err != nil {
		return err
	}
	for _, di := range devs {
		if !di.Connected {
			continue
		}
		d := c.Device(di.Address)
		logf("disconnecting %s before disruptive op", di.Address)
		_ = d.Disconnect()
		_ = pollUntil(context.Background(), func() bool {
			conn, err := d.Connected()
			return err != nil || !conn
		}, 50*time.Millisecond, 2*time.Second)
	}
	return nil
}
