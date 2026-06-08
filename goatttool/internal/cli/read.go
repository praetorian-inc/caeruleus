package cli

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"goatttool/internal/bluez"
)

var readFlags struct {
	handle      string
	uuid        string
	offset      uint16
	ascii       bool
	extract     bool
	retry       int
	retryDelay  time.Duration
	watch       bool
	every       time.Duration
	duration    time.Duration
	changesOnly bool
}

func newReadCmd() *cobra.Command {
	c := &cobra.Command{
		Use:     "read",
		Aliases: []string{"char-read"},
		Short:   "Read a characteristic by handle (-a) or UUID (-u)",
		Long: `Read a GATT characteristic and print one line of structured fields:

    0x002a hex=<no-space hex> ascii=<quoted ASCII>

Use -A for ASCII-only (one line, no key/value) or --json for machine output.`,
		RunE: runRead,
	}
	c.Flags().StringVarP(&readFlags.handle, "handle", "a", "", "ATT handle (e.g. 0x002a)")
	c.Flags().StringVarP(&readFlags.uuid, "uuid", "u", "", "characteristic UUID")
	c.Flags().Uint16Var(&readFlags.offset, "offset", 0, "read offset (for long reads)")
	c.Flags().BoolVarP(&readFlags.ascii, "ascii", "A", false, "print just the decoded ASCII payload, no key=value framing")
	c.Flags().BoolVar(&readFlags.extract, "extract", false, "print just the hex payload (lossless, single line) — pipe to `write -n` for round-trip")
	c.Flags().IntVar(&readFlags.retry, "retry", 0, "retry up to N times when the operation fails with a transient BlueZ/HCI error")
	c.Flags().DurationVar(&readFlags.retryDelay, "retry-delay", 500*time.Millisecond, "delay between retries (e.g. 250ms, 2s)")
	c.Flags().BoolVar(&readFlags.watch, "watch", false, "keep re-reading until SIGINT or --duration expires")
	c.Flags().DurationVar(&readFlags.every, "every", 100*time.Millisecond, "watch poll interval")
	c.Flags().DurationVar(&readFlags.duration, "duration", 0, "stop --watch after this duration (0 = until SIGINT)")
	c.Flags().BoolVar(&readFlags.changesOnly, "changes-only", false, "during --watch, only print when the value differs from the previous read")
	return c
}

type readResult struct {
	Handle uint16 `json:"handle"`
	UUID   string `json:"uuid,omitempty"`
	Hex    string `json:"hex"`
	ASCII  string `json:"ascii"`
}

func runRead(cmd *cobra.Command, args []string) error {
	if readFlags.handle == "" && readFlags.uuid == "" {
		return fmt.Errorf("supply -a/--handle or -u/--uuid")
	}
	addr, err := requireBdaddr()
	if err != nil {
		return err
	}

	if readFlags.watch {
		return runReadWatch(addr)
	}

	var obj bluez.GattObject
	var val []byte
	if err := retryable(readFlags.retry, readFlags.retryDelay, func() error {
		ctx, cancel := ctxWithRootTimeout()
		defer cancel()
		s, err := openSession(ctx, addr, true)
		if err != nil {
			return err
		}
		defer s.close()
		o, err := resolveChar(s, readFlags.handle, readFlags.uuid)
		if err != nil {
			return err
		}
		v, err := s.conn.Characteristic(o.Path).ReadValue(readFlags.offset)
		if err != nil {
			return err
		}
		obj, val = o, v
		return nil
	}); err != nil {
		return err
	}

	emitRead(obj.Handle, obj.UUID, val)
	return nil
}

// emitRead renders one read result in whichever format the user asked for.
// Shared by single-shot and --watch paths.
func emitRead(handle uint16, uuid string, val []byte) {
	if formatIsJSON() {
		_ = emitJSON(readResult{Handle: handle, UUID: uuid, Hex: hex.EncodeToString(val), ASCII: asciiize(val)})
		return
	}
	switch {
	case readFlags.extract:
		// Lossless one-line hex: trivially `goatttool write -b X -a Y -n $(read ... --extract)`.
		fmt.Println(hex.EncodeToString(val))
	case readFlags.ascii:
		fmt.Println(string(val))
	default:
		fmt.Println(formatReadLine(handle, val))
	}
}

// runReadWatch opens one session and polls a single characteristic on a
// fixed interval. Stops on SIGINT or when --duration elapses (0 = forever).
// With --changes-only, identical-to-previous reads are suppressed.
func runReadWatch(addr string) error {
	parent := context.Background()
	if readFlags.duration > 0 {
		var cancel context.CancelFunc
		parent, cancel = context.WithTimeout(parent, readFlags.duration)
		defer cancel()
	}
	ctx, cancel := context.WithCancel(parent)
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigCh)
	go func() {
		select {
		case <-sigCh:
			cancel()
		case <-ctx.Done():
		}
	}()

	// Connect with the user's read --timeout window (or default), but the
	// watch loop itself runs against the live session.
	openCtx, openCancel := ctxWithRootTimeout()
	defer openCancel()
	s, err := openSession(openCtx, addr, true)
	if err != nil {
		return err
	}
	defer s.close()

	obj, err := resolveChar(s, readFlags.handle, readFlags.uuid)
	if err != nil {
		return err
	}
	c := s.conn.Characteristic(obj.Path)

	interval := readFlags.every
	if interval <= 0 {
		interval = 100 * time.Millisecond
	}
	t := time.NewTicker(interval)
	defer t.Stop()

	var prev []byte
	first := true
	for {
		if first {
			first = false
		} else {
			select {
			case <-ctx.Done():
				return nil
			case <-t.C:
			}
		}
		val, err := c.ReadValue(readFlags.offset)
		if err != nil {
			if bluez.IsTransientError(err) {
				// keep watching; print a hint and continue
				fmt.Fprintf(os.Stderr, "watch: transient read error: %v\n", err)
				continue
			}
			return err
		}
		if readFlags.changesOnly && bytesEqualReadWatch(prev, val) {
			continue
		}
		emitRead(obj.Handle, obj.UUID, val)
		prev = append(prev[:0], val...)
	}
}

func bytesEqualReadWatch(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// formatReadLine renders one structured line per read result. Used by `read`,
// `batch`, `serve`, and the watch loop so output stays uniform.
func formatReadLine(handle uint16, val []byte) string {
	return fmt.Sprintf("0x%04x hex=%s ascii=%q", handle, hex.EncodeToString(val), asciiize(val))
}

// resolveChar finds the characteristic that matches either the handle or UUID.
// If both are supplied, handle wins.
func resolveChar(s *session, handle, uuid string) (bluez.GattObject, error) {
	if handle != "" {
		h, err := parseHandle(handle)
		if err != nil {
			return bluez.GattObject{}, err
		}
		obj, ok := s.tree.ByHandle[h]
		if !ok {
			return bluez.GattObject{}, fmt.Errorf("no characteristic/descriptor at handle 0x%04x", h)
		}
		return obj, nil
	}
	u := strings.ToLower(uuid)
	matches := s.tree.ByUUID[u]
	if len(matches) == 0 {
		return bluez.GattObject{}, fmt.Errorf("no characteristic with UUID %s", uuid)
	}
	return matches[0], nil
}

// resolveCharOrDescriptor mirrors resolveChar but returns the object path so
// the caller can dispatch read/write to either iface.
func resolveCharOrDescriptor(s *session, handle, uuid string) (bluez.GattObject, error) {
	return resolveChar(s, handle, uuid)
}

// spacedHex formats bytes as "de ad be ef" — matches gatttool's output style.
func spacedHex(b []byte) string {
	var sb strings.Builder
	for i, x := range b {
		if i > 0 {
			sb.WriteByte(' ')
		}
		sb.WriteString(fmt.Sprintf("%02x", x))
	}
	return sb.String()
}

// readValueAuto reads from either a characteristic or descriptor path.
func readValueAuto(conn *bluez.Conn, obj bluez.GattObject) ([]byte, error) {
	switch obj.Kind {
	case "descriptor":
		return conn.Descriptor(obj.Path).ReadValue(0)
	default:
		return conn.Characteristic(obj.Path).ReadValue(0)
	}
}

