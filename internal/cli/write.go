package cli

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"caeruleus/internal/bluez"
)

var writeFlags struct {
	handle       string
	uuid         string
	hexVal       string
	strVal       string
	withResponse bool
	eachLine     bool
	retry        int
	retryDelay   time.Duration
}

func newWriteCmd() *cobra.Command {
	c := &cobra.Command{
		Use:     "write",
		Aliases: []string{"char-write"},
		Short:   "Write a value to a characteristic by handle (-a) or UUID (-u)",
		Long: `Write a value (hex via -n, ASCII via -s) to a GATT characteristic and print
one line of structured fields:

    0x002c written=20 type=request

Use --json for machine output.`,
		RunE: runWrite,
	}
	c.Flags().StringVarP(&writeFlags.handle, "handle", "a", "", "ATT handle (e.g. 0x002c)")
	c.Flags().StringVarP(&writeFlags.uuid, "uuid", "u", "", "characteristic UUID")
	c.Flags().StringVarP(&writeFlags.hexVal, "value", "n", "", "hex value to write (e.g. deadbeef)")
	c.Flags().StringVarP(&writeFlags.strVal, "string", "s", "", "ASCII string to write (alternative to -n)")
	c.Flags().BoolVar(&writeFlags.withResponse, "req", false, "use write-with-response (write request) instead of write-command")
	c.Flags().BoolVar(&writeFlags.eachLine, "each-line", false,
		"read stdin one ASCII payload per line and write each to --handle")
	c.Flags().IntVar(&writeFlags.retry, "retry", 0, "retry up to N times when the operation fails with a transient BlueZ/HCI error")
	c.Flags().DurationVar(&writeFlags.retryDelay, "retry-delay", 500*time.Millisecond, "delay between retries")
	return c
}

type writeResult struct {
	Handle uint16 `json:"handle"`
	UUID   string `json:"uuid,omitempty"`
	Wrote  string `json:"wrote_hex"`
	Type   string `json:"type"`
}

func runWrite(cmd *cobra.Command, args []string) error {
	if writeFlags.handle == "" && writeFlags.uuid == "" {
		return fmt.Errorf("supply -a/--handle or -u/--uuid")
	}
	if writeFlags.eachLine {
		return runWriteEachLine()
	}
	if writeFlags.hexVal == "" && writeFlags.strVal == "" {
		return fmt.Errorf("supply -n/--value (hex), -s/--string (ASCII), or --each-line")
	}
	if writeFlags.hexVal != "" && writeFlags.strVal != "" {
		return fmt.Errorf("supply -n or -s, not both")
	}

	addr, err := requireBdaddr()
	if err != nil {
		return err
	}

	var payload []byte
	if writeFlags.hexVal != "" {
		// Detect the common bash-quoting mistake: `write -n "" --req` after
		// a `read --extract` that errored silently. parseHexBytes happens
		// to surface this as "hex value has odd length: --req" because
		// pflag absorbs --req as the value when the user passed an empty
		// string. Catch it explicitly so the error is actionable.
		if strings.HasPrefix(writeFlags.hexVal, "--") {
			return fmt.Errorf("--value/-n received %q - looks like an upstream `$(read --extract)` returned empty; quote with double quotes or check the prior command's exit code", writeFlags.hexVal)
		}
		payload, err = parseHexBytes(writeFlags.hexVal)
		if err != nil {
			return err
		}
	} else {
		payload = []byte(writeFlags.strVal)
	}

	var obj bluez.GattObject
	var wtype bluez.WriteType
	if err := retryable(writeFlags.retry, writeFlags.retryDelay, func() error {
		ctx, cancel := ctxWithRootTimeout()
		defer cancel()
		s, err := openSession(ctx, addr, true)
		if err != nil {
			return err
		}
		defer s.close()

		o, err := resolveChar(s, writeFlags.handle, writeFlags.uuid)
		if err != nil {
			return err
		}

		// Decide write type. --req forces request; otherwise default to
		// command, but escalate to request when the characteristic doesn't
		// advertise write-without-response.
		wt := bluez.WriteCommand
		if writeFlags.withResponse {
			wt = bluez.WriteRequest
		} else if o.Kind == "characteristic" && !propsCan(o.Flags, "write-without-response") && propsCan(o.Flags, "write") {
			wt = bluez.WriteRequest
		}

		switch o.Kind {
		case "descriptor":
			if err := s.conn.Descriptor(o.Path).WriteValue(payload); err != nil {
				return fmt.Errorf("descriptor write: %w", err)
			}
		default:
			if err := s.conn.Characteristic(o.Path).WriteValue(payload, wt); err != nil {
				return fmt.Errorf("write: %w", err)
			}
		}
		obj, wtype = o, wt
		return nil
	}); err != nil {
		return err
	}

	if formatIsJSON() {
		return emitJSON(writeResult{Handle: obj.Handle, UUID: obj.UUID, Wrote: spacedHex(payload), Type: string(wtype)})
	}
	fmt.Println(formatWriteLine(obj.Handle, payload, wtype))
	return nil
}

// formatWriteLine renders one structured line per successful write. Shared
// with `batch` and `serve` for output consistency.
func formatWriteLine(handle uint16, payload []byte, wtype bluez.WriteType) string {
	t := string(wtype)
	if t == "" {
		t = "command"
	}
	return fmt.Sprintf("0x%04x written=%d type=%s", handle, len(payload), t)
}

// runWriteEachLine reads stdin one ASCII payload per line and writes each
// to --handle. Stdin is drained ENTIRELY before we open the BLE session.
//
// This matters for pipelines where the producer also touches the BLE bus
// (a chain like `{ caeruleus read ...; ... } | caeruleus write --each-line`).
// BLE peripherals typically allow only one active connection at a time;
// if we connected up-front we'd hold the link, deadlocking the producer's
// reads. By waiting for EOF first, the producer completes naturally, then
// we connect once and replay all the payloads through one session.
//
// Memory cost is negligible - per-line BLE payloads are small (≤ MTU,
// typically <512 bytes) and N is dictated by the producer's output. The
// trade-off vs streaming is non-existent in practice: there's no use case
// for "submit one payload, then wait, then submit another" - that's just
// two separate `caeruleus write` calls.
func runWriteEachLine() error {
	addr, err := requireBdaddr()
	if err != nil {
		return err
	}

	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 0, 4096), 65536)

	// Drain everything BEFORE touching the bus. Empty lines are skipped.
	var payloads [][]byte
	for scanner.Scan() {
		if len(scanner.Bytes()) == 0 {
			continue
		}
		payloads = append(payloads, append([]byte(nil), scanner.Bytes()...))
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read stdin: %w", err)
	}
	if len(payloads) == 0 {
		// No input → no work, no connection.
		return nil
	}

	ctx, cancel := ctxWithRootTimeout()
	defer cancel()
	s, err := openSession(ctx, addr, true)
	if err != nil {
		return err
	}
	defer s.close()

	obj, err := resolveChar(s, writeFlags.handle, writeFlags.uuid)
	if err != nil {
		return err
	}

	wt := bluez.WriteCommand
	if writeFlags.withResponse {
		wt = bluez.WriteRequest
	} else if obj.Kind == "characteristic" && !propsCan(obj.Flags, "write-without-response") && propsCan(obj.Flags, "write") {
		wt = bluez.WriteRequest
	}

	for _, payload := range payloads {
		var werr error
		switch obj.Kind {
		case "descriptor":
			werr = s.conn.Descriptor(obj.Path).WriteValue(payload)
		default:
			werr = s.conn.Characteristic(obj.Path).WriteValue(payload, wt)
		}
		if werr != nil {
			fmt.Fprintf(os.Stderr, "write %q: %v\n", string(payload), werr)
			continue
		}
		fmt.Println(formatWriteLine(obj.Handle, payload, wt))
	}
	return nil
}
