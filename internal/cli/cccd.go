package cli

import (
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"

	bdaddrPkg "caeruleus/internal/bdaddr"
	"caeruleus/internal/l2cap"
)

var cccdFlags struct {
	char   string
	handle string
	enable string
	value  string
	raw    bool
}

// cccdUUID is the Client Characteristic Configuration Descriptor UUID
// (0x2902 in the 128-bit form). Unused by the current Layer A path —
// BlueZ hides CCCDs from D-Bus and we drive subscription via StartNotify
// — but kept named (vs a magic string in a future PR) for the Layer B
// raw-L2CAP descriptor walk that will need it.
//
//nolint:unused // reserved for the M4 raw-L2CAP path
const cccdUUID = "00002902-0000-1000-8000-00805f9b34fb"

func newCCCDCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "cccd",
		Short: "Manipulate a Client Characteristic Configuration Descriptor",
	}
	c.AddCommand(newCCCDWriteCmd())
	return c
}

func newCCCDWriteCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "write",
		Short: "Write a 2-byte CCCD value via BlueZ (or raw L2CAP if --raw)",
		Long: `Writes a 2-byte CCCD value either via BlueZ's GattDescriptor1.WriteValue
(Layer A, default) or via a raw L2CAP ATT socket alongside BlueZ
(Layer B, --raw).

Layer A works only when BlueZ has actually discovered the CCCD as a
descriptor object — typically when the characteristic advertises NOTIFY
or INDICATE. For chars that don't advertise either (the "hidden notify"
class — a CCCD exists on the wire but the char's properties don't
declare it), BlueZ silently omits the CCCD from its object tree and
Layer A returns a clear error.

Layer B opens an AF_BLUETOOTH/L2CAP socket on ATT CID 0x0004 alongside
the BlueZ-owned LE link and emits an ATT Write Request (opcode 0x12)
to --handle directly. Needs root (CAP_NET_RAW). Kernel coexistence
with bluetoothd is generally fine for one-shot writes on a handle
bluetoothd isn't probing; if it fails, stop bluetoothd or take the
controller exclusive via HCI_CHANNEL_USER.

Selecting the value:
  --enable notify    -> 01 00
  --enable indicate  -> 02 00
  --enable off       -> 00 00
  --value HEX        -> explicit override (must be 2 bytes)

Selecting the target:
  --char  0xHND      -> auto-locate the CCCD on that characteristic
  --handle 0xHND     -> write directly to this descriptor handle
                        (no UUID check; useful when --char isn't enough)`,
		RunE: runCCCDWrite,
	}
	c.Flags().StringVar(&cccdFlags.char, "char", "", "characteristic value handle; CCCD is auto-located on that char")
	c.Flags().StringVar(&cccdFlags.handle, "handle", "", "explicit descriptor handle to write to (skips auto-discovery)")
	c.Flags().StringVar(&cccdFlags.enable, "enable", "", "notify | indicate | off")
	c.Flags().StringVar(&cccdFlags.value, "value", "", "explicit 2-byte hex value (overrides --enable)")
	c.Flags().BoolVar(&cccdFlags.raw, "raw", false, "use raw L2CAP ATT path (Layer B — requires root and --handle)")
	return c
}

func cccdPayload() ([]byte, error) {
	if cccdFlags.value != "" {
		b, err := parseHexBytes(cccdFlags.value)
		if err != nil {
			return nil, err
		}
		if len(b) != 2 {
			return nil, fmt.Errorf("CCCD value must be exactly 2 bytes, got %d", len(b))
		}
		return b, nil
	}
	switch strings.ToLower(cccdFlags.enable) {
	case "notify":
		return []byte{0x01, 0x00}, nil
	case "indicate":
		return []byte{0x02, 0x00}, nil
	case "off", "disable":
		return []byte{0x00, 0x00}, nil
	default:
		return nil, fmt.Errorf("--enable must be notify|indicate|off, or supply --value HEX")
	}
}

func runCCCDWrite(cmd *cobra.Command, args []string) error {
	payload, err := cccdPayload()
	if err != nil {
		return err
	}

	if cccdFlags.raw {
		return runCCCDWriteRaw(payload)
	}

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

	// --handle: an explicit descriptor handle the user knows BlueZ
	// exposes (rare, but supported). Bypass the StartNotify path.
	if cccdFlags.handle != "" {
		h, err := parseHandle(cccdFlags.handle)
		if err != nil {
			return err
		}
		obj, ok := s.tree.ByHandle[h]
		if !ok || obj.Kind != "descriptor" {
			return fmt.Errorf("BlueZ does not expose a descriptor at 0x%04x via D-Bus; try --raw (Layer B) for direct ATT writes", h)
		}
		if err := s.conn.Descriptor(obj.Path).WriteValue(payload); err != nil {
			return fmt.Errorf("CCCD write 0x%04x: %w", obj.Handle, err)
		}
		fmt.Printf("0x%04x written=2 type=request payload=%02x%02x\n", obj.Handle, payload[0], payload[1])
		return nil
	}

	// --char: Layer A canonical path. BlueZ hides CCCDs as descriptor
	// objects but exposes their effect via StartNotify / StopNotify.
	// 0100 == StartNotify, 0200 == StartNotify (indicate; BlueZ picks
	// notify vs indicate from the char's Flags), 0000 == StopNotify.
	if cccdFlags.char == "" {
		return fmt.Errorf("supply --char (value handle) or --handle (descriptor handle)")
	}
	ch, err := parseHandle(cccdFlags.char)
	if err != nil {
		return err
	}
	char, ok := s.tree.ByHandle[ch]
	if !ok || char.Kind != "characteristic" {
		return fmt.Errorf("no characteristic at 0x%04x", ch)
	}
	c := s.conn.Characteristic(char.Path)

	// Map the 2-byte CCCD value to the BlueZ-level intent.
	intent := "StartNotify"
	switch {
	case payload[0] == 0x00 && payload[1] == 0x00:
		intent = "StopNotify"
		if err := c.StopNotify(); err != nil {
			return fmt.Errorf("StopNotify 0x%04x: %w", char.Handle, err)
		}
	default:
		// 0100 = notify, 0200 = indicate, both → StartNotify; BlueZ picks
		// the right CCCD value based on the char's advertised Flags.
		if err := c.StartNotify(); err != nil {
			return fmt.Errorf("StartNotify 0x%04x: %w (char must advertise notify or indicate for Layer A — use --raw for chars without)", char.Handle, err)
		}
	}
	fmt.Printf("0x%04x %s=ok (CCCD effectively %02x%02x via BlueZ)\n", char.Handle, intent, payload[0], payload[1])
	return nil
}

// runCCCDWriteRaw opens a raw L2CAP socket on the ATT fixed channel
// (CID 0x0004) toward the peripheral and sends an ATT Write Request
// (opcode 0x12) to the user-supplied handle. Bypasses BlueZ's
// descriptor-object filtering, so it works on the "hidden notify"
// class of CCCDs that BlueZ doesn't expose via D-Bus.
//
// Requires root (CAP_NET_RAW for the socket). The peripheral must be
// reachable; we don't bring up an LE connection ourselves — BlueZ's
// existing link (if any) carries the ATT traffic, and the kernel
// routes our PDUs onto that link.
//
// --handle is required (we don't auto-discover the CCCD because the
// whole point of --raw is to reach handles BlueZ hides).
func runCCCDWriteRaw(payload []byte) error {
	if cccdFlags.handle == "" {
		return fmt.Errorf("cccd write --raw requires --handle (the descriptor handle to write — use this when BlueZ hides the CCCD from D-Bus because the char doesn't advertise notify/indicate)")
	}
	handle, err := parseHandle(cccdFlags.handle)
	if err != nil {
		return err
	}
	addrStr, err := requireBdaddr()
	if err != nil {
		return err
	}
	if err := requireRoot("cccd write --raw"); err != nil {
		return err
	}

	// bdaddr.ParseMAC returns LE order (LSB-first, wire layout); the
	// L2CAP Sockaddr expects "natural" order (MSB-first) which the
	// kernel reverses internally. Swap.
	leAddr, err := bdaddrPkg.ParseMAC(addrStr)
	if err != nil {
		return err
	}
	var peer [6]byte
	for i := 0; i < 6; i++ {
		peer[i] = leAddr[5-i]
	}

	addrType := uint8(l2cap.BDADDRLEPublic)
	if root.addrType == "random" {
		addrType = l2cap.BDADDRLERandom
	}

	logf("opening raw L2CAP ATT socket to %s (type=%s)", addrStr, root.addrType)
	conn, err := l2cap.Dial(peer, addrType)
	if err != nil {
		return err
	}
	defer conn.Close()

	if err := conn.WriteRequest(handle, payload, 3*time.Second); err != nil {
		return fmt.Errorf("ATT Write Request 0x%04x: %w", handle, err)
	}
	fmt.Printf("0x%04x written=%d via=l2cap-att-write-request payload=%02x%02x\n",
		handle, len(payload), payload[0], payload[1])
	return nil
}
