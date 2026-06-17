package cli

import (
	"fmt"
	"strconv"
	"time"

	"github.com/spf13/cobra"

	bdaddrPkg "github.com/praetorian-inc/caeruleus/internal/bdaddr"
	"github.com/praetorian-inc/caeruleus/internal/l2cap"
)

// rawWriteFlags backs the `caeruleus raw-write` command - a single-shot,
// arbitrary-length ATT Write Request over a raw L2CAP socket. Bypasses
// BlueZ's per-char MTU enforcement and long-write fragmentation so we
// can test single-PDU writes that the spec wouldn't otherwise allow.
//
// Caller must first disconnect BlueZ from the peer (the kernel refuses
// a second L2CAP socket on CID 0x0004 alongside BlueZ).
var rawWriteFlags struct {
	handle  string
	hex     string
	pattern string
	length  int
}

func newRawWriteCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "raw-write",
		Short: "Single-PDU ATT Write Request via raw L2CAP (bypasses BlueZ MTU + fragmentation)",
		Long: `Sends one ATT Write Request PDU directly over a raw L2CAP socket on
CID 0x0004. Useful for testing target behaviour on oversized or otherwise
malformed single-PDU writes that BlueZ would split (via Long Write) or
refuse.

Pre-requisite: BlueZ must not hold the LE link to -b. Run
  caeruleus disconnect -b <addr>
first.

Provide the value either as explicit hex (-n) or as a length+pattern
(--length N [--pattern BYTE]) for quick repeated-pattern tests.`,
		RunE: runRawWrite,
	}
	c.Flags().StringVarP(&rawWriteFlags.handle, "handle", "a", "", "target ATT handle (e.g. 0x001e)")
	c.Flags().StringVarP(&rawWriteFlags.hex, "value", "n", "", "explicit hex value (overrides --length/--pattern)")
	c.Flags().IntVar(&rawWriteFlags.length, "length", 0, "value length when using --pattern")
	c.Flags().StringVar(&rawWriteFlags.pattern, "pattern", "0x41", "byte pattern to fill --length bytes (default 0x41 'A')")
	return c
}

func runRawWrite(cmd *cobra.Command, args []string) error {
	if rawWriteFlags.handle == "" {
		return fmt.Errorf("supply -a/--handle")
	}
	if rawWriteFlags.hex == "" && rawWriteFlags.length == 0 {
		return fmt.Errorf("supply either -n/--value HEX or --length N")
	}
	handle, err := parseHandle(rawWriteFlags.handle)
	if err != nil {
		return err
	}
	addrStr, err := requireBdaddr()
	if err != nil {
		return err
	}
	if err := requireRoot("raw-write"); err != nil {
		return err
	}

	var value []byte
	if rawWriteFlags.hex != "" {
		value, err = parseHexBytes(rawWriteFlags.hex)
		if err != nil {
			return err
		}
	} else {
		pb, err := parsePatternByte(rawWriteFlags.pattern)
		if err != nil {
			return err
		}
		value = make([]byte, rawWriteFlags.length)
		for i := range value {
			value[i] = pb
		}
	}

	statusf("dialing L2CAP CID 0x0004 -> %s (type=%s)", addrStr, root.addrType)
	conn, err := dialRawATT(addrStr)
	if err != nil {
		return err
	}
	defer conn.Close()

	statusf("sending Write Request handle=0x%04x value_len=%d", handle, len(value))
	r, err := conn.WriteRequestEx(handle, value, 5*time.Second)
	if err != nil {
		return fmt.Errorf("transport: %w", err)
	}
	switch r.Opcode {
	case l2cap.OpWriteResponse:
		fmt.Printf("0x%04x raw-write written=%d resp=Write-Response\n", handle, len(value))
	case l2cap.OpErrorResponse:
		fmt.Printf("0x%04x raw-write written=%d resp=Error-Response req=0x%02x handle=0x%04x code=0x%02x (%s)\n",
			handle, len(value), r.ReqOp, r.Handle, r.ErrCode, l2cap.AttErrorString(r.ErrCode))
	default:
		fmt.Printf("0x%04x raw-write written=%d resp=opcode=0x%02x body_len=%d\n",
			handle, len(value), r.Opcode, len(r.Body))
	}
	return nil
}

// dialRawATT opens a raw L2CAP socket on the ATT fixed channel (CID 0x0004) to
// addr, honoring --addr-type. If BlueZ is holding the link the kernel returns
// EBUSY; we detach BlueZ (Device1.Disconnect) and retry once. The caller closes
// the returned conn. Raw ATT bypasses BlueZ's GATT layer entirely, so reads and
// writes over it never trigger an SMP security elevation / bond - which is why
// the encryption baseline uses it to classify gated handles without pairing.
func dialRawATT(addr string) (*l2cap.Conn, error) {
	at := uint8(l2cap.BDADDRLEPublic)
	if root.addrType == "random" {
		at = l2cap.BDADDRLERandom
	}
	le, err := bdaddrPkg.ParseMAC(addr)
	if err != nil {
		return nil, err
	}
	var peer [6]byte
	for i := 0; i < 6; i++ {
		peer[i] = le[5-i]
	}
	conn, err := l2cap.Dial(peer, at)
	if err != nil && isResourceBusy(err) {
		logf("L2CAP EBUSY - disconnecting BlueZ from %s and retrying", addr)
		if derr := detachBlueZ(addr); derr != nil {
			return nil, fmt.Errorf("detach BlueZ: %w (original dial error: %v)", derr, err)
		}
		time.Sleep(300 * time.Millisecond)
		conn, err = l2cap.Dial(peer, at)
	}
	if err != nil {
		return nil, fmt.Errorf("l2cap dial: %w", err)
	}
	return conn, nil
}

func parsePatternByte(s string) (byte, error) {
	v, err := strconv.ParseUint(s, 0, 8)
	if err != nil {
		return 0, fmt.Errorf("--pattern %q: %w", s, err)
	}
	return byte(v), nil
}
