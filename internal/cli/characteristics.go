package cli

import (
	"fmt"
	"sort"

	"github.com/spf13/cobra"

	"goatttool/internal/bluez"
)

func newCharacteristicsCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "characteristics",
		Aliases: []string{"chars"},
		Short:   "List characteristics (gatttool --characteristics)",
		RunE:    runCharacteristics,
	}
}

type charLine struct {
	Handle      uint16 `json:"handle"`
	ValueHandle uint16 `json:"value_handle"`
	UUID        string `json:"uuid"`
	Props       uint8  `json:"props_mask"`
	Flags       string `json:"flags"`
}

func runCharacteristics(cmd *cobra.Command, args []string) error {
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

	chars := append([]bluez.GattObject(nil), s.tree.Characteristics...)
	sort.Slice(chars, func(i, j int) bool { return chars[i].Handle < chars[j].Handle })

	lines := make([]charLine, 0, len(chars))
	for _, ch := range chars {
		// gatttool emits two handles per characteristic: the declaration handle
		// (one less than the value handle) and the value handle. BlueZ only
		// exposes the value handle directly.
		decl := ch.Handle
		if decl > 0 {
			decl = decl - 1
		}
		lines = append(lines, charLine{
			Handle:      decl,
			ValueHandle: ch.Handle,
			UUID:        ch.UUID,
			Props:       propsMask(ch.Flags),
			Flags:       formatProps(ch.Flags),
		})
	}

	if formatIsJSON() {
		return emitJSON(lines)
	}
	for _, l := range lines {
		fmt.Printf("handle: 0x%04x, char properties: 0x%02x, char value handle: 0x%04x, uuid: %s\n",
			l.Handle, l.Props, l.ValueHandle, l.UUID)
	}
	return nil
}

// propsMask reduces the GATT property flag strings to a Bluetooth Core
// characteristic-properties bit field, for gatttool-compatible output.
func propsMask(flags []string) uint8 {
	var m uint8
	for _, f := range flags {
		switch f {
		case "broadcast":
			m |= 0x01
		case "read":
			m |= 0x02
		case "write-without-response":
			m |= 0x04
		case "write":
			m |= 0x08
		case "notify":
			m |= 0x10
		case "indicate":
			m |= 0x20
		case "authenticated-signed-writes":
			m |= 0x40
		case "reliable-write", "writable-auxiliaries":
			m |= 0x80
		}
	}
	return m
}
