package cli

import (
	"fmt"
	"sort"

	"github.com/spf13/cobra"

	"github.com/praetorian-inc/caeruleus/internal/bluez"
)

func newPrimaryCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "primary",
		Short: "List primary services (gatttool --primary)",
		RunE:  runPrimary,
	}
}

type svcLine struct {
	Start uint16 `json:"start_handle"`
	End   uint16 `json:"end_handle"`
	UUID  string `json:"uuid"`
}

func runPrimary(cmd *cobra.Command, args []string) error {
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

	lines := computeServiceRanges(s.tree)
	if formatIsJSON() {
		return emitJSON(lines)
	}
	for _, l := range lines {
		fmt.Printf("attr handle: 0x%04x, end grp handle: 0x%04x uuid: %s\n", l.Start, l.End, l.UUID)
	}
	return nil
}

// computeServiceRanges walks all GATT objects and infers each service's end
// group handle from the highest handle in its subtree (chars + descriptors).
func computeServiceRanges(tree *bluez.GattTree) []svcLine {
	maxHnd := map[string]uint16{}
	for _, ch := range tree.Characteristics {
		parent := string(ch.Parent)
		if ch.Handle > maxHnd[parent] {
			maxHnd[parent] = ch.Handle
		}
	}
	for _, d := range tree.Descriptors {
		// Descriptor parent is the characteristic; walk up one more step to
		// find the service path.
		charPath := string(d.Parent)
		for _, ch := range tree.Characteristics {
			if string(ch.Path) == charPath {
				if d.Handle > maxHnd[string(ch.Parent)] {
					maxHnd[string(ch.Parent)] = d.Handle
				}
				break
			}
		}
	}
	var out []svcLine
	for _, sv := range tree.Services {
		end := maxHnd[string(sv.Path)]
		if end < sv.Handle {
			end = sv.Handle
		}
		out = append(out, svcLine{Start: sv.Handle, End: end, UUID: sv.UUID})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Start < out[j].Start })
	return out
}
