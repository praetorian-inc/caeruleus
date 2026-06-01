package cli

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"goatttool/internal/bdaddr"
	"goatttool/internal/bluez"
)

// bdaddrOpenManager wraps bdaddr.OpenManager so adapter.go's MGMT read in
// `adapter info` doesn't have to deal with import details inline.
func bdaddrOpenManager(idx uint16) (*bdaddr.Manager, error) {
	return bdaddr.OpenManager(idx)
}

func newAdapterCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "adapter",
		Short: "Inspect or recover the local HCI adapter",
	}
	c.AddCommand(newAdapterPowerCmd())
	c.AddCommand(newAdapterInfoCmd())
	return c
}

func newAdapterPowerCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "power [on|off|cycle]",
		Short: "Toggle Adapter1.Powered (the equivalent of bluetoothctl 'power on/off')",
		Long: `power on/off/cycle drives the BlueZ Adapter1.Powered property. This is
the supported way to bring the LE stack down and back up cleanly, and the
right recovery when the controller is stuck in INQUIRY mode or otherwise
not receiving LE advertisements. goatttool's own operations (notably
bdaddr --set) now use this rather than the legacy HCIDEVRESET ioctl, so
the stuck state shouldn't arise from our own paths — but external tools
or kernel resets can still wedge it, hence this manual rescue.

cycle = off → wait briefly → on; useful as a one-shot rescue.

Examples:
  goatttool adapter power on
  goatttool adapter power off
  goatttool adapter power cycle`,
		Args: cobra.ExactArgs(1),
		RunE: runAdapterPower,
	}
	return c
}

var adapterInfoFlags struct {
	verbose bool
}

func newAdapterInfoCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "info",
		Short: "Print adapter info as a single key=value line (--verbose for the multi-line form)",
		RunE:  runAdapterInfo,
	}
	c.Flags().BoolVar(&adapterInfoFlags.verbose, "verbose", false, "print one labelled line per field (slower to scan, easier to read)")
	return c
}

func runAdapterPower(cmd *cobra.Command, args []string) error {
	switch strings.ToLower(args[0]) {
	case "on":
		return setPower(true)
	case "off":
		return setPower(false)
	case "cycle":
		return cyclePower()
	default:
		return fmt.Errorf("usage: adapter power on|off|cycle")
	}
}

func setPower(on bool) error {
	c, err := bluez.Dial(root.adapter)
	if err != nil {
		return err
	}
	defer c.Close()
	if err := c.SetPowered(on); err != nil {
		return fmt.Errorf("set Powered=%v: %w (run with sudo?)", on, err)
	}
	// Wait briefly for the property to settle so callers can chain.
	err = pollUntil(context.Background(), func() bool {
		cur, err := c.Powered()
		return err == nil && cur == on
	}, 80*time.Millisecond, 3*time.Second)
	if err != nil {
		return fmt.Errorf("Powered did not converge to %v within 3s", on)
	}
	fmt.Printf("adapter %s Powered=%v\n", root.adapter, on)
	return nil
}

// cyclePower performs an off→on toggle. Used by `adapter power cycle` and
// implicitly by `bdaddr --set` to apply the vendor write — replacing the
// HCIDEVRESET ioctl which reliably wedged Intel adapters in INQUIRY mode.
func cyclePower() error {
	if err := setPower(false); err != nil {
		return err
	}
	// Brief settle window — the controller drops to its idle state and
	// the kernel deallocates scan parameters here. Coming back up before
	// this is finished can lead to the very stuck-INQUIRY state we're
	// trying to escape.
	time.Sleep(400 * time.Millisecond)
	return setPower(true)
}

func runAdapterInfo(cmd *cobra.Command, args []string) error {
	c, err := bluez.Dial(root.adapter)
	if err != nil {
		return err
	}
	defer c.Close()
	addrV, _ := c.AdpObj.GetProperty(bluez.IfaceAdapter + ".Address")
	powered, _ := c.Powered()
	discoveringV, _ := c.AdpObj.GetProperty(bluez.IfaceAdapter + ".Discovering")
	nameV, _ := c.AdpObj.GetProperty(bluez.IfaceAdapter + ".Name")
	bluezAddr, _ := addrV.Value().(string)
	name, _ := nameV.Value().(string)
	discovering, _ := discoveringV.Value().(bool)

	// MGMT chip-live read. Failure is informational (root needed).
	mgmtAddr := ""
	mgmtErr := ""
	if idx, idxErr := adapterIndex(root.adapter); idxErr == nil {
		if mgr, err := bdaddrOpenManager(idx); err == nil {
			defer mgr.Close()
			if info, err := mgr.ReadControllerInfo(); err == nil {
				mgmtAddr = info.Address
			} else {
				mgmtErr = err.Error()
			}
		} else {
			mgmtErr = "root required"
		}
	}

	if adapterInfoFlags.verbose {
		fmt.Printf("adapter=%s name=%v powered=%v discovering=%v\n",
			root.adapter, name, powered, discovering)
		fmt.Printf("addr-bluez=%s   (bluetoothd cache; what Adapter1.Address reports)\n", bluezAddr)
		switch {
		case mgmtAddr != "":
			fmt.Printf("addr-mgmt=%s   (chip-live via MGMT; what's actually used for outgoing connections)\n", mgmtAddr)
			if !strings.EqualFold(bluezAddr, mgmtAddr) {
				fmt.Printf("WARN: BlueZ cache is stale. Refresh via `goatttool bdaddr --refresh-bluez` (note: may revert volatile spoof).\n")
			}
		case mgmtErr != "":
			fmt.Printf("addr-mgmt=<%s>\n", mgmtErr)
		}
		return nil
	}

	// Compact default: one parseable key=value line. Token-efficient and
	// trivially greppable.
	parts := []string{
		fmt.Sprintf("adapter=%s", root.adapter),
		fmt.Sprintf("name=%q", name),
		fmt.Sprintf("powered=%v", powered),
		fmt.Sprintf("discovering=%v", discovering),
		fmt.Sprintf("addr.bluez=%s", bluezAddr),
	}
	switch {
	case mgmtAddr != "":
		parts = append(parts, fmt.Sprintf("addr.mgmt=%s", mgmtAddr))
		if !strings.EqualFold(bluezAddr, mgmtAddr) {
			parts = append(parts, "addr.mismatch=true")
		}
	case mgmtErr != "":
		parts = append(parts, fmt.Sprintf("addr.mgmt-err=%q", mgmtErr))
	}
	fmt.Println(strings.Join(parts, " "))
	return nil
}
