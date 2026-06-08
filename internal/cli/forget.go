package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"caeruleus/internal/bluez"
)

func newForgetCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "forget",
		Aliases: []string{"rm", "remove"},
		Short:   "Tell bluetoothd to purge cached state for -b BDADDR",
		Long: `Removes the Device1 object from bluetoothd's tree via
Adapter1.RemoveDevice. Any cached GATT structure, CCCD subscription state,
and pairing record is dropped. The next connect re-discovers from scratch.

Use this when a peripheral is wedged — e.g. bluetoothd thinks it's still
Connected=true after an ungraceful link teardown, or you want a fresh CCCD
enable instead of BlueZ's auto-restore behaviour.`,
		RunE: runForget,
	}
}

func runForget(cmd *cobra.Command, args []string) error {
	addr, err := requireBdaddr()
	if err != nil {
		return err
	}
	c, err := bluez.Dial(root.adapter)
	if err != nil {
		return err
	}
	defer c.Close()

	path := c.DevicePath(addr)
	if err := c.RemoveDevice(path); err != nil {
		// "No such device" / "Does not exist" is a no-op success.
		s := err.Error()
		if containsAny(s, "Does Not Exist", "No such device", "UnknownObject") {
			fmt.Printf("%s already forgotten\n", addr)
			return nil
		}
		return fmt.Errorf("RemoveDevice: %w", err)
	}
	fmt.Printf("%s forgotten\n", addr)
	return nil
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if len(sub) > 0 && (len(s) >= len(sub)) {
			for i := 0; i+len(sub) <= len(s); i++ {
				if s[i:i+len(sub)] == sub {
					return true
				}
			}
		}
	}
	return false
}
