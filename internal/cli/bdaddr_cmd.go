package cli

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"goatttool/internal/bdaddr"
)

var bdaddrFlags struct {
	show         bool
	set          string
	transient    bool
	noReset      bool // legacy alias for "skip the apply step"; default is now skip
	refreshBluez bool // opt-in to HCIDEVRESET + conditional INQUIRY clear
	vendor       string
	listVendors  bool
}

func newBdaddrCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "bdaddr",
		Short: "Read or spoof the adapter's BD_ADDR (needs root; vendor-specific)",
		Long: `bdaddr reads or rewrites the local controller's Bluetooth address.

Without flags or with --show, it reads the current address and the controller
manufacturer via BlueZ's Management API.

With --set XX:XX:XX:XX:XX:XX it issues the vendor-specific HCI write command
matching the controller manufacturer, then performs an Adapter1.Powered cycle
so the kernel re-reads BD_ADDR from the chip — without this the kernel keeps
returning the OEM address from the in-memory cache populated at last HCI_UP
and the post-write verification is meaningless. The soft cycle preserves the
volatile BD_ADDR on common chips (Intel, Broadcom), so the spoof survives.

Workflows (try in order — stop at the first that sticks):

  bdaddr --set XX                  # DEFAULT. Vendor write + soft Adapter1.Powered
                                     cycle to refresh the kernel/bluetoothd cache.
                                     Drops any active LE links briefly. Spoof
                                     survives on chips that retain volatile
                                     BD_ADDR across HCI_DOWN/UP. Confirmed working
                                     on Intel AX-series and most Broadcom parts.

  bdaddr --set XX --refresh-bluez  # LAST RESORT. Vendor write + HCIDEVRESET. On
                                     Intel AX this reload reverts the spoof and
                                     can leave the controller stuck in BR/EDR
                                     INQUIRY mode (a conditional rescue power-
                                     cycle runs after). Use only if plain --set
                                     leaves bluetoothd reporting the old addr.

This is fundamentally vendor-specific. Some chips (notably newer Intel
AX-series BLE controllers) keep the BD_ADDR in non-rewritable storage and
ignore the vendor write; --show will report a working address but --set will
silently fail. Try anyway, but report a clear status.`,
		RunE: runBdaddr,
	}
	c.Flags().BoolVar(&bdaddrFlags.show, "show", false, "read and print the current adapter BD_ADDR + manufacturer")
	c.Flags().StringVar(&bdaddrFlags.set, "set", "", "rewrite the adapter BD_ADDR to this MAC")
	c.Flags().BoolVar(&bdaddrFlags.transient, "transient", false, "do not persist the change (informational only — kernel decides)")
	c.Flags().BoolVar(&bdaddrFlags.refreshBluez, "refresh-bluez", false,
		"LAST RESORT only — use plain --set first. Runs HCIDEVRESET after the vendor write; on some chips (notably Intel AX) this also reloads OTP and silently reverts the spoof, and can leave the controller stuck in BR/EDR INQUIRY mode. Reach for this only when plain --set leaves bluetoothd reporting the old addr.")
	// Backward-compat: --no-apply was the previous-default-disabler; the
	// behaviour it produced is now the default, so the flag is a no-op.
	c.Flags().BoolVar(&bdaddrFlags.noReset, "no-apply", false, "no-op; the apply step is off by default now")
	c.Flags().BoolVar(&bdaddrFlags.noReset, "no-reset", false, "deprecated alias for --no-apply (no-op)")
	_ = c.Flags().MarkHidden("no-apply")
	_ = c.Flags().MarkHidden("no-reset")
	c.Flags().StringVar(&bdaddrFlags.vendor, "vendor", "", "force a specific vendor command (csr|broadcom|ti|intel|zeevo|st|cypress|ericsson)")
	c.Flags().BoolVar(&bdaddrFlags.listVendors, "list-vendors", false, "list known vendor command tables and exit")
	return c
}

func runBdaddr(cmd *cobra.Command, args []string) error {
	if bdaddrFlags.listVendors {
		for _, v := range bdaddr.KnownVendors() {
			fmt.Printf("%-10s opcode=0x%04x  payload=%s\n", v.Name, v.Opcode, v.Description)
		}
		return nil
	}

	// AF_BLUETOOTH raw + Adapter1.Powered both need root; fail early so we
	// don't half-issue a vendor write or leave the controller in a weird
	// state.
	if err := requireRoot("bdaddr"); err != nil {
		return err
	}

	idx, err := adapterIndex(root.adapter)
	if err != nil {
		return err
	}

	mgr, err := bdaddr.OpenManager(idx)
	if err != nil {
		return err
	}
	defer mgr.Close()

	info, err := mgr.ReadControllerInfo()
	if err != nil {
		return fmt.Errorf("read controller info: %w", err)
	}

	if bdaddrFlags.set == "" || bdaddrFlags.show {
		fmt.Printf("adapter:        %s (hci%d)\n", info.Address, idx)
		fmt.Printf("manufacturer:   %d (%s)\n", info.Manufacturer, info.ManufacturerName)
		fmt.Printf("supported set:  %s\n", strings.Join(info.Settings, ","))
		if bdaddrFlags.set == "" {
			return nil
		}
	}

	target, err := bdaddr.ParseMAC(bdaddrFlags.set)
	if err != nil {
		return err
	}
	vendor := bdaddrFlags.vendor
	if vendor == "" {
		vendor = bdaddr.VendorForManufacturer(info.Manufacturer)
	}
	if vendor == "" {
		return fmt.Errorf("no known vendor command for manufacturer %d — pass --vendor to force one", info.Manufacturer)
	}

	logf("issuing vendor=%s write of %s on hci%d", vendor, bdaddrFlags.set, idx)
	if err := bdaddr.SetAddress(idx, vendor, target); err != nil {
		return fmt.Errorf("vendor write failed: %w", err)
	}
	if bdaddrFlags.refreshBluez {
		// --refresh-bluez opt-in path: HCIDEVRESET so bluetoothd re-reads
		// the address, with a conditional INQUIRY-clear power-cycle if
		// the reset leaves the controller wedged. WARNING: the power
		// cycle, if it fires, re-loads OTP and undoes the spoof. This is
		// the right path only when the user explicitly wants bluetoothd
		// to display the new address.
		if err := drainConnectedPeripherals(); err != nil {
			failf("could not drain peripherals before reset: %v", err)
		}
		if err := bdaddr.ResetAdapter(idx); err != nil {
			return fmt.Errorf("HCIDEVRESET hci%d: %w", idx, err)
		}
		if err := clearStuckINQUIRY(); err != nil {
			failf("post-reset INQUIRY clear: %v (try: goatttool adapter power-cycle)", err)
		}
	} else {
		// Soft refresh path. The kernel populates hdev->bdaddr from the
		// chip during HCI_UP and never re-reads it afterwards, so both
		// MGMT_OP_READ_INFO and HCIGETDEVINFO return the OEM value right
		// after a successful vendor write — making a chip-live readback
		// impossible without a power cycle. Adapter1.Powered=false→true
		// flushes that cache; on Intel/Broadcom/etc. the firmware
		// retains volatile BD_ADDR across this soft cycle, so the spoof
		// survives. (HCIDEVRESET would also re-init but reloads OTP on
		// Intel and reverts the spoof — that's the --refresh-bluez path.)
		if err := drainConnectedPeripherals(); err != nil {
			failf("could not drain peripherals before power cycle: %v", err)
		}
		if err := cyclePower(); err != nil {
			failf("Adapter1.Powered cycle failed: %v (post-write readback may be stale)", err)
		}
	}

	// Re-read to confirm. The cycle above (or HCIDEVRESET above that) is
	// what makes this readback chip-live; without it, MGMT returns the
	// pre-write cached value and we'd print a misleading "rejected".
	info2, err := mgr.ReadControllerInfo()
	if err == nil {
		fmt.Printf("post-write addr: %s (wanted %s)\n", info2.Address, bdaddrFlags.set)
		if strings.EqualFold(info2.Address, bdaddrFlags.set) {
			fmt.Println("OK — adapter accepted the new address")
		} else {
			fmt.Println("WARNING — adapter rejected or ignored the vendor write (read-back differs)")
		}
	}
	return nil
}

// adapterIndex parses "hciN" to N. Returns 0 for plain "hci0".
func adapterIndex(name string) (uint16, error) {
	if !strings.HasPrefix(name, "hci") {
		return 0, fmt.Errorf("adapter %q is not in hciN form", name)
	}
	var n int
	if _, err := fmt.Sscanf(name, "hci%d", &n); err != nil {
		return 0, fmt.Errorf("parse adapter index %q: %w", name, err)
	}
	return uint16(n), nil
}
