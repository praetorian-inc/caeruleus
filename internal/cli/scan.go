package cli

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/godbus/dbus/v5"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/spf13/cobra"

	"goatttool/internal/bluez"
)

var scanFlags struct {
	duration   int
	onlyNew    bool
	name       string
	prefix     string
	keepFilter bool
}

func newScanCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "scan",
		Short: "Scan for nearby BLE devices",
		Long: `scan starts LE device discovery and lists every device BlueZ knows about
after the scan window — both freshly-advertised devices (InterfacesAdded
events) and devices BlueZ had cached from before. Pass --new to suppress
the cached set if you only want devices that advertised in this window.

The bluetoothd-side SetDiscoveryFilter is reset to the default before
returning so subsequent scans by other clients aren't constrained.`,
		RunE: runScan,
	}
	c.Flags().IntVarP(&scanFlags.duration, "duration", "d", 8, "scan duration in seconds")
	c.Flags().BoolVar(&scanFlags.onlyNew, "new", false, "show only devices freshly advertising during this scan; exclude BlueZ's pre-existing snapshot")
	c.Flags().StringVar(&scanFlags.name, "name", "", "only print devices whose name matches this substring")
	c.Flags().StringVar(&scanFlags.prefix, "prefix", "", "only print devices whose address starts with this prefix")
	c.Flags().BoolVar(&scanFlags.keepFilter, "keep-filter", false, "leave the DiscoveryFilter in place after scan returns (default: clear it)")
	return c
}

func runScan(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(scanFlags.duration+5)*time.Second)
	defer cancel()

	conn, err := bluez.Dial(root.adapter)
	if err != nil {
		return err
	}
	defer conn.Close()

	if on, _ := conn.Powered(); !on {
		logf("adapter powered off, turning on")
		if err := conn.SetPowered(true); err != nil {
			return fmt.Errorf("powering adapter: %w", err)
		}
	}

	// Set LE-only discovery + duplicate reporting so we see RSSI updates.
	_ = conn.SetDiscoveryFilter(map[string]dbus.Variant{
		"Transport":     dbus.MakeVariant("le"),
		"DuplicateData": dbus.MakeVariant(true),
	})
	if !scanFlags.keepFilter {
		// Reset the filter when we leave so callers running bluetoothctl
		// (or another goatttool invocation) get an unconstrained default.
		// SetDiscoveryFilter with an empty dict restores defaults.
		defer func() { _ = conn.SetDiscoveryFilter(map[string]dbus.Variant{}) }()
	}

	// Subscribe before starting so we don't race the first ad.
	addCh, err := conn.SubscribeInterfacesAdded(ctx, 64)
	if err != nil {
		return err
	}
	propCh, err := conn.Subscribe(ctx, conn.AdapterPath(), 128)
	if err != nil {
		return err
	}

	if err := conn.StartDiscovery(); err != nil {
		return fmt.Errorf("StartDiscovery: %w", err)
	}
	defer func() { _ = conn.StopDiscovery() }()

	// By default include devices BlueZ has cached from before this scan
	// window. They surface only via GetManagedObjects, not InterfacesAdded,
	// so a pure event-driven scan misses them — which led to confusing
	// "device not found" results when bluetoothd thought a stale device
	// was still around. --new opts back into event-only mode.
	seen := map[dbus.ObjectPath]bluez.DeviceInfo{}
	if !scanFlags.onlyNew {
		if initial, err := conn.Devices(); err == nil {
			for _, di := range initial {
				seen[di.Path] = di
			}
		}
	}

	stop := time.After(time.Duration(scanFlags.duration) * time.Second)
	logf("scanning for %ds…", scanFlags.duration)

loop:
	for {
		select {
		case <-stop:
			break loop
		case <-ctx.Done():
			break loop
		case ev := <-addCh:
			if props, ok := ev.Interfaces[bluez.IfaceDevice]; ok {
				di := propsToDevice(ev.Path, props)
				merge(seen, di)
			}
		case ev := <-propCh:
			if ev.Interface != bluez.IfaceDevice {
				continue
			}
			di, ok := seen[ev.Path]
			if !ok {
				di = bluez.DeviceInfo{Path: ev.Path}
			}
			updateDevice(&di, ev.Changed)
			seen[ev.Path] = di
		}
	}

	// Render.
	list := make([]bluez.DeviceInfo, 0, len(seen))
	for _, di := range seen {
		if !matchesScanFilter(di) {
			continue
		}
		list = append(list, di)
	}
	sort.Slice(list, func(i, j int) bool {
		// Strongest RSSI first; unknowns last.
		if list[i].RSSI == 0 && list[j].RSSI != 0 {
			return false
		}
		if list[j].RSSI == 0 && list[i].RSSI != 0 {
			return true
		}
		return list[i].RSSI > list[j].RSSI
	})

	if formatIsJSON() {
		return emitJSON(list)
	}
	if len(list) == 0 {
		// Distinguish "no devices in range" from "LE scan is wedged":
		// we counted the number of fresh PropertiesChanged/InterfacesAdded
		// events; if zero across the whole window, the radio is the
		// likely culprit and the user wants a different next step than
		// "scan harder."
		freshSeen := 0
		for _, di := range seen {
			if di.RSSI != 0 {
				freshSeen++
			}
		}
		if freshSeen == 0 {
			fmt.Println("no devices found (LE scan returned zero advertisement events — radio may be wedged; try: goatttool adapter power cycle)")
		} else {
			fmt.Println("no devices found")
		}
		return nil
	}
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"ADDRESS", "TYPE", "RSSI", "NAME"})
	for _, di := range list {
		name := di.Name
		if name == "" {
			name = di.Alias
		}
		rssi := ""
		if di.RSSI != 0 {
			rssi = fmt.Sprintf("%d", di.RSSI)
		}
		t.AppendRow(table.Row{di.Address, di.AddrType, rssi, name})
	}
	t.Render()
	return nil
}

func propsToDevice(path dbus.ObjectPath, props map[string]dbus.Variant) bluez.DeviceInfo {
	di := bluez.DeviceInfo{Path: path}
	updateDevice(&di, props)
	return di
}

func updateDevice(di *bluez.DeviceInfo, props map[string]dbus.Variant) {
	if v, ok := props["Address"]; ok {
		di.Address, _ = v.Value().(string)
	}
	if v, ok := props["AddressType"]; ok {
		di.AddrType, _ = v.Value().(string)
	}
	if v, ok := props["Name"]; ok {
		di.Name, _ = v.Value().(string)
	}
	if v, ok := props["Alias"]; ok {
		di.Alias, _ = v.Value().(string)
	}
	if v, ok := props["RSSI"]; ok {
		switch x := v.Value().(type) {
		case int16:
			di.RSSI = x
		case int32:
			di.RSSI = int16(x)
		}
	}
	if v, ok := props["Connected"]; ok {
		di.Connected, _ = v.Value().(bool)
	}
	if v, ok := props["Paired"]; ok {
		di.Paired, _ = v.Value().(bool)
	}
}

func merge(seen map[dbus.ObjectPath]bluez.DeviceInfo, di bluez.DeviceInfo) {
	if cur, ok := seen[di.Path]; ok {
		if di.Name == "" {
			di.Name = cur.Name
		}
		if di.Alias == "" {
			di.Alias = cur.Alias
		}
		if di.AddrType == "" {
			di.AddrType = cur.AddrType
		}
		if di.RSSI == 0 {
			di.RSSI = cur.RSSI
		}
	}
	seen[di.Path] = di
}

func matchesScanFilter(di bluez.DeviceInfo) bool {
	if scanFlags.name != "" {
		hay := strings.ToLower(di.Name + " " + di.Alias)
		if !strings.Contains(hay, strings.ToLower(scanFlags.name)) {
			return false
		}
	}
	if scanFlags.prefix != "" {
		if !strings.HasPrefix(strings.ToUpper(di.Address), strings.ToUpper(scanFlags.prefix)) {
			return false
		}
	}
	return true
}
