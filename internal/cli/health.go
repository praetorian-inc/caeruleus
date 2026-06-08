package cli

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/godbus/dbus/v5"

	"caeruleus/internal/bluez"
)

// errLEScanWedged is returned by verifyLEHealthy when an active discovery
// produces zero events in the given window. It carries a fix hint suitable
// for direct display to the user.
var errLEScanWedged = errors.New("LE scan appears wedged - try `caeruleus adapter power cycle`")

// verifyLEHealthy probes whether the LE side of the controller is
// currently delivering advertisements. It starts a short discovery and
// waits for any InterfacesAdded or PropertiesChanged-with-RSSI event,
// timing out after window.
//
// Returns nil if at least one event arrived. Returns errLEScanWedged if
// no events arrived - most likely a post-HCIDEVRESET stuck state. Other
// errors mean we couldn't even start the probe (no bus, no adapter,
// discovery already-in-progress on a conflicting filter, etc.).
//
// The probe is short on purpose: in a healthy environment near any LE
// devices, the first advert lands within a second or two. Long timeouts
// give false negatives in a Faraday cage but anything <3s is plenty in
// normal rooms.
func verifyLEHealthy(ctx context.Context, window time.Duration) error {
	conn, err := bluez.Dial(root.adapter)
	if err != nil {
		return err
	}
	defer conn.Close()

	// LE-only filter so we don't get tricked by BR/EDR inquiries that
	// some chips can run even when LE scan is dead.
	if err := conn.SetDiscoveryFilter(map[string]dbus.Variant{
		"Transport":     dbus.MakeVariant("le"),
		"DuplicateData": dbus.MakeVariant(true),
	}); err != nil {
		return fmt.Errorf("health probe: SetDiscoveryFilter: %w", err)
	}
	defer func() { _ = conn.SetDiscoveryFilter(map[string]dbus.Variant{}) }()

	subCtx, cancel := context.WithTimeout(ctx, window)
	defer cancel()

	addCh, err := conn.SubscribeInterfacesAdded(subCtx, 16)
	if err != nil {
		return fmt.Errorf("health probe: subscribe added: %w", err)
	}
	propCh, err := conn.Subscribe(subCtx, conn.AdapterPath(), 32)
	if err != nil {
		return fmt.Errorf("health probe: subscribe props: %w", err)
	}

	if err := conn.StartDiscovery(); err != nil {
		// Discovery already in progress is fine - we'll piggy-back on it.
		s := err.Error()
		if !contains(s, "AlreadyExists") && !contains(s, "InProgress") {
			return fmt.Errorf("health probe: StartDiscovery: %w", err)
		}
	}
	defer func() { _ = conn.StopDiscovery() }()

	deadline := time.After(window)
	for {
		select {
		case <-deadline:
			return errLEScanWedged
		case <-subCtx.Done():
			return errLEScanWedged
		case <-addCh:
			return nil
		case ev, ok := <-propCh:
			if !ok {
				continue
			}
			// Any RSSI update from a device path counts - that's a fresh
			// advert decoded by the LE radio.
			if ev.Interface != bluez.IfaceDevice {
				continue
			}
			if _, has := ev.Changed["RSSI"]; has {
				return nil
			}
		}
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
