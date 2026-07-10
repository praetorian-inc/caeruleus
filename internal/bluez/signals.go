package bluez

import (
	"context"
	"fmt"

	"github.com/godbus/dbus/v5"
)

// PropChange is a single PropertiesChanged event delivered to a subscriber.
type PropChange struct {
	Path       dbus.ObjectPath
	Interface  string
	Changed    map[string]dbus.Variant
	Invalidate []string
}

// Subscribe installs a match rule for PropertiesChanged on the path (or any
// path below it, if path ends in "/"). The returned channel closes when ctx
// is done. Caller must consume from the channel to avoid backpressure.
func (c *Conn) Subscribe(ctx context.Context, path dbus.ObjectPath, buf int) (<-chan PropChange, error) {
	rule := []dbus.MatchOption{
		dbus.WithMatchInterface("org.freedesktop.DBus.Properties"),
		dbus.WithMatchMember("PropertiesChanged"),
		dbus.WithMatchSender(BusName),
	}
	if path != "" && path != "/" {
		rule = append(rule, dbus.WithMatchPathNamespace(path))
	}
	if err := c.Bus.AddMatchSignal(rule...); err != nil {
		return nil, fmt.Errorf("AddMatchSignal: %w", err)
	}

	if buf <= 0 {
		buf = 32
	}
	raw := make(chan *dbus.Signal, buf)
	c.Bus.Signal(raw)

	out := make(chan PropChange, buf)
	go func() {
		defer close(out)
		defer c.Bus.RemoveSignal(raw)
		defer func() { _ = c.Bus.RemoveMatchSignal(rule...) }()
		for {
			select {
			case <-ctx.Done():
				return
			case sig, ok := <-raw:
				if !ok {
					return
				}
				if sig.Name != "org.freedesktop.DBus.Properties.PropertiesChanged" {
					continue
				}
				if len(sig.Body) < 3 {
					continue
				}
				iface, _ := sig.Body[0].(string)
				changed, _ := sig.Body[1].(map[string]dbus.Variant)
				invalidate, _ := sig.Body[2].([]string)
				select {
				case out <- PropChange{Path: sig.Path, Interface: iface, Changed: changed, Invalidate: invalidate}:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	return out, nil
}

// SubscribeInterfacesAdded delivers InterfacesAdded events (used by --scan).
func (c *Conn) SubscribeInterfacesAdded(ctx context.Context, buf int) (<-chan InterfacesAdded, error) {
	rule := []dbus.MatchOption{
		dbus.WithMatchInterface("org.freedesktop.DBus.ObjectManager"),
		dbus.WithMatchMember("InterfacesAdded"),
		dbus.WithMatchSender(BusName),
	}
	if err := c.Bus.AddMatchSignal(rule...); err != nil {
		return nil, fmt.Errorf("AddMatchSignal: %w", err)
	}

	if buf <= 0 {
		buf = 32
	}
	raw := make(chan *dbus.Signal, buf)
	c.Bus.Signal(raw)

	out := make(chan InterfacesAdded, buf)
	go func() {
		defer close(out)
		defer c.Bus.RemoveSignal(raw)
		defer func() { _ = c.Bus.RemoveMatchSignal(rule...) }()
		for {
			select {
			case <-ctx.Done():
				return
			case sig, ok := <-raw:
				if !ok {
					return
				}
				if sig.Name != "org.freedesktop.DBus.ObjectManager.InterfacesAdded" {
					continue
				}
				if len(sig.Body) < 2 {
					continue
				}
				path, _ := sig.Body[0].(dbus.ObjectPath)
				ifaces, _ := sig.Body[1].(map[string]map[string]dbus.Variant)
				select {
				case out <- InterfacesAdded{Path: path, Interfaces: ifaces}:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	return out, nil
}

// InterfacesAdded mirrors the ObjectManager.InterfacesAdded signal.
type InterfacesAdded struct {
	Path       dbus.ObjectPath
	Interfaces map[string]map[string]dbus.Variant
}
