package bluez

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/godbus/dbus/v5"
)

// ManagedObjects is the raw return shape of org.freedesktop.DBus.ObjectManager
// .GetManagedObjects(): { path -> { iface -> { prop -> variant } } }.
type ManagedObjects map[dbus.ObjectPath]map[string]map[string]dbus.Variant

// GetManagedObjects pulls the full BlueZ object tree in one D-Bus round-trip.
func (c *Conn) GetManagedObjects() (ManagedObjects, error) {
	root := c.Bus.Object(BusName, dbus.ObjectPath("/"))
	var out ManagedObjects
	if err := root.Call("org.freedesktop.DBus.ObjectManager.GetManagedObjects", 0).Store(&out); err != nil {
		return nil, fmt.Errorf("GetManagedObjects: %w", err)
	}
	return out, nil
}

// DeviceInfo summarises a discovered peripheral for scan output.
type DeviceInfo struct {
	Path       dbus.ObjectPath
	Address    string
	AddrType   string
	Name       string
	Alias      string
	RSSI       int16
	Appearance uint16
	Connected  bool
	Paired     bool
	UUIDs      []string
}

// Devices returns every Device1 known to BlueZ on this adapter.
func (c *Conn) Devices() ([]DeviceInfo, error) {
	mo, err := c.GetManagedObjects()
	if err != nil {
		return nil, err
	}
	prefix := string(c.AdapterPath()) + "/dev_"
	var out []DeviceInfo
	for path, ifaces := range mo {
		if !strings.HasPrefix(string(path), prefix) {
			continue
		}
		props, ok := ifaces[IfaceDevice]
		if !ok {
			continue
		}
		di := DeviceInfo{Path: path}
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
		if v, ok := props["Appearance"]; ok {
			switch x := v.Value().(type) {
			case uint16:
				di.Appearance = x
			case int16:
				di.Appearance = uint16(x)
			case uint32:
				di.Appearance = uint16(x)
			}
		}
		if v, ok := props["UUIDs"]; ok {
			di.UUIDs, _ = v.Value().([]string)
		}
		out = append(out, di)
	}
	return out, nil
}

// GattTree captures the discovered services, characteristics, and descriptors
// for a single peripheral, in the order BlueZ presents them.
type GattTree struct {
	Services        []GattObject
	Characteristics []GattObject
	Descriptors     []GattObject
	// ByHandle maps an ATT handle to the object that owns it. The map covers
	// characteristics and descriptors; services aren't useful by handle here.
	ByHandle map[uint16]GattObject
	// ByUUID maps a lowercase UUID to one or more characteristics. Same UUID
	// can appear on multiple services, so the value is a slice.
	ByUUID map[string][]GattObject
}

// EnumerateGatt walks the ObjectManager tree below a device and builds a
// flat GattTree. Caller must have called Device.Connect first so that
// ServicesResolved is true.
func (c *Conn) EnumerateGatt(devPath dbus.ObjectPath) (*GattTree, error) {
	mo, err := c.GetManagedObjects()
	if err != nil {
		return nil, err
	}
	prefix := string(devPath) + "/"
	tree := &GattTree{
		ByHandle: map[uint16]GattObject{},
		ByUUID:   map[string][]GattObject{},
	}
	for path, ifaces := range mo {
		if !strings.HasPrefix(string(path), prefix) {
			continue
		}
		switch {
		case hasIface(ifaces, IfaceService):
			g := readGattObject(path, ifaces[IfaceService], "service")
			tree.Services = append(tree.Services, g)
		case hasIface(ifaces, IfaceCharacteristic):
			g := readGattObject(path, ifaces[IfaceCharacteristic], "characteristic")
			tree.Characteristics = append(tree.Characteristics, g)
			if g.Handle != 0 {
				tree.ByHandle[g.Handle] = g
			}
			u := strings.ToLower(g.UUID)
			tree.ByUUID[u] = append(tree.ByUUID[u], g)
		case hasIface(ifaces, IfaceDescriptor):
			g := readGattObject(path, ifaces[IfaceDescriptor], "descriptor")
			tree.Descriptors = append(tree.Descriptors, g)
			if g.Handle != 0 {
				tree.ByHandle[g.Handle] = g
			}
		}
	}
	return tree, nil
}

func readGattObject(path dbus.ObjectPath, props map[string]dbus.Variant, kind string) GattObject {
	g := GattObject{Path: path, Kind: kind}
	if v, ok := props["UUID"]; ok {
		g.UUID, _ = v.Value().(string)
	}
	if v, ok := props["Handle"]; ok {
		switch n := v.Value().(type) {
		case uint16:
			g.Handle = n
		case int16:
			g.Handle = uint16(n)
		}
	}
	// Fallback for BlueZ < 5.57: the path's last segment is charNNNN/descNNNN.
	if g.Handle == 0 {
		g.Handle = handleFromPath(path)
	}
	if v, ok := props["Flags"]; ok {
		g.Flags, _ = v.Value().([]string)
	}
	// Parent path: trim last "/segment".
	if i := strings.LastIndex(string(path), "/"); i > 0 {
		g.Parent = dbus.ObjectPath(string(path)[:i])
	}
	return g
}

// handleFromPath extracts the hex handle from a BlueZ object path segment
// like "charNNNN" / "descNNNN" / "serviceNNNN". Returns 0 on failure.
func handleFromPath(p dbus.ObjectPath) uint16 {
	s := string(p)
	i := strings.LastIndex(s, "/")
	if i < 0 {
		return 0
	}
	last := s[i+1:]
	for _, pfx := range []string{"char", "desc", "service"} {
		if strings.HasPrefix(last, pfx) {
			n, err := strconv.ParseUint(last[len(pfx):], 16, 16)
			if err != nil {
				return 0
			}
			return uint16(n)
		}
	}
	return 0
}

func hasIface(m map[string]map[string]dbus.Variant, iface string) bool {
	_, ok := m[iface]
	return ok
}
