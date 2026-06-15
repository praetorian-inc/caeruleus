// Package bluez wraps the org.bluez D-Bus interfaces we need to talk to a
// remote GATT server through bluetoothd. We hand-roll the bits we use rather
// than depend on a generated wrapper.
package bluez

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/godbus/dbus/v5"
)

const (
	BusName = "org.bluez"

	IfaceAdapter        = "org.bluez.Adapter1"
	IfaceDevice         = "org.bluez.Device1"
	IfaceService        = "org.bluez.GattService1"
	IfaceCharacteristic = "org.bluez.GattCharacteristic1"
	IfaceDescriptor     = "org.bluez.GattDescriptor1"
)

// Conn is a thin handle around a system-bus connection plus a chosen adapter.
type Conn struct {
	Bus     *dbus.Conn
	Adapter string // e.g. "hci0"
	AdpObj  dbus.BusObject
}

// Dial connects to the system bus and selects the named adapter (default "hci0").
func Dial(adapter string) (*Conn, error) {
	if adapter == "" {
		adapter = "hci0"
	}
	bus, err := dbus.SystemBus()
	if err != nil {
		return nil, fmt.Errorf("system bus: %w", err)
	}
	path := dbus.ObjectPath("/org/bluez/" + adapter)
	obj := bus.Object(BusName, path)
	// Touch a property so we fail loudly if the adapter doesn't exist.
	if _, err := getProp(obj, IfaceAdapter, "Address"); err != nil {
		bus.Close()
		return nil, fmt.Errorf("adapter %s: %w", adapter, err)
	}
	return &Conn{Bus: bus, Adapter: adapter, AdpObj: obj}, nil
}

func (c *Conn) Close() error {
	if c.Bus != nil {
		return c.Bus.Close()
	}
	return nil
}

// AdapterPath returns the D-Bus path for the active adapter.
func (c *Conn) AdapterPath() dbus.ObjectPath {
	return dbus.ObjectPath("/org/bluez/" + c.Adapter)
}

// Powered returns the current power state of the adapter.
func (c *Conn) Powered() (bool, error) {
	v, err := getProp(c.AdpObj, IfaceAdapter, "Powered")
	if err != nil {
		return false, err
	}
	b, ok := v.(bool)
	if !ok {
		return false, fmt.Errorf("Powered: unexpected type %T", v)
	}
	return b, nil
}

// SetPowered turns the adapter on or off.
func (c *Conn) SetPowered(on bool) error {
	return setProp(c.AdpObj, IfaceAdapter, "Powered", on)
}

// SetDiscoveryFilter sets a discovery filter dictionary on the adapter.
func (c *Conn) SetDiscoveryFilter(filter map[string]dbus.Variant) error {
	return c.AdpObj.Call(IfaceAdapter+".SetDiscoveryFilter", 0, filter).Err
}

// StartDiscovery begins LE/Classic device discovery; pair with StopDiscovery.
func (c *Conn) StartDiscovery() error {
	return c.AdpObj.Call(IfaceAdapter+".StartDiscovery", 0).Err
}

func (c *Conn) StopDiscovery() error {
	return c.AdpObj.Call(IfaceAdapter+".StopDiscovery", 0).Err
}

// RemoveDevice forces bluetoothd to forget a device, so the next discovery
// will report it fresh (useful when state is stuck).
func (c *Conn) RemoveDevice(devPath dbus.ObjectPath) error {
	return c.AdpObj.Call(IfaceAdapter+".RemoveDevice", 0, devPath).Err
}

// DevicePath returns the canonical D-Bus path for a peripheral MAC.
func (c *Conn) DevicePath(addr string) dbus.ObjectPath {
	return dbus.ObjectPath(fmt.Sprintf("/org/bluez/%s/dev_%s",
		c.Adapter, strings.ReplaceAll(strings.ToUpper(addr), ":", "_")))
}

// Device represents a single remote BLE peripheral.
type Device struct {
	conn *Conn
	Path dbus.ObjectPath
	obj  dbus.BusObject
}

// Device returns a handle for the given MAC; it does not connect.
func (c *Conn) Device(addr string) *Device {
	path := c.DevicePath(addr)
	return &Device{conn: c, Path: path, obj: c.Bus.Object(BusName, path)}
}

// Address returns the BD_ADDR string of the peripheral.
func (d *Device) Address() (string, error) {
	v, err := getProp(d.obj, IfaceDevice, "Address")
	if err != nil {
		return "", err
	}
	s, _ := v.(string)
	return s, nil
}

// Name returns the GAP-advertised name (or alias when no Name is set).
func (d *Device) Name() (string, error) {
	if v, err := getProp(d.obj, IfaceDevice, "Name"); err == nil {
		if s, ok := v.(string); ok {
			return s, nil
		}
	}
	v, err := getProp(d.obj, IfaceDevice, "Alias")
	if err != nil {
		return "", err
	}
	s, _ := v.(string)
	return s, nil
}

// Connected reports current ACL state.
func (d *Device) Connected() (bool, error) {
	v, err := getProp(d.obj, IfaceDevice, "Connected")
	if err != nil {
		return false, err
	}
	b, _ := v.(bool)
	return b, nil
}

// ServicesResolved reports whether GATT discovery has completed.
func (d *Device) ServicesResolved() (bool, error) {
	v, err := getProp(d.obj, IfaceDevice, "ServicesResolved")
	if err != nil {
		return false, err
	}
	b, _ := v.(bool)
	return b, nil
}

// SetAddressType sets the address type ("public" or "random") before connect.
func (d *Device) SetAddressType(t string) error {
	if t == "" {
		return nil
	}
	return setProp(d.obj, IfaceDevice, "AddressType", t)
}

// Exists reports whether the Device1 object is currently registered on the bus.
// BlueZ purges unpaired devices a short time after disconnect, so callers may
// need to re-trigger discovery before calling Connect.
func (d *Device) Exists() bool {
	_, err := d.obj.GetProperty(IfaceDevice + ".Address")
	return err == nil
}

// Connect establishes an LE ACL link and waits for ServicesResolved. If the
// Device1 object is not registered on the bus yet, a brief discovery pass is
// run first (BlueZ purges unpaired peripherals after disconnect). On certain
// transient failures (I/O error, le-connection-abort-by-local, page timeout)
// we fall back to RemoveDevice + re-discover + retry once - BlueZ may have
// a stuck Device1 with Connected=true from an ungraceful prior teardown,
// and only purging the object lets a fresh ACL link complete.
// timeout caps the whole operation including discovery and service resolution.
func (d *Device) Connect(ctx context.Context, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	err := d.connectOnce(ctx)
	switch {
	case err == nil:
		return d.WaitServicesResolved(ctx)
	case IsStuckConnect(err):
		// BlueZ's view is wrong (stuck Connected=true, "already in
		// progress"). Purge the Device1 and try fresh - only safe here
		// because the stuck-Connected state needs a hard reset.
		_ = d.conn.RemoveDevice(d.Path)
		time.Sleep(300 * time.Millisecond)
		if err := d.connectOnce(ctx); err != nil {
			return fmt.Errorf("Connect (after RemoveDevice retry): %w", err)
		}
		return d.WaitServicesResolved(ctx)
	case IsTransientLE(err):
		// LE radio momentarily unhappy. Just wait + retry; DO NOT purge.
		// RemoveDevice here would wipe the cache we'd need when fresh
		// discovery is also unresponsive (post-HCIDEVRESET, stuck LE scan).
		time.Sleep(500 * time.Millisecond)
		if err := d.connectOnce(ctx); err != nil {
			return fmt.Errorf("Connect (after transient-LE retry): %w", err)
		}
		return d.WaitServicesResolved(ctx)
	default:
		return err
	}
}

// ConnectLink establishes the ACL link and waits for Connected=true, WITHOUT
// waiting for GATT ServicesResolved. Pairing and other link-level operations
// need only the link, not the resolved attribute table - and full GATT
// discovery can be very slow on peripherals with lax connection parameters,
// so waiting for it would needlessly time out.
func (d *Device) ConnectLink(ctx context.Context, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	if err := d.connectOnce(ctx); err != nil {
		if !IsTransientError(err) {
			return err
		}
		time.Sleep(300 * time.Millisecond)
		if err := d.connectOnce(ctx); err != nil {
			return err
		}
	}
	t := time.NewTicker(100 * time.Millisecond)
	defer t.Stop()
	for {
		if c, _ := d.Connected(); c {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("ConnectLink: %w", ctx.Err())
		case <-t.C:
		}
	}
}

// connectOnce is one connect attempt: ensure the Device1 exists, then call
// Device1.Connect if not already connected. Errors are wrapped with a hint
// when they match a well-known opaque kernel/BlueZ message that has a known
// recovery procedure.
func (d *Device) connectOnce(ctx context.Context) error {
	if !d.Exists() {
		if err := d.conn.ensureDeviceVisible(ctx, d.Path, 6*time.Second); err != nil {
			return hintWrap(err)
		}
	}
	if connected, _ := d.Connected(); connected {
		return nil
	}
	if call := d.obj.Call(IfaceDevice+".Connect", 0); call.Err != nil {
		return hintWrap(fmt.Errorf("Connect: %w", call.Err))
	}
	return nil
}

// hintWrap augments well-known opaque BlueZ/kernel errors with a one-line
// fix suggestion. The original error is kept via %w so callers using
// errors.Is / errors.As keep working unchanged.
func hintWrap(err error) error {
	if err == nil {
		return nil
	}
	s := err.Error()
	switch {
	case strings.Contains(s, "Input/output error"):
		return fmt.Errorf("%w (often: ATT MTU too high for this peripheral, or post-HCIDEVRESET stuck state. Try `caeruleus mtu --set 247` or `caeruleus adapter power cycle`)", err)
	case strings.Contains(s, "not seen during discovery"):
		return fmt.Errorf("%w (LE scan may be unresponsive; try `caeruleus adapter power cycle`)", err)
	case strings.Contains(s, "le-connection-abort-by-local"):
		return fmt.Errorf("%w (peripheral aborted the LE link; the firmware may be holding a stale supervision-timeout window - try `caeruleus forget` then retry)", err)
	}
	return err
}

// IsTransientError reports whether an error is retry-able at all (either
// kind of transient). The retry policy splits further into IsStuckConnect
// (BlueZ state needs purging) vs IsTransientLE (just wait + retry, do NOT
// purge - RemoveDevice on a discovery-side failure makes things worse).
func IsTransientError(err error) bool {
	return IsStuckConnect(err) || IsTransientLE(err)
}

// IsStuckConnect matches errors that suggest BlueZ's view of the device
// is wrong (already-in-progress, stale Connected=true). Retry path:
// RemoveDevice + reconnect from scratch.
func IsStuckConnect(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	for _, hit := range []string{
		"Operation already in progress",
		"Already Connected",
		"AlreadyConnected",
	} {
		if strings.Contains(s, hit) {
			return true
		}
	}
	return false
}

// IsTransientLE matches errors that suggest the LE link / radio is
// momentarily unhappy but BlueZ's tree is fine. Retry path: wait + retry,
// keep the cached Device1 (purging it removes the only path we have when
// fresh discovery is unresponsive - e.g. post-HCIDEVRESET).
func IsTransientLE(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	for _, hit := range []string{
		"Input/output error",
		"le-connection-abort-by-local",
		"br-connection-page-timeout",
		"Software caused connection abort",
		"Connection refused",
		"not seen during discovery",
		"context deadline exceeded",
		"Resource Not Ready",
		"Not connected",
		// BlueZ rejects connect attempts that arrive while it's still
		// finishing teardown of the previous link. Common when two
		// caeruleus invocations run back-to-back from the same shell.
		"In Progress",
	} {
		if strings.Contains(s, hit) {
			return true
		}
	}
	return false
}

// ensureDeviceVisible runs a short LE-only discovery until the device path
// appears in the BlueZ object tree, or the deadline expires. The discovery
// filter and StartDiscovery are both reset on return so we don't leak
// bluetoothd-wide state to other clients (a caeruleus scan or bluetoothctl
// running in parallel will see a clean default).
func (c *Conn) ensureDeviceVisible(ctx context.Context, devPath dbus.ObjectPath, max time.Duration) error {
	subCtx, cancel := context.WithTimeout(ctx, max)
	defer cancel()

	_ = c.SetDiscoveryFilter(map[string]dbus.Variant{
		"Transport": dbus.MakeVariant("le"),
	})
	defer func() { _ = c.SetDiscoveryFilter(map[string]dbus.Variant{}) }()

	addCh, err := c.SubscribeInterfacesAdded(subCtx, 32)
	if err != nil {
		return err
	}
	if err := c.StartDiscovery(); err != nil {
		// "AlreadyExists" or similar is fine - discovery may already be running.
		if !isAlreadyExists(err) {
			return fmt.Errorf("StartDiscovery: %w", err)
		}
	}
	defer func() { _ = c.StopDiscovery() }()

	// Fast-path: already present?
	obj := c.Bus.Object(BusName, devPath)
	if _, err := obj.GetProperty(IfaceDevice + ".Address"); err == nil {
		return nil
	}

	t := time.NewTicker(300 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-subCtx.Done():
			return fmt.Errorf("device %s not seen during discovery: %w", devPath, subCtx.Err())
		case ev := <-addCh:
			if ev.Path == devPath {
				return nil
			}
		case <-t.C:
			if _, err := obj.GetProperty(IfaceDevice + ".Address"); err == nil {
				return nil
			}
		}
	}
}

func isAlreadyExists(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "AlreadyExists") || strings.Contains(s, "InProgress")
}

// WaitServicesResolved polls ServicesResolved until true or ctx is done.
// BlueZ emits a PropertiesChanged signal when it flips; we poll for simplicity.
func (d *Device) WaitServicesResolved(ctx context.Context) error {
	t := time.NewTicker(150 * time.Millisecond)
	defer t.Stop()
	for {
		ok, err := d.ServicesResolved()
		if err == nil && ok {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("waiting for ServicesResolved: %w", ctx.Err())
		case <-t.C:
		}
	}
}

// Disconnect tears down the ACL link.
func (d *Device) Disconnect() error {
	ctx, cancel := context.WithTimeout(context.Background(), CallTimeout)
	defer cancel()
	return d.obj.CallWithContext(ctx, IfaceDevice+".Disconnect", 0).Err
}

// PairTimeout bounds Device1.Pair. Pairing is a multi-step SMP exchange and on
// peripherals with very lax connection parameters each round-trip can take
// seconds, so it gets a far more generous budget than a single GATT op.
var PairTimeout = 60 * time.Second

// Pair invokes BlueZ Device1.Pair. Bounded by PairTimeout: some BlueZ versions
// complete the bond but leave the call outstanding, so callers should read
// Paired()/Bonded() afterward rather than relying solely on this returning nil.
func (d *Device) Pair() error {
	ctx, cancel := context.WithTimeout(context.Background(), PairTimeout)
	defer cancel()
	return d.obj.CallWithContext(ctx, IfaceDevice+".Pair", 0).Err
}

// CancelPairing aborts an in-progress Device1.Pair. Safe to call when no
// pairing is underway (BlueZ returns DoesNotExist, which callers ignore).
func (d *Device) CancelPairing() error {
	return d.obj.Call(IfaceDevice+".CancelPairing", 0).Err
}

// Paired reports the BlueZ Device1.Paired property - whether a pairing
// procedure has completed for this peer (with or without a stored bond).
func (d *Device) Paired() (bool, error) {
	v, err := getProp(d.obj, IfaceDevice, "Paired")
	if err != nil {
		return false, err
	}
	b, _ := v.(bool)
	return b, nil
}

// Bonded reports the Device1.Bonded property - whether long-term keys are
// stored for this peer. Older BlueZ (<5.50) lacks this property; callers
// should treat the error as "unknown" rather than fatal.
func (d *Device) Bonded() (bool, error) {
	v, err := getProp(d.obj, IfaceDevice, "Bonded")
	if err != nil {
		return false, err
	}
	b, _ := v.(bool)
	return b, nil
}

// --- GATT object helpers ------------------------------------------------

// GattObject is a unified view of any GATT-related D-Bus object.
type GattObject struct {
	Path   dbus.ObjectPath
	Kind   string // "service" | "characteristic" | "descriptor"
	UUID   string
	Handle uint16
	Flags  []string // characteristic/descriptor only
	Parent dbus.ObjectPath
}

// Characteristic gives a typed view onto a single characteristic.
type Characteristic struct {
	conn *Conn
	Path dbus.ObjectPath
	obj  dbus.BusObject
}

func (c *Conn) Characteristic(path dbus.ObjectPath) *Characteristic {
	return &Characteristic{conn: c, Path: path, obj: c.Bus.Object(BusName, path)}
}

// UUID returns the characteristic UUID string.
func (c *Characteristic) UUID() (string, error) {
	v, err := getProp(c.obj, IfaceCharacteristic, "UUID")
	if err != nil {
		return "", err
	}
	s, _ := v.(string)
	return s, nil
}

// Handle returns the BlueZ Handle property (matches ATT handle on the peer).
// On older BlueZ (<5.57) the property is missing - caller can fall back to
// parsing the object path.
func (c *Characteristic) Handle() (uint16, error) {
	v, err := getProp(c.obj, IfaceCharacteristic, "Handle")
	if err != nil {
		return 0, err
	}
	switch h := v.(type) {
	case uint16:
		return h, nil
	case int16:
		return uint16(h), nil
	default:
		return 0, fmt.Errorf("Handle: unexpected type %T", v)
	}
}

// Flags returns the characteristic flag list (read, write, notify, ...).
func (c *Characteristic) Flags() ([]string, error) {
	v, err := getProp(c.obj, IfaceCharacteristic, "Flags")
	if err != nil {
		return nil, err
	}
	s, _ := v.([]string)
	return s, nil
}

// CallTimeout bounds individual GATT D-Bus operations (ReadValue / WriteValue).
// Without it these can hang indefinitely: reading a characteristic the
// peripheral guards with encryption makes BlueZ try to elevate security
// (pair), and with no pairing agent registered the synchronous call never
// returns. A bounded call surfaces that as a timeout the caller can classify.
var CallTimeout = 15 * time.Second

// ReadValue executes GattCharacteristic1.ReadValue with an empty options dict.
func (c *Characteristic) ReadValue(offset uint16) ([]byte, error) {
	opts := map[string]dbus.Variant{}
	if offset != 0 {
		opts["offset"] = dbus.MakeVariant(offset)
	}
	ctx, cancel := context.WithTimeout(context.Background(), CallTimeout)
	defer cancel()
	var out []byte
	if err := c.obj.CallWithContext(ctx, IfaceCharacteristic+".ReadValue", 0, opts).Store(&out); err != nil {
		return nil, fmt.Errorf("ReadValue: %w", err)
	}
	return out, nil
}

// WriteType selects the ATT write opcode BlueZ should use.
type WriteType string

const (
	WriteCommand  WriteType = "command"  // write-without-response
	WriteRequest  WriteType = "request"  // write-with-response
	WriteReliable WriteType = "reliable" // reliable writes (prepare/execute)
)

// WriteValue executes GattCharacteristic1.WriteValue with an explicit type.
func (c *Characteristic) WriteValue(value []byte, wtype WriteType) error {
	opts := map[string]dbus.Variant{}
	if wtype != "" {
		opts["type"] = dbus.MakeVariant(string(wtype))
	}
	ctx, cancel := context.WithTimeout(context.Background(), CallTimeout)
	defer cancel()
	return c.obj.CallWithContext(ctx, IfaceCharacteristic+".WriteValue", 0, value, opts).Err
}

// StartNotify enables notifications/indications on the characteristic.
func (c *Characteristic) StartNotify() error {
	return c.obj.Call(IfaceCharacteristic+".StartNotify", 0).Err
}

// StopNotify disables notifications/indications.
func (c *Characteristic) StopNotify() error {
	return c.obj.Call(IfaceCharacteristic+".StopNotify", 0).Err
}

// MTU returns the negotiated ATT MTU for the current connection, or 0 if the
// property is unsupported on the running BlueZ.
func (c *Characteristic) MTU() (uint16, error) {
	v, err := getProp(c.obj, IfaceCharacteristic, "MTU")
	if err != nil {
		return 0, err
	}
	switch n := v.(type) {
	case uint16:
		return n, nil
	case int16:
		return uint16(n), nil
	}
	return 0, fmt.Errorf("MTU: unexpected type %T", v)
}

// Descriptor is a typed view onto a single GATT descriptor.
type Descriptor struct {
	conn *Conn
	Path dbus.ObjectPath
	obj  dbus.BusObject
}

func (c *Conn) Descriptor(path dbus.ObjectPath) *Descriptor {
	return &Descriptor{conn: c, Path: path, obj: c.Bus.Object(BusName, path)}
}

func (d *Descriptor) UUID() (string, error) {
	v, err := getProp(d.obj, IfaceDescriptor, "UUID")
	if err != nil {
		return "", err
	}
	s, _ := v.(string)
	return s, nil
}

func (d *Descriptor) ReadValue(offset uint16) ([]byte, error) {
	opts := map[string]dbus.Variant{}
	if offset != 0 {
		opts["offset"] = dbus.MakeVariant(offset)
	}
	var out []byte
	if err := d.obj.Call(IfaceDescriptor+".ReadValue", 0, opts).Store(&out); err != nil {
		return nil, fmt.Errorf("ReadValue: %w", err)
	}
	return out, nil
}

func (d *Descriptor) WriteValue(value []byte) error {
	opts := map[string]dbus.Variant{}
	return d.obj.Call(IfaceDescriptor+".WriteValue", 0, value, opts).Err
}

// --- helpers ------------------------------------------------------------

func getProp(o dbus.BusObject, iface, name string) (interface{}, error) {
	v, err := o.GetProperty(iface + "." + name)
	if err != nil {
		return nil, err
	}
	return v.Value(), nil
}

func setProp(o dbus.BusObject, iface, name string, v interface{}) error {
	return o.SetProperty(iface+"."+name, dbus.MakeVariant(v))
}

// ErrNoSuchObject is returned when an object isn't (yet) registered with BlueZ.
var ErrNoSuchObject = errors.New("no such bluez object")
