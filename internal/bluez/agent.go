package bluez

import (
	"fmt"

	"github.com/godbus/dbus/v5"
)

// BlueZ will not complete pairing - not even Just Works - unless an
// org.bluez.Agent1 is registered to field the pairing callbacks. This is a
// minimal NoInputNoOutput agent that auto-accepts: it makes Just Works
// pairing succeed without operator interaction (the common case for a
// headless central pairing with a peripheral that has no IO capability).
//
// It does NOT handle passkey/PIN entry meaningfully (it returns fixed values),
// so MITM/passkey pairing against a peripheral that demands a specific passkey
// will still fail - which is the correct outcome for an unattended tool.

const agentPath = dbus.ObjectPath("/caeruleus/agent")

type pairingAgent struct{}

func (pairingAgent) Release() *dbus.Error                                 { return nil }
func (pairingAgent) Cancel() *dbus.Error                                  { return nil }
func (pairingAgent) RequestPinCode(dbus.ObjectPath) (string, *dbus.Error) { return "000000", nil }
func (pairingAgent) RequestPasskey(dbus.ObjectPath) (uint32, *dbus.Error) { return 0, nil }
func (pairingAgent) DisplayPinCode(dbus.ObjectPath, string) *dbus.Error   { return nil }
func (pairingAgent) DisplayPasskey(dbus.ObjectPath, uint32, uint16) *dbus.Error {
	return nil
}

// RequestConfirmation is called for numeric-comparison (Just Works with
// bonding) pairing; accept unconditionally.
func (pairingAgent) RequestConfirmation(dbus.ObjectPath, uint32) *dbus.Error { return nil }

// RequestAuthorization / AuthorizeService are the incoming-pairing and
// service-authorisation hooks; accept unconditionally.
func (pairingAgent) RequestAuthorization(dbus.ObjectPath) *dbus.Error     { return nil }
func (pairingAgent) AuthorizeService(dbus.ObjectPath, string) *dbus.Error { return nil }

// RegisterPairingAgent exports a NoInputNoOutput auto-accept agent and makes
// it the default. The returned function unregisters it; call it (defer) once
// pairing is done. Register only around explicit pairing - leaving it active
// would let an encrypted-attribute read transparently bond, which would mask
// the unauthenticated-access tests.
func (c *Conn) RegisterPairingAgent() (func(), error) {
	if err := c.Bus.Export(pairingAgent{}, agentPath, "org.bluez.Agent1"); err != nil {
		return nil, fmt.Errorf("export agent: %w", err)
	}
	am := c.Bus.Object(BusName, dbus.ObjectPath("/org/bluez"))
	if call := am.Call("org.bluez.AgentManager1.RegisterAgent", 0, agentPath, "NoInputNoOutput"); call.Err != nil {
		_ = c.Bus.Export(nil, agentPath, "org.bluez.Agent1")
		return nil, fmt.Errorf("RegisterAgent: %w", call.Err)
	}
	// Best-effort: become the default agent so our callbacks are used.
	_ = am.Call("org.bluez.AgentManager1.RequestDefaultAgent", 0, agentPath).Err

	return func() {
		_ = am.Call("org.bluez.AgentManager1.UnregisterAgent", 0, agentPath).Err
		_ = c.Bus.Export(nil, agentPath, "org.bluez.Agent1")
	}, nil
}
