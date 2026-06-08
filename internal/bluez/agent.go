package bluez

import (
	"fmt"
	"sync"

	"github.com/godbus/dbus/v5"
)

// BlueZ will not complete pairing - not even Just Works - unless an
// org.bluez.Agent1 is registered to field the pairing callbacks. PairingAgent
// is a configurable agent: its registered IO capability decides which SMP
// association models are possible, it can supply an operator passkey for
// Passkey Entry, it surfaces displayed passkeys / numeric-comparison values,
// and it records which model BlueZ actually drove (inferred from which
// callbacks fired) so the caller can report it.
//
// It auto-accepts (Just Works and Numeric Comparison are confirmed without
// prompting) so an unattended central can bond. Passkey Entry needs the
// secret: it returns the operator-supplied Passkey, or rejects if none was
// given - which is the correct outcome for a tool that does not know it.

const agentPath = dbus.ObjectPath("/caeruleus/agent")

// IO capability strings accepted by AgentManager1.RegisterAgent.
const (
	CapNoInputNoOutput = "NoInputNoOutput"
	CapDisplayOnly     = "DisplayOnly"
	CapKeyboardOnly    = "KeyboardOnly"
	CapDisplayYesNo    = "DisplayYesNo"
	CapKeyboardDisplay = "KeyboardDisplay"
)

type PairingAgent struct {
	Passkey *uint32                      // operator-supplied passkey for Passkey Entry (input side)
	Logf    func(string, ...interface{}) // surface display/confirm prompts to the operator (may be nil)

	mu    sync.Mutex
	model string // "just-works" | "passkey-entry" | "numeric-comparison"
	mitm  bool   // a MITM-protected callback fired
}

func (a *PairingAgent) note(model string, mitm bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if model != "" {
		a.model = model
	}
	if mitm {
		a.mitm = true
	}
}

// Model returns the association model BlueZ drove and whether it was
// MITM-protected. Defaults to Just Works when no model-specific callback fired.
func (a *PairingAgent) Model() (string, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	m := a.model
	if m == "" {
		m = "just-works"
	}
	return m, a.mitm
}

func (a *PairingAgent) logf(f string, v ...interface{}) {
	if a.Logf != nil {
		a.Logf(f, v...)
	}
}

func (a *PairingAgent) Release() *dbus.Error { return nil }
func (a *PairingAgent) Cancel() *dbus.Error  { return nil }

func (a *PairingAgent) RequestPinCode(dbus.ObjectPath) (string, *dbus.Error) {
	a.note("passkey-entry", true)
	if a.Passkey != nil {
		return fmt.Sprintf("%06d", *a.Passkey), nil
	}
	a.logf("peripheral requested a PIN/passkey but none was supplied (use --passkey)")
	return "", dbus.NewError("org.bluez.Error.Rejected", nil)
}

func (a *PairingAgent) RequestPasskey(dbus.ObjectPath) (uint32, *dbus.Error) {
	a.note("passkey-entry", true)
	if a.Passkey != nil {
		return *a.Passkey, nil
	}
	a.logf("peripheral requested a passkey to enter but none was supplied (use --passkey)")
	return 0, dbus.NewError("org.bluez.Error.Rejected", nil)
}

func (a *PairingAgent) DisplayPasskey(_ dbus.ObjectPath, passkey uint32, _ uint16) *dbus.Error {
	a.note("passkey-entry", true)
	a.logf("enter this passkey on the peripheral: %06d", passkey)
	return nil
}

func (a *PairingAgent) DisplayPinCode(_ dbus.ObjectPath, pin string) *dbus.Error {
	a.note("passkey-entry", true)
	a.logf("enter this PIN on the peripheral: %s", pin)
	return nil
}

func (a *PairingAgent) RequestConfirmation(_ dbus.ObjectPath, passkey uint32) *dbus.Error {
	a.note("numeric-comparison", true)
	a.logf("numeric comparison value %06d (auto-confirming)", passkey)
	return nil
}

func (a *PairingAgent) RequestAuthorization(dbus.ObjectPath) *dbus.Error {
	a.note("just-works", false)
	return nil
}

func (a *PairingAgent) AuthorizeService(dbus.ObjectPath, string) *dbus.Error { return nil }

// RegisterPairingAgent exports the agent with the given IO capability and makes
// it the default. The returned function unregisters it; defer it once pairing
// is done. Register only around explicit pairing - leaving it active would let
// an encrypted-attribute read transparently bond, masking the unauthenticated
// access tests. capability defaults to NoInputNoOutput (forces Just Works).
func (c *Conn) RegisterPairingAgent(capability string, agent *PairingAgent) (func(), error) {
	if capability == "" {
		capability = CapNoInputNoOutput
	}
	if err := c.Bus.Export(agent, agentPath, "org.bluez.Agent1"); err != nil {
		return nil, fmt.Errorf("export agent: %w", err)
	}
	am := c.Bus.Object(BusName, dbus.ObjectPath("/org/bluez"))
	if call := am.Call("org.bluez.AgentManager1.RegisterAgent", 0, agentPath, capability); call.Err != nil {
		_ = c.Bus.Export(nil, agentPath, "org.bluez.Agent1")
		return nil, fmt.Errorf("RegisterAgent(%s): %w", capability, call.Err)
	}
	_ = am.Call("org.bluez.AgentManager1.RequestDefaultAgent", 0, agentPath).Err

	return func() {
		_ = am.Call("org.bluez.AgentManager1.UnregisterAgent", 0, agentPath).Err
		_ = c.Bus.Export(nil, agentPath, "org.bluez.Agent1")
	}, nil
}
