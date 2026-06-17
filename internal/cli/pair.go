package cli

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/praetorian-inc/caeruleus/internal/bluez"
)

// pairAttempt captures the outcome of one connect+Pair cycle. pairErr is the
// peer-side result (nil = accepted; non-nil = rejected/unsupported, which is
// data, not a tool failure). A connect failure is returned as the error.
type pairAttempt struct {
	paired  bool
	bonded  *bool // nil when BlueZ doesn't expose the Bonded property
	pairErr error
	model   string // association model BlueZ drove (just-works/passkey-entry/numeric-comparison)
	mitm    bool   // MITM-protected association
}

// isSMPRejection returns true when err indicates the peripheral did not enter
// its pairing state machine — as opposed to pairing that completed but was
// rejected for another reason (e.g. wrong passkey). These are the cases where
// retrying with receive-pairing (full GATT connect) may succeed.
func isSMPRejection(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return containsAny(s, "Authentication Canceled", "Authentication Failed")
}

// attemptPair brings up the link to addr, invokes Device1.Pair with an agent
// of the given IO capability (and optional passkey), records the resulting
// Paired/Bonded state and the negotiated association model, then disconnects
// (the bond persists). pairMode selects the connect strategy: "send-pairing"
// uses ConnectLink (bare ACL), "receive-pairing" uses Connect (full GATT
// discovery). The returned error is non-nil only when the device could not be
// reached.
func attemptPair(ctx context.Context, addr, capability string, passkey *uint32, pairMode string, promptPasskey func() (uint32, error)) (pairAttempt, error) {
	conn, err := bluez.Dial(root.adapter)
	if err != nil {
		return pairAttempt{}, err
	}
	defer conn.Close()

	// BlueZ needs a registered agent to complete pairing (even Just Works).
	// Its capability decides which association models are possible; surface any
	// display/confirm prompts to the operator. Register for this pairing only.
	agent := &bluez.PairingAgent{Passkey: passkey, PromptPasskey: promptPasskey, Logf: func(f string, v ...interface{}) { statusf(f, v...) }}
	if cleanup, e := conn.RegisterPairingAgent(capability, agent); e == nil {
		defer cleanup()
	} else {
		logf("pairing agent registration failed: %v", e)
	}

	dev := conn.Device(addr)
	if root.addrType != "" {
		_ = dev.SetAddressType(root.addrType)
	}
	switch pairMode {
	case "receive-pairing":
		// ConnectLink calls D-Bus Device1.Connect (which starts GATT
		// discovery in BlueZ) but only waits for Connected=true, not
		// ServicesResolved. During GATT discovery BlueZ reads attributes;
		// when it hits one that returns Insufficient Authentication, the
		// registered agent handles the SMP exchange reactively. We then
		// poll for Paired=true rather than blocking on ServicesResolved
		// (which stalls while the SMP exchange is in-flight).
		if err := dev.ConnectLink(ctx, time.Duration(root.timeout)*time.Second); err != nil {
			return pairAttempt{}, fmt.Errorf("connect before pair: %w", err)
		}
		if paired, _ := dev.WaitPaired(ctx, time.Duration(root.timeout)*time.Second); paired {
			pa := pairAttempt{paired: true}
			if b, e := dev.Bonded(); e == nil {
				pa.bonded = &b
			}
			pa.model, pa.mitm = agent.Model()
			return pa, nil
		}
		// Paired never flipped — fall through to explicit Pair() below in
		// case GATT discovery didn't hit a protected characteristic.
	default: // send-pairing
		if err := dev.ConnectLink(ctx, time.Duration(root.timeout)*time.Second); err != nil {
			return pairAttempt{}, fmt.Errorf("connect before pair: %w", err)
		}
	}

	defer func() {
		if c, e := dev.Connected(); e == nil && c {
			_ = dev.Disconnect()
		}
	}()

	perr := dev.Pair()
	pa := pairAttempt{}
	pa.paired, _ = dev.Paired()
	if !pa.paired {
		// Only surface the error if we did NOT end up paired; some BlueZ
		// versions complete the bond but leave Pair() outstanding (it returns
		// a timeout), which is not a failure.
		pa.pairErr = perr
	}
	if b, e := dev.Bonded(); e == nil {
		pa.bonded = &b
	}
	pa.model, pa.mitm = agent.Model()

	// After a successful pair, prime BlueZ's GATT cache by triggering
	// service discovery on this connection. ConnectLink (above) skipped
	// GATT resolution for speed, but that leaves a Device1 with no cached
	// attribute table — subsequent Connect calls may see 0 services because
	// BlueZ reports ServicesResolved=true from the stale (empty) cache.
	// Best-effort: if discovery doesn't finish before the context expires,
	// the bond is still valid and the shell's connect recovery handles it.
	if pa.paired {
		_ = dev.WaitServicesResolved(ctx)
	}

	return pa, nil
}

// bluezIOCap maps the friendly --io value to a BlueZ agent capability.
func bluezIOCap(io string) (string, error) {
	switch io {
	case "", "none":
		return bluez.CapNoInputNoOutput, nil
	case "display-only":
		return bluez.CapDisplayOnly, nil
	case "keyboard-only":
		return bluez.CapKeyboardOnly, nil
	case "display-yesno":
		return bluez.CapDisplayYesNo, nil
	case "keyboard-display":
		return bluez.CapKeyboardDisplay, nil
	default:
		return "", fmt.Errorf("invalid --io %q: use none|display-only|keyboard-only|display-yesno|keyboard-display", io)
	}
}

// pairResult is the structured output of `pair` / `unpair`.
type pairResult struct {
	Address     string `json:"address"`
	Action      string `json:"action"`                // "pair" | "unpair"
	Paired      bool   `json:"paired"`
	Bonded      *bool  `json:"bonded,omitempty"`      // nil when BlueZ doesn't expose Bonded
	PairMode    string `json:"pair_mode,omitempty"`    // send-pairing | receive-pairing
	Association string `json:"association,omitempty"`  // just-works | passkey-entry | numeric-comparison
	MITM        bool   `json:"mitm,omitempty"`
	Removed     bool   `json:"removed,omitempty"`
	Error       string `json:"error,omitempty"`        // peer-side rejection, not a tool failure
}

var pairFlags struct {
	io       string
	passkey  string
	rebond   bool
	pairMode string
}

func newPairCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "pair",
		Short: "Pair / bond with -b BDADDR (BlueZ Device1.Pair)",
		Long: `Brings up the LE link to -b BDADDR, invokes Device1.Pair through an agent of
the chosen IO capability, and reports the resulting Paired / Bonded state and
the association model BlueZ negotiated (just-works / passkey-entry /
numeric-comparison) plus whether it was MITM-protected.

By default the agent is NoInputNoOutput, which forces Just Works (no MITM) -
the common case for IoT peripherals. For a device that demands MITM, raise the
capability with --io and, for Passkey Entry, supply the passkey the peripheral
displays (or that is printed/known) with --passkey:

  caeruleus pair -b A --io keyboard-display --passkey 123456

Pairing is an observation, not an assertion: a peripheral that rejects pairing
is a finding, not a tool error (exits 0 with the rejection recorded). A device
that bonds via Just Works when it should require MITM is a weak-pairing finding.
A failure to reach the device at all is a hard error.`,
		RunE: runPair,
	}
	c.Flags().StringVar(&pairFlags.io, "io", "none", "IO capability: none|display-only|keyboard-only|display-yesno|keyboard-display")
	c.Flags().StringVar(&pairFlags.passkey, "passkey", "", "passkey for Passkey Entry: digits, or '-' to prompt interactively")
	c.Flags().BoolVar(&pairFlags.rebond, "rebond", false, "drop any existing bond first, then pair fresh")
	c.Flags().StringVar(&pairFlags.pairMode, "pair-mode", "auto", "pairing strategy: send-pairing|receive-pairing|auto")
	return c
}

func newUnpairCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "unpair",
		Short: "Drop the bond / pairing for -b BDADDR (BlueZ Adapter1.RemoveDevice)",
		Long: `Cancels any in-progress pairing and removes the stored bond by purging the
Device1 object (Adapter1.RemoveDevice) - the only lever BlueZ gives us to
drop long-term keys. The next connect re-discovers and re-pairs from scratch.

This is the same underlying call as 'forget'; 'unpair' exists as the
pairing-workflow-named counterpart to 'pair' (e.g. test access, pair,
re-test, unpair, confirm it fell back to unencrypted).`,
		RunE: runUnpair,
	}
}

func runPair(cmd *cobra.Command, args []string) error {
	addr, err := requireBdaddr()
	if err != nil {
		return err
	}
	capability, err := bluezIOCap(pairFlags.io)
	if err != nil {
		return err
	}
	var passkey *uint32
	var promptPasskey func() (uint32, error)
	switch strings.TrimSpace(pairFlags.passkey) {
	case "":
		// no passkey
	case "-":
		// Interactive: prompt the operator when the peripheral requests input.
		promptPasskey = func() (uint32, error) {
			fmt.Print("[?] enter passkey shown on device: ")
			var s string
			if _, err := fmt.Scanln(&s); err != nil {
				return 0, err
			}
			n, err := strconv.ParseUint(strings.TrimSpace(s), 10, 32)
			if err != nil || n > 999999 {
				return 0, fmt.Errorf("invalid passkey %q", s)
			}
			return uint32(n), nil
		}
	default:
		n, perr := strconv.ParseUint(strings.TrimSpace(pairFlags.passkey), 10, 32)
		if perr != nil || n > 999999 {
			return fmt.Errorf("invalid --passkey %q: expected up to 6 digits", pairFlags.passkey)
		}
		u := uint32(n)
		passkey = &u
	}

	ctx, cancel := ctxWithRootTimeout()
	defer cancel()

	// --rebond: drop any stored bond first so we pair fresh.
	if pairFlags.rebond {
		if c, e := bluez.Dial(root.adapter); e == nil {
			_ = c.RemoveDevice(c.DevicePath(addr))
			c.Close()
		}
	}

	mode := pairFlags.pairMode
	switch mode {
	case "send-pairing", "receive-pairing", "auto":
	default:
		return fmt.Errorf("invalid --pair-mode %q: use send-pairing|receive-pairing|auto", mode)
	}

	var pa pairAttempt
	usedMode := mode

	switch mode {
	case "send-pairing", "receive-pairing":
		pa, err = attemptPair(ctx, addr, capability, passkey, mode, promptPasskey)
		if err != nil {
			return err
		}
	case "auto":
		if promptPasskey != nil {
			// Interactive passkey requires the reactive flow — the
			// send-pairing probe would trigger the device's pairing state
			// machine (via GATT) and then reject it (no prompt), poisoning
			// the device state for the real attempt.
			usedMode = "receive-pairing"
			pa, err = attemptPair(ctx, addr, capability, passkey, "receive-pairing", promptPasskey)
			if err != nil {
				return err
			}
		} else {
			usedMode = "send-pairing"
			pa, err = attemptPair(ctx, addr, capability, passkey, "send-pairing", nil)
			if err != nil {
				return err
			}
			if pa.pairErr != nil && isSMPRejection(pa.pairErr) {
				logf("send-pairing failed (%v), retrying with receive-pairing", pa.pairErr)
				usedMode = "receive-pairing"
				ctx2, cancel2 := ctxWithRootTimeout()
				defer cancel2()
				pa, err = attemptPair(ctx2, addr, capability, passkey, "receive-pairing", nil)
				if err != nil {
					return err
				}
			}
		}
	}

	res := pairResult{Address: addr, Action: "pair", Paired: pa.paired, Bonded: pa.bonded, PairMode: usedMode}
	if pa.paired {
		res.Association = pa.model
		res.MITM = pa.mitm
	}
	if pa.pairErr != nil {
		res.Error = pa.pairErr.Error()
	}

	if formatIsJSON() {
		return emitJSON(res)
	}
	if pa.pairErr != nil {
		failf("pair %s rejected/unsupported: %v", addr, pa.pairErr)
	} else if pa.paired && !pa.mitm {
		statusf("pair %s ok via %s - no MITM protection", addr, pa.model)
	} else {
		statusf("pair %s ok", addr)
	}
	fmt.Printf("address=%s action=pair paired=%v", addr, pa.paired)
	if res.Bonded != nil {
		fmt.Printf(" bonded=%v", *res.Bonded)
	}
	fmt.Printf(" pair_mode=%s", usedMode)
	if pa.paired {
		fmt.Printf(" association=%s mitm=%v", pa.model, pa.mitm)
	}
	if res.Error != "" {
		fmt.Printf(" pair_error=%q", res.Error)
	}
	fmt.Println()
	return nil
}

func runUnpair(cmd *cobra.Command, args []string) error {
	addr, err := requireBdaddr()
	if err != nil {
		return err
	}
	conn, err := bluez.Dial(root.adapter)
	if err != nil {
		return err
	}
	defer conn.Close()

	dev := conn.Device(addr)
	_ = dev.CancelPairing() // no-op if nothing is pairing

	res := pairResult{Address: addr, Action: "unpair", Paired: false}
	rmErr := conn.RemoveDevice(conn.DevicePath(addr))
	switch {
	case rmErr == nil:
		res.Removed = true
	case containsAny(rmErr.Error(), "Does Not Exist", "No such device", "UnknownObject"):
		// Already gone - bond is absent, which is the desired post-state.
		res.Removed = true
	default:
		return fmt.Errorf("RemoveDevice: %w", rmErr)
	}

	if formatIsJSON() {
		return emitJSON(res)
	}
	statusf("unpair %s ok", addr)
	fmt.Printf("address=%s action=unpair removed=%v paired=false\n", addr, res.Removed)
	return nil
}
