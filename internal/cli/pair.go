package cli

import (
	"context"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"caeruleus/internal/bluez"
)

// pairAttempt captures the outcome of one connect+Pair cycle. pairErr is the
// peer-side result (nil = accepted; non-nil = rejected/unsupported, which is
// data, not a tool failure). A connect failure is returned as the error.
type pairAttempt struct {
	paired  bool
	bonded  *bool // nil when BlueZ doesn't expose the Bonded property
	pairErr error
}

// attemptPair brings up the link to addr, invokes Device1.Pair, records the
// resulting Paired/Bonded state, then disconnects (the bond persists). The
// returned error is non-nil only when the device could not be reached.
func attemptPair(ctx context.Context, addr string) (pairAttempt, error) {
	conn, err := bluez.Dial(root.adapter)
	if err != nil {
		return pairAttempt{}, err
	}
	defer conn.Close()

	dev := conn.Device(addr)
	if root.addrType != "" {
		_ = dev.SetAddressType(root.addrType)
	}
	if err := dev.Connect(ctx, time.Duration(root.timeout)*time.Second); err != nil {
		return pairAttempt{}, fmt.Errorf("connect before pair: %w", err)
	}
	defer func() {
		if c, e := dev.Connected(); e == nil && c {
			_ = dev.Disconnect()
		}
	}()

	pa := pairAttempt{pairErr: dev.Pair()}
	pa.paired, _ = dev.Paired()
	if b, e := dev.Bonded(); e == nil {
		pa.bonded = &b
	}
	return pa, nil
}

// pairResult is the structured output of `pair` / `unpair`.
type pairResult struct {
	Address string `json:"address"`
	Action  string `json:"action"` // "pair" | "unpair"
	Paired  bool   `json:"paired"`
	Bonded  *bool  `json:"bonded,omitempty"` // nil when BlueZ doesn't expose Bonded
	Removed bool   `json:"removed,omitempty"`
	Error   string `json:"error,omitempty"` // peer-side rejection, not a tool failure
}

func newPairCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "pair",
		Short: "Pair / bond with -b BDADDR (BlueZ Device1.Pair)",
		Long: `Brings up the LE link to -b BDADDR and invokes Device1.Pair, then reports
the resulting Paired / Bonded state.

Pairing is an observation, not an assertion: a peripheral that rejects or
does not support pairing is a finding, not a tool error. In that case the
attempt exits 0 with the rejection recorded in 'pair_error' (text) or the
"error" field (JSON). A failure to reach the device at all is a hard error.

Use this to test whether a peripheral enforces pairing before exposing
characteristics — pair, then re-read the same characteristic that errored
unpaired (see 'caeruleus encryption' for the automated form).`,
		RunE: runPair,
	}
}

func newUnpairCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "unpair",
		Short: "Drop the bond / pairing for -b BDADDR (BlueZ Adapter1.RemoveDevice)",
		Long: `Cancels any in-progress pairing and removes the stored bond by purging the
Device1 object (Adapter1.RemoveDevice) — the only lever BlueZ gives us to
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
	ctx, cancel := ctxWithRootTimeout()
	defer cancel()

	pa, err := attemptPair(ctx, addr)
	if err != nil {
		return err // could not reach the device — a real error
	}

	res := pairResult{Address: addr, Action: "pair", Paired: pa.paired, Bonded: pa.bonded}
	if pa.pairErr != nil {
		res.Error = pa.pairErr.Error()
	}

	if formatIsJSON() {
		return emitJSON(res)
	}
	if pa.pairErr != nil {
		failf("pair %s rejected/unsupported: %v", addr, pa.pairErr)
	} else {
		statusf("pair %s ok", addr)
	}
	fmt.Printf("address=%s action=pair paired=%v", addr, pa.paired)
	if res.Bonded != nil {
		fmt.Printf(" bonded=%v", *res.Bonded)
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
		// Already gone — bond is absent, which is the desired post-state.
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
