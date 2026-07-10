package cli

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/praetorian-inc/caeruleus/internal/bluez"
	"github.com/praetorian-inc/caeruleus/internal/hcimon"
)

// connParamsWindow is how long we keep listening for a Connection Update
// Complete after the link comes up. Peripherals that want different
// parameters than the central offered typically request the update within
// the first second of the connection; 3s is a comfortable margin.
const connParamsWindow = 3 * time.Second

// connParamsResult is the structured output of `conn-params`.
type connParamsResult struct {
	Address              string  `json:"address"`
	Captured             bool    `json:"captured"` // false if no Connection Complete was seen
	ConnHandle           uint16  `json:"conn_handle"`
	Role                 string  `json:"role"` // local controller role: central | peripheral
	IntervalMs           float64 `json:"interval_ms"`
	IntervalUnits        uint16  `json:"interval_units"`
	Latency              uint16  `json:"latency_events"`
	SupervisionTimeoutMs int     `json:"supervision_timeout_ms"`
	TimeoutUnits         uint16  `json:"timeout_units"`
	Renegotiated         bool    `json:"renegotiated"` // a Connection Update Complete refined the initial params
	MTU                  uint16  `json:"att_mtu"`
}

func newConnParamsCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "conn-params",
		Aliases: []string{"connparams", "cparams"},
		Short:   "Report the negotiated connection parameters for -b BDADDR (needs root)",
		Long: `Recovers the LE connection parameters BlueZ does not expose over D-Bus - connection interval, peripheral latency, and supervision timeout - plus the
negotiated ATT MTU.

How it works: the local link is dropped if up, then re-established while a
kernel HCI monitor socket (the same interface btmon uses) captures the LE
Connection Complete event, and any Connection Update Complete the peripheral
requests in the first few seconds. No external tools are invoked.

Requires root (the HCI monitor socket needs CAP_NET_RAW + CAP_NET_ADMIN).

A short / aggressive supervision timeout or a peripheral-driven interval that
ignores the central's preference can be a DoS-relevant finding; a very long
interval with non-zero latency affects responsiveness of any active attack.`,
		RunE: runConnParams,
	}
}

func runConnParams(cmd *cobra.Command, args []string) error {
	if err := requireRoot("conn-params"); err != nil {
		return err
	}
	addr, err := requireBdaddr()
	if err != nil {
		return err
	}

	// Step 1: ensure the link is down so the connect below yields a fresh
	// Connection Complete the monitor can catch. If something else (or a
	// prior run) left it connected, the event already fired and we'd miss it.
	if pre, e := bluez.Dial(root.adapter); e == nil {
		d := pre.Device(addr)
		if c, ce := d.Connected(); ce == nil && c {
			logf("disconnecting %s to capture a fresh Connection Complete", addr)
			_ = d.Disconnect()
			_ = pollUntil(context.Background(), func() bool {
				conn, perr := d.Connected()
				return perr != nil || !conn
			}, 50*time.Millisecond, 2*time.Second)
		}
		pre.Close()
	}

	// Step 2: open the monitor and start decoding connection events before
	// we trigger the connection.
	mon, err := hcimon.Open()
	if err != nil {
		return err
	}
	defer mon.Close()
	monCtx, monCancel := context.WithCancel(context.Background())
	defer monCancel()
	events := make(chan hcimon.ConnEvent, 32)
	go func() { _ = mon.RunConn(monCtx, events) }()
	time.Sleep(150 * time.Millisecond) // let the poll loop reach its first read

	// Step 3: connect (fresh link → Connection Complete) and enumerate so we
	// can also read the negotiated ATT MTU.
	ctx, cancel := ctxWithRootTimeout()
	defer cancel()
	s, err := openSession(ctx, addr, true)
	if err != nil {
		return err
	}
	defer s.close()

	var mtu uint16
	for _, ch := range s.tree.Characteristics {
		if m, e := s.conn.Characteristic(ch.Path).MTU(); e == nil && m > 0 {
			mtu = m
			break
		}
	}

	// Step 4: drain connection events. Take the Connection Complete that
	// matches our peer, then keep any Update Complete on that handle until
	// the window closes.
	res := connParamsResult{Address: addr, MTU: mtu}
	var connHandle uint16
	haveHandle := false
	deadline := time.After(connParamsWindow)
collect:
	for {
		select {
		case ev := <-events:
			switch {
			case !ev.Updated && ev.PeerAddr != "" && strings.EqualFold(ev.PeerAddr, addr):
				connHandle = ev.ConnHandle
				haveHandle = true
				applyConnEvent(&res, ev, false)
			case ev.Updated && haveHandle && ev.ConnHandle == connHandle:
				applyConnEvent(&res, ev, true)
			}
		case <-deadline:
			break collect
		}
	}
	monCancel()

	if formatIsJSON() {
		return emitJSON(res)
	}
	if !res.Captured {
		failf("no Connection Complete captured for %s (reporting MTU only)", addr)
		fmt.Printf("address=%s captured=false att_mtu=%d\n", addr, res.MTU)
		return nil
	}
	fmt.Printf("address=%s conn_handle=0x%04x role=%s interval=%.2fms latency=%d supervision_timeout=%dms att_mtu=%d renegotiated=%v\n",
		res.Address, res.ConnHandle, res.Role, res.IntervalMs, res.Latency,
		res.SupervisionTimeoutMs, res.MTU, res.Renegotiated)
	return nil
}

// applyConnEvent folds an HCI connection event into the result. updated marks
// it as a renegotiation (Connection Update Complete) vs the initial complete.
func applyConnEvent(res *connParamsResult, ev hcimon.ConnEvent, updated bool) {
	res.Captured = true
	res.ConnHandle = ev.ConnHandle
	res.IntervalUnits = ev.IntervalUnits
	res.IntervalMs = ev.IntervalMillis()
	res.Latency = ev.LatencyEvents
	res.TimeoutUnits = ev.TimeoutUnits
	res.SupervisionTimeoutMs = ev.TimeoutMillis()
	if updated {
		res.Renegotiated = true
	} else {
		// Role only comes from the initial Connection Complete.
		if ev.Role == 0 {
			res.Role = "central"
		} else {
			res.Role = "peripheral"
		}
	}
}
