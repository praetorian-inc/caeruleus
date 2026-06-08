package cli

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"caeruleus/internal/hcimon"
)

var monitorFlags struct {
	handle   string
	duration int
	count    int
	extract  bool
}

func newMonitorCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "monitor",
		Short: "Passively decode ATT notifications/indications from the HCI monitor socket (needs root)",
		Long: `monitor opens the kernel's HCI_CHANNEL_MONITOR socket (same interface as btmon)
and decodes inbound ATT Handle Value Notification (0x1B) and Indication (0x1D)
PDUs. This bypasses BlueZ entirely, so it picks up notifications that bluetoothd
filters out — e.g. on characteristics that don't advertise NOTIFY, or
immediate-fire notifications that race past D-Bus subscribers.

Requires root or CAP_NET_RAW + CAP_NET_ADMIN. Output is caeruleus's normal
notification format; use --json for structured output.

Note on --handle: this filters on the ATT handle inside the PDU — i.e. the
handle the peripheral reports the notification *on the wire* — which is
not always the char value handle you subscribed against. The hidden-CCCD
case is the canonical surprise: some peripherals emit the notification on
the CCCD handle itself (the descriptor right after the char value handle)
rather than on the char's value handle. If a tight filter sees nothing,
drop the filter once to discover the actual emit handle.`,
		RunE: runMonitor,
	}
	c.Flags().StringVarP(&monitorFlags.handle, "handle", "a", "", "only print events whose PDU att-handle matches (NOT the subscribed char — drop the filter first if unsure)")
	c.Flags().IntVarP(&monitorFlags.duration, "duration", "d", 10, "stop after this many seconds (0 = forever)")
	c.Flags().IntVar(&monitorFlags.count, "count", 0, "stop after receiving this many events (0 = no limit)")
	c.Flags().BoolVar(&monitorFlags.extract, "extract", false, "print just the hex payload per event (one line each) — parity with listen --extract")
	return c
}

func runMonitor(cmd *cobra.Command, args []string) error {
	// HCI_CHANNEL_MONITOR needs CAP_NET_RAW. Fail fast with a clean message.
	if err := requireRoot("monitor"); err != nil {
		return err
	}

	var filterHandle uint16
	hasFilter := false
	if monitorFlags.handle != "" {
		h, err := parseHandle(monitorFlags.handle)
		if err != nil {
			return err
		}
		filterHandle = h
		hasFilter = true
	}

	m, err := hcimon.Open()
	if err != nil {
		return err
	}
	defer m.Close()

	dur := time.Duration(monitorFlags.duration) * time.Second
	if monitorFlags.duration == 0 {
		dur = 24 * time.Hour
	}
	ctx, cancel := context.WithTimeout(context.Background(), dur)
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigCh)
	go func() {
		select {
		case <-sigCh:
			cancel()
		case <-ctx.Done():
		}
	}()

	events := make(chan hcimon.Notification, 64)
	errCh := make(chan error, 1)
	go func() { errCh <- m.Run(ctx, events) }()

	got := 0
	for ev := range events {
		if hasFilter && ev.AttHandle != filterHandle {
			continue
		}
		switch {
		case formatIsJSON():
			_ = emitJSONEvent(map[string]interface{}{
				"ts":         ev.When.UTC(),
				"adapter":    ev.Adapter,
				"conn":       ev.ConnHandle,
				"att_handle": ev.AttHandle,
				"hex":        hex.EncodeToString(ev.Value),
				"ascii":      asciiize(ev.Value),
				"indicate":   ev.IsIndicate,
			})
		case monitorFlags.extract:
			fmt.Println(hex.EncodeToString(ev.Value))
		default:
			kind := "Notification"
			if ev.IsIndicate {
				kind = "Indication  "
			}
			fmt.Printf("%s handle = 0x%04x value: %s\n", kind, ev.AttHandle, spacedHex(ev.Value))
			if a := asciiize(ev.Value); a != "" {
				fmt.Printf("                          ascii: %s\n", a)
			}
		}
		got++
		if monitorFlags.count > 0 && got >= monitorFlags.count {
			cancel()
			break
		}
	}
	if err := <-errCh; err != nil {
		return err
	}
	return nil
}
