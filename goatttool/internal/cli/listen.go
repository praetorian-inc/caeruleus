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

	"goatttool/internal/bluez"
	"goatttool/internal/hcimon"
)

// maybeStartMonitor opens an hcimon socket if want is true. Returns a channel
// of notifications + a stop func. When want is false or the socket can't be
// opened, returns (nil, no-op, nil) so the caller can still proceed with the
// pure D-Bus path.
func maybeStartMonitor(ctx context.Context, want bool) (<-chan hcimon.Notification, func(), error) {
	if !want {
		return nil, func() {}, nil
	}
	m, err := hcimon.Open()
	if err != nil {
		// Be gentle: log + continue with D-Bus only.
		logf("hcimon disabled: %v", err)
		return nil, func() {}, nil
	}
	monCtx, cancel := context.WithCancel(ctx)
	out := make(chan hcimon.Notification, 64)
	go func() {
		if err := m.Run(monCtx, out); err != nil {
			logf("hcimon run: %v", err)
		}
	}()
	stop := func() {
		cancel()
		_ = m.Close()
	}
	return out, stop, nil
}

var listenFlags struct {
	handle       string
	uuid         string
	duration     int
	count        int
	trigger      string // optional hex write to fire before listening
	trigHnd      string
	trigCount    int           // 0 = single fire (or 1 if --trigger-value)
	trigInterval time.Duration // gap between repeated triggers
	monitor      string        // "auto" | "on" | "off" — fan in HCI monitor socket
	hiddenCCCD   bool          // if true, don't call StartNotify (for chars without notify)
	extract      bool
	retry        int
	retryDelay   time.Duration
}

func newListenCmd() *cobra.Command {
	c := &cobra.Command{
		Use:     "listen",
		Aliases: []string{"notify", "subscribe"},
		Short:   "Subscribe to notifications/indications on a characteristic",
		Long: `listen subscribes to notifications/indications on a GATT characteristic and
prints each event until the duration or count limit is reached.

Trigger writes:
  --trigger-value HEX        write HEX to the listen handle (or --trigger-handle)
                             after StartNotify but before reading. Useful when
                             the peripheral only emits a notification in
                             response to a write.
  --trigger-count N          fire the trigger N times (default 1). Use for
                             "multi-notification" peripherals that emit one
                             event per write.
  --trigger-interval D       delay between repeated triggers (default 300ms).

Counting:
  --count N                  stop after N events (0 = unlimited).
  When --trigger-value is set and --count is left at 0, --count is auto-set
  to 1 (one trigger -> one event is the canonical case). If you also pass
  --trigger-count >1 or want a stream, set --count 0 explicitly.

Hidden CCCDs:
  --hidden                   skip StartNotify (for chars whose properties
                             don't advertise notify/indicate; pair with
                             --monitor on, which needs sudo, to capture
                             the wire events). Without --monitor on, the
                             listener has no event source and exits silent.`,
		RunE: runListen,
	}
	c.Flags().StringVarP(&listenFlags.handle, "handle", "a", "", "ATT handle of the characteristic")
	c.Flags().StringVarP(&listenFlags.uuid, "uuid", "u", "", "characteristic UUID")
	c.Flags().IntVarP(&listenFlags.duration, "duration", "d", 5, "stop after this many seconds (0 = forever)")
	c.Flags().IntVar(&listenFlags.count, "count", 0, "stop after receiving this many notifications (0 = unlimited; auto-set to 1 when --trigger-value is given and --count isn't)")
	c.Flags().StringVar(&listenFlags.trigger, "trigger-value", "", "hex value to write before listening (forces a notify); pairs with --trigger-count for repeated fires")
	c.Flags().StringVar(&listenFlags.trigHnd, "trigger-handle", "", "handle to write the trigger value to (defaults to the listen handle)")
	c.Flags().IntVar(&listenFlags.trigCount, "trigger-count", 1, "number of times to fire --trigger-value (use with --count 0 to capture every response)")
	c.Flags().DurationVar(&listenFlags.trigInterval, "trigger-interval", 300*time.Millisecond, "delay between repeated triggers")
	c.Flags().StringVar(&listenFlags.monitor, "monitor", "auto",
		"fan in HCI monitor socket events too: auto|on|off (auto = on if euid==0)")
	c.Flags().BoolVar(&listenFlags.hiddenCCCD, "hidden", false,
		"don't call StartNotify — only watch via HCI monitor (for chars that don't advertise notify; needs --monitor on)")
	c.Flags().BoolVar(&listenFlags.extract, "extract", false,
		"print just the hex payload per event (lossless, one line each) — pipe to `write -n`")
	c.Flags().IntVar(&listenFlags.retry, "retry", 0, "retry the entire listen window up to N times on transient BlueZ/HCI errors")
	c.Flags().DurationVar(&listenFlags.retryDelay, "retry-delay", 500*time.Millisecond, "delay between retries")
	return c
}

type notifyEvent struct {
	When   time.Time `json:"ts"`
	Handle uint16    `json:"handle"`
	Hex    string    `json:"hex"`
	ASCII  string    `json:"ascii"`
	Source string    `json:"source"` // "dbus" or "monitor"
	Kind   string    `json:"kind"`   // "notification" or "indication"
}

func runListen(cmd *cobra.Command, args []string) error {
	if listenFlags.handle == "" && listenFlags.uuid == "" {
		return fmt.Errorf("supply -a/--handle or -u/--uuid")
	}
	addr, err := requireBdaddr()
	if err != nil {
		return err
	}

	return retryable(listenFlags.retry, listenFlags.retryDelay, func() error {
		return runListenOnce(addr)
	})
}

// runListenOnce performs a single listen window. The caller may retry this
// whole function on transient errors.
func runListenOnce(addr string) error {
	// Listen + duration + slack — don't use root --timeout; default is too short.
	dur := time.Duration(listenFlags.duration) * time.Second
	if listenFlags.duration == 0 {
		dur = 24 * time.Hour
	}
	// "Trigger then capture one" is the overwhelmingly common pattern when
	// --trigger-value is set with default --trigger-count=1. Auto-imply
	// --count 1 in that case so users don't sit through the full duration
	// waiting for nothing else to fire. If --trigger-count > 1 (multi-fire),
	// leave --count at 0 (unlimited) — the user clearly wants every response.
	// Override with explicit --count to restore previous behaviour.
	effectiveCount := listenFlags.count
	if effectiveCount == 0 && listenFlags.trigger != "" && listenFlags.trigCount <= 1 {
		effectiveCount = 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), dur+5*time.Second)
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	// Decide whether to fan in the HCI monitor socket. "auto" enables it when
	// euid==0, since AF_BLUETOOTH SOCK_RAW needs root.
	wantMonitor := false
	switch listenFlags.monitor {
	case "on", "true", "1":
		wantMonitor = true
	case "off", "false", "0":
		wantMonitor = false
	default:
		wantMonitor = os.Geteuid() == 0
	}

	// --hidden disables BlueZ-side subscription, so without the HCI monitor
	// channel there's literally no event source left. Warn loudly rather
	// than running a silent no-op.
	if listenFlags.hiddenCCCD && !wantMonitor {
		failf("--hidden skips StartNotify and --monitor is off — this listen has no event source and will produce nothing. Re-run with --monitor on (needs sudo) or drop --hidden.")
	}

	// Bring the monitor up BEFORE connecting so we don't miss the immediate
	// notification BlueZ's StartNotify will trigger.
	monCh, monStop, err := maybeStartMonitor(ctx, wantMonitor)
	if err != nil {
		return err
	}
	defer monStop()

	s, err := openSession(ctx, addr, true)
	if err != nil {
		return err
	}
	defer s.close()

	obj, err := resolveChar(s, listenFlags.handle, listenFlags.uuid)
	if err != nil {
		return err
	}
	c := s.conn.Characteristic(obj.Path)

	propCh, err := s.conn.Subscribe(ctx, s.device.Path, 128)
	if err != nil {
		return err
	}

	if !listenFlags.hiddenCCCD {
		if err := c.StartNotify(); err != nil {
			// If the char doesn't advertise notify, falling back to monitor-only
			// is the right move — emit a hint and continue.
			if monCh == nil {
				return fmt.Errorf("StartNotify: %w (try --monitor on or --hidden with sudo)", err)
			}
			logf("StartNotify failed (%v) — relying on HCI monitor only", err)
		} else {
			defer func() { _ = c.StopNotify() }()
		}
	}

	// Optional trigger writes. The first fires synchronously before the
	// event loop so single-shot callers behave exactly as before. Any
	// remaining fires happen in a goroutine paced by --trigger-interval,
	// so peripherals that emit one notification per write (multi-notify
	// challenges) can be captured in a single subcommand call.
	if listenFlags.trigger != "" {
		payload, err := parseHexBytes(listenFlags.trigger)
		if err != nil {
			return err
		}
		var trigObj bluez.GattObject = obj
		if listenFlags.trigHnd != "" {
			h, err := parseHandle(listenFlags.trigHnd)
			if err != nil {
				return err
			}
			tg, ok := s.tree.ByHandle[h]
			if !ok {
				return fmt.Errorf("trigger handle 0x%04x not found", h)
			}
			trigObj = tg
		}
		tc := s.conn.Characteristic(trigObj.Path)
		wt := bluez.WriteCommand
		if !propsCan(trigObj.Flags, "write-without-response") && propsCan(trigObj.Flags, "write") {
			wt = bluez.WriteRequest
		}
		if err := tc.WriteValue(payload, wt); err != nil {
			return fmt.Errorf("trigger write: %w", err)
		}
		fires := listenFlags.trigCount
		if fires < 1 {
			fires = 1
		}
		logf("trigger wrote %d bytes to 0x%04x (1/%d)", len(payload), trigObj.Handle, fires)
		if fires > 1 {
			interval := listenFlags.trigInterval
			if interval <= 0 {
				interval = 300 * time.Millisecond
			}
			go func() {
				for i := 2; i <= fires; i++ {
					select {
					case <-ctx.Done():
						return
					case <-time.After(interval):
					}
					if err := tc.WriteValue(payload, wt); err != nil {
						logf("trigger write %d/%d failed: %v", i, fires, err)
						return
					}
					logf("trigger wrote %d bytes to 0x%04x (%d/%d)", len(payload), trigObj.Handle, i, fires)
				}
			}()
		}
	}

	logf("listening on 0x%04x for %s (monitor=%v, hidden=%v, path=%s)",
		obj.Handle, dur, monCh != nil, listenFlags.hiddenCCCD, obj.Path)
	deadline := time.After(dur)
	got := 0
	emit := func(ne notifyEvent, raw []byte) {
		switch {
		case formatIsJSON():
			_ = emitJSONEvent(ne)
		case listenFlags.extract:
			fmt.Println(hex.EncodeToString(raw))
		default:
			kind := "Notification"
			if ne.Kind == "indication" {
				kind = "Indication  "
			}
			fmt.Printf("%s handle = 0x%04x value: %s\n", kind, ne.Handle, spacedHex(raw))
			if a := asciiize(raw); a != "" {
				fmt.Printf("                          ascii: %s\n", a)
			}
		}
	}

	// dedupe: BlueZ may surface the same value via PropertiesChanged while the
	// monitor also caught it. Skip duplicates within a short window.
	type dedupKey struct {
		hex string
	}
	lastSeen := map[dedupKey]time.Time{}
	const dedupWindow = 200 * time.Millisecond

	for {
		select {
		case <-deadline:
			return nil
		case <-sigCh:
			return nil
		case ev, ok := <-propCh:
			if !ok {
				return nil
			}
			if ev.Path != obj.Path || ev.Interface != bluez.IfaceCharacteristic {
				continue
			}
			raw, ok := ev.Changed["Value"]
			if !ok {
				continue
			}
			b, ok := raw.Value().([]byte)
			if !ok {
				continue
			}
			hx := hex.EncodeToString(b)
			if t, ok := lastSeen[dedupKey{hx}]; ok && time.Since(t) < dedupWindow {
				continue
			}
			lastSeen[dedupKey{hx}] = time.Now()
			ne := notifyEvent{When: time.Now(), Handle: obj.Handle, Hex: hx, ASCII: asciiize(b),
				Source: "dbus", Kind: "notification"}
			emit(ne, b)
			got++
			if effectiveCount > 0 && got >= effectiveCount {
				return nil
			}
		case mev, ok := <-monCh:
			if !ok {
				monCh = nil
				continue
			}
			if mev.AttHandle != obj.Handle {
				continue
			}
			hx := hex.EncodeToString(mev.Value)
			if t, ok := lastSeen[dedupKey{hx}]; ok && time.Since(t) < dedupWindow {
				continue
			}
			lastSeen[dedupKey{hx}] = time.Now()
			kind := "notification"
			if mev.IsIndicate {
				kind = "indication"
			}
			ne := notifyEvent{When: mev.When, Handle: mev.AttHandle, Hex: hx, ASCII: asciiize(mev.Value),
				Source: "monitor", Kind: kind}
			emit(ne, mev.Value)
			got++
			if effectiveCount > 0 && got >= effectiveCount {
				return nil
			}
		}
	}
}
