package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/godbus/dbus/v5"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/spf13/cobra"

	"caeruleus/internal/bluez"
)

var scanFlags struct {
	duration   int
	onlyNew    bool
	name       string
	prefix     string
	keepFilter bool
	live       bool
}

// scanEvent is one streamed observation emitted under --live. "found" is the
// first time a device is seen this window (including BlueZ's cached snapshot);
// "update" is a subsequent RSSI/name/type change on a device already reported.
type scanEvent struct {
	Event    string `json:"event"`
	Index    int    `json:"index"` // 1-based, stable in first-seen order (matches the table column)
	Address  string `json:"address"`
	AddrType string `json:"addr_type,omitempty"`
	RSSI     int16  `json:"rssi,omitempty"`
	Name     string `json:"name,omitempty"`
}

func newScanCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "scan",
		Short: "Scan for nearby BLE devices",
		Long: `scan starts LE device discovery and lists every device BlueZ knows about
after the scan window - both freshly-advertised devices (InterfacesAdded
events) and devices BlueZ had cached from before. Pass --new to suppress
the cached set if you only want devices that advertised in this window.

Pass --live to watch devices arrive in real time instead of printing a single
table at the end. On a terminal this shows one self-updating table: a new
device adds a row and an RSSI/name change rewrites that row in place rather
than appending a duplicate. Under -o json/jsonl each observation is emitted
as a discrete {event:"found"|"update", …} record (one per line for jsonl);
when stdout is not a terminal, text mode falls back to one append line per
event so redirected output stays escape-free.
--live runs until interrupted (Ctrl-C) unless you pass an explicit --duration.

The bluetoothd-side SetDiscoveryFilter is reset to the default before
returning so subsequent scans by other clients aren't constrained.`,
		RunE: runScan,
	}
	c.Flags().IntVarP(&scanFlags.duration, "duration", "d", 8, "scan duration in seconds")
	c.Flags().BoolVar(&scanFlags.onlyNew, "new", false, "show only devices freshly advertising during this scan; exclude BlueZ's pre-existing snapshot")
	c.Flags().StringVar(&scanFlags.name, "name", "", "only print devices whose name matches this substring")
	c.Flags().StringVar(&scanFlags.prefix, "prefix", "", "only print devices whose address starts with this prefix")
	c.Flags().BoolVar(&scanFlags.keepFilter, "keep-filter", false, "leave the DiscoveryFilter in place after scan returns (default: clear it)")
	c.Flags().BoolVar(&scanFlags.live, "live", false, "stream devices as they are discovered/updated instead of printing one table at the end")
	return c
}

func runScan(cmd *cobra.Command, args []string) error {
	// A live view with no explicit --duration runs until the user interrupts
	// it (Ctrl-C) - a fixed default window would silently cut the stream off.
	// A bounded window still applies if --duration was passed explicitly.
	unbounded := scanFlags.live && !cmd.Flags().Changed("duration")

	var ctx context.Context
	var cancel context.CancelFunc
	if unbounded {
		ctx, cancel = context.WithCancel(context.Background())
	} else {
		ctx, cancel = context.WithTimeout(context.Background(), time.Duration(scanFlags.duration+5)*time.Second)
	}
	defer cancel()

	// SIGINT/SIGTERM cancels the scan context so the loop unwinds and the
	// deferred BlueZ teardown (StopDiscovery / filter reset) still runs.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigCh)
	go func() {
		<-sigCh
		cancel()
		// A second signal hard-exits: if the deferred BlueZ teardown
		// (StopDiscovery / filter reset) wedges on an unresponsive
		// bluetoothd - most likely during an unbounded --live scan - the
		// user can still escalate Ctrl-C instead of having to SIGKILL from
		// another terminal.
		<-sigCh
		os.Exit(130)
	}()

	conn, err := bluez.Dial(root.adapter)
	if err != nil {
		return err
	}
	defer conn.Close()

	dur := time.Duration(scanFlags.duration) * time.Second
	if unbounded {
		dur = 0 // run until Ctrl-C (context cancel)
	}

	seen, _, err := runLiveScan(ctx, conn, liveScanConfig{
		duration:   dur,
		onlyNew:    scanFlags.onlyNew,
		keepFilter: scanFlags.keepFilter,
		matches:    matchesScanFilter,
		out:        os.Stdout,
		live:       scanFlags.live,
		inPlace:    scanFlags.live && !formatIsJSON() && stdoutIsTTY(),
		jsonMode:   scanFlags.live && formatIsJSON(),
	})
	if err != nil {
		return err
	}

	// In --live mode the per-event stream WAS the output; printing the
	// batch table/array again would just duplicate it. Emit a short
	// stderr summary and return.
	if scanFlags.live {
		matched := 0
		for _, di := range seen {
			if matchesScanFilter(di) {
				matched++
			}
		}
		statusf("scan complete: %d device(s)", matched)
		return nil
	}

	// Render.
	list := make([]bluez.DeviceInfo, 0, len(seen))
	for _, di := range seen {
		if !matchesScanFilter(di) {
			continue
		}
		list = append(list, di)
	}
	sort.Slice(list, func(i, j int) bool {
		// Strongest RSSI first; unknowns last.
		if list[i].RSSI == 0 && list[j].RSSI != 0 {
			return false
		}
		if list[j].RSSI == 0 && list[i].RSSI != 0 {
			return true
		}
		return list[i].RSSI > list[j].RSSI
	})

	if formatIsJSON() {
		return emitJSON(list)
	}
	if len(list) == 0 {
		// Distinguish "no devices in range" from "LE scan is unresponsive":
		// we counted the number of fresh PropertiesChanged/InterfacesAdded
		// events; if zero across the whole window, the radio is the
		// likely culprit and the user wants a different next step than
		// "scan harder."
		freshSeen := 0
		for _, di := range seen {
			if di.RSSI != 0 {
				freshSeen++
			}
		}
		if freshSeen == 0 {
			fmt.Println("no devices found (LE scan returned zero advertisement events - radio may be unresponsive; try: caeruleus adapter power cycle)")
		} else {
			fmt.Println("no devices found")
		}
		return nil
	}
	t := newTable()
	t.AppendHeader(table.Row{"ADDRESS", "TYPE", "RSSI", "DEVICE", "NAME"})
	for _, di := range list {
		devType := inferDeviceType(di.Appearance, di.UUIDs)
		t.AppendRow(table.Row{di.Address, di.AddrType, rssiStr(di.RSSI), devType, displayName(di)})
	}
	t.Render()
	return nil
}

// liveRowFmt lays out the live-scan columns. The leading "#" is a 1-based,
// first-seen index the shell's `connect <n>` resolves against. NAME is last
// because it's the only variable-width field; LASTSEEN is an HH:MM:SS stamp.
const liveRowFmt = "%3s  %-17s  %-6s  %5s  %-8s  %s"

// liveScanConfig parameterises runLiveScan, which backs both the top-level
// `scan` command and the interactive shell's `scan`.
type liveScanConfig struct {
	duration   time.Duration               // >0 = bounded window; 0 = until ctx/stop fires
	onlyNew    bool                        // exclude BlueZ's pre-existing cached snapshot
	keepFilter bool                        // leave the DiscoveryFilter in place on return
	matches    func(bluez.DeviceInfo) bool // row filter; nil accepts everything
	out        io.Writer                   // render target; defaults to os.Stdout
	live       bool                        // render incrementally (vs accumulate-only)
	inPlace    bool                        // redraw one table in place (TTY text)
	jsonMode   bool                        // emit discrete JSON events instead of a table
	footer     string                      // optional line under the in-place table
	stop       <-chan struct{}             // external stop (e.g. Enter pressed); nil = none
}

// indexer assigns each device path a stable 1-based index in first-seen order,
// so order[i] is the device shown at index i+1 (matching the live table column
// and the shell's `connect <n>`). Observe is idempotent per path.
type indexer struct {
	order []dbus.ObjectPath
	idxOf map[dbus.ObjectPath]int
}

func newIndexer() *indexer {
	return &indexer{idxOf: map[dbus.ObjectPath]int{}}
}

// Observe records a sighting of path and returns its 1-based index. firstSeen
// is true only the first time a given path is observed; repeats return the
// original index and never grow order.
func (ix *indexer) Observe(path dbus.ObjectPath) (idx int, firstSeen bool) {
	if i, ok := ix.idxOf[path]; ok {
		return i, false
	}
	ix.order = append(ix.order, path)
	i := len(ix.order)
	ix.idxOf[path] = i
	return i, true
}

// classify decides what a PropertiesChanged event on an already-tracked device
// means: "update" when a rendered field (RSSI/Name/AddrType) actually changed,
// "" (no event) when the re-observation is identical. The "found" case for a
// never-seen device is handled by the caller.
func classify(prev, next bluez.DeviceInfo) string {
	if next.RSSI != prev.RSSI || next.Name != prev.Name || next.AddrType != prev.AddrType {
		return "update"
	}
	return ""
}

// runLiveScan runs LE discovery and returns every device seen plus the paths
// in first-seen order (so order[i] is the device at 1-based index i+1, matching
// the table column and the shell's `connect <n>`). When cfg.live is set it also
// renders results as they arrive - an in-place table (inPlace), discrete JSON
// events (jsonMode), or append-only text lines. It returns when the duration
// elapses, cfg.stop fires, or ctx is cancelled. The caller owns the connection
// and any end-of-scan summary. order is populated only when cfg.live is set.
func runLiveScan(ctx context.Context, conn *bluez.Conn, cfg liveScanConfig) (map[dbus.ObjectPath]bluez.DeviceInfo, []dbus.ObjectPath, error) {
	if cfg.matches == nil {
		cfg.matches = func(bluez.DeviceInfo) bool { return true }
	}
	out := cfg.out
	if out == nil {
		out = os.Stdout
	}

	if on, _ := conn.Powered(); !on {
		logf("adapter powered off, turning on")
		if err := conn.SetPowered(true); err != nil {
			return nil, nil, fmt.Errorf("powering adapter: %w", err)
		}
	}

	// LE-only discovery + duplicate reporting so we see RSSI updates.
	_ = conn.SetDiscoveryFilter(map[string]dbus.Variant{
		"Transport":     dbus.MakeVariant("le"),
		"DuplicateData": dbus.MakeVariant(true),
	})
	if !cfg.keepFilter {
		// SetDiscoveryFilter with an empty dict restores defaults, so other
		// clients (bluetoothctl, another caeruleus run) aren't constrained.
		defer func() { _ = conn.SetDiscoveryFilter(map[string]dbus.Variant{}) }()
	}

	// Subscribe before starting so we don't race the first ad.
	addCh, err := conn.SubscribeInterfacesAdded(ctx, 64)
	if err != nil {
		return nil, nil, err
	}
	propCh, err := conn.Subscribe(ctx, conn.AdapterPath(), 128)
	if err != nil {
		return nil, nil, err
	}
	if err := conn.StartDiscovery(); err != nil {
		return nil, nil, fmt.Errorf("StartDiscovery: %w", err)
	}
	defer func() { _ = conn.StopDiscovery() }()

	// By default include devices BlueZ has cached from before this scan
	// window. They surface only via GetManagedObjects, not InterfacesAdded,
	// so a pure event-driven scan misses them. --new opts back into
	// event-only mode.
	seen := map[dbus.ObjectPath]bluez.DeviceInfo{}
	ix := newIndexer()                          // device paths in first-seen order, for stable rows
	lastSeen := map[dbus.ObjectPath]time.Time{} // most recent observation per device
	liveLines := 0                              // table lines (incl. header/footer) currently on screen

	fmtSeen := func(t time.Time) string {
		if t.IsZero() {
			return ""
		}
		return t.Format("15:04:05")
	}
	deviceRow := func(prefix, idx string, di bluez.DeviceInfo, seenAt time.Time) string {
		return prefix + fmt.Sprintf(liveRowFmt, idx, di.Address, di.AddrType, rssiStr(di.RSSI), fmtSeen(seenAt), displayName(di))
	}
	header := "    " + fmt.Sprintf(liveRowFmt, "#", "ADDRESS", "TYPE", "RSSI", "LASTSEEN", "NAME")

	// redraw rewrites the whole table in place: jump the cursor up over the
	// previous frame, then reprint header + one row per device. \033[K clears
	// each line's leftover tail so a shorter value can't ghost a longer one.
	redraw := func() {
		if liveLines > 0 {
			fmt.Fprintf(out, "\033[%dA", liveLines)
		}
		liveLines = 0
		draw := func(s string) { fmt.Fprintf(out, "%s\033[K\n", s); liveLines++ }
		draw(header)
		for i, p := range ix.order {
			draw(deviceRow("    ", strconv.Itoa(i+1), seen[p], lastSeen[p]))
		}
		if cfg.footer != "" {
			draw(cfg.footer)
		}
	}

	// emit reflects one observation, honouring the filter and output mode.
	// It's a no-op when cfg.live is false (accumulate-only for a batch table).
	// Every matched device joins `order` once, fixing its 1-based index across
	// all output modes (in-place, append, JSON).
	emit := func(di bluez.DeviceInfo, kind string, when time.Time) {
		if !cfg.live || !cfg.matches(di) {
			return
		}
		lastSeen[di.Path] = when
		idx, _ := ix.Observe(di.Path)
		switch {
		case cfg.jsonMode:
			_ = emitJSONEvent(scanEvent{Event: kind, Index: idx, Address: di.Address, AddrType: di.AddrType, RSSI: di.RSSI, Name: deviceName(di)})
		case cfg.inPlace:
			redraw()
		default: // append-only text: one line per event
			marker := "+"
			if kind == "update" {
				marker = "~"
			}
			fmt.Fprintln(out, deviceRow("["+marker+"] ", strconv.Itoa(idx), di, when))
		}
	}

	if cfg.live && !cfg.jsonMode {
		if cfg.inPlace {
			redraw() // paint the header (and footer) frame immediately
		} else {
			fmt.Fprintln(out, header)
		}
	}

	if !cfg.onlyNew {
		if initial, err := conn.Devices(); err == nil {
			now := time.Now()
			for _, di := range initial {
				seen[di.Path] = di
				emit(di, "found", now)
			}
		}
	}

	// A nil channel never fires, so an indefinite scan simply has no timed
	// arm and relies on cfg.stop / ctx below.
	var deadline <-chan time.Time
	if cfg.duration > 0 {
		deadline = time.After(cfg.duration)
		logf("scanning for %s…", cfg.duration)
	} else {
		logf("scanning until stopped…")
	}

	for {
		select {
		case <-deadline:
			return seen, ix.order, nil
		case <-cfg.stop:
			return seen, ix.order, nil
		case <-ctx.Done():
			return seen, ix.order, nil
		case ev := <-addCh:
			if props, ok := ev.Interfaces[bluez.IfaceDevice]; ok {
				di := propsToDevice(ev.Path, props)
				_, existed := seen[ev.Path]
				merge(seen, di)
				if existed {
					emit(seen[ev.Path], "update", time.Now())
				} else {
					emit(seen[ev.Path], "found", time.Now())
				}
			}
		case ev := <-propCh:
			if ev.Interface != bluez.IfaceDevice {
				continue
			}
			di, existed := seen[ev.Path]
			if !existed {
				di = bluez.DeviceInfo{Path: ev.Path}
			}
			prev := di
			updateDevice(&di, ev.Changed)
			seen[ev.Path] = di
			if !existed {
				emit(di, "found", time.Now())
			} else if kind := classify(prev, di); kind != "" {
				emit(di, kind, time.Now())
			}
		}
	}
}

// deviceName picks the human label for a device, preferring the advertised
// Name over the BlueZ Alias fallback. The result is raw, device-advertised
// text; terminal render paths must scrub it first (use displayName).
func deviceName(di bluez.DeviceInfo) string {
	if di.Name != "" {
		return di.Name
	}
	return di.Alias
}

// displayName is deviceName scrubbed for safe terminal rendering. BLE names are
// advertised by the peripheral and so are attacker-controlled; printing them
// verbatim would let an in-range advertiser inject ANSI/control sequences into
// the operator's terminal (cursor moves, screen clears, OSC title/clipboard, or
// corruption of the in-place redraw line accounting).
func displayName(di bluez.DeviceInfo) string {
	return sanitizeTerminal(deviceName(di))
}

// sanitizeTerminal drops C0 control bytes (including ESC 0x1b, the introducer
// for every CSI/OSC escape sequence) and DEL, so device-supplied text can't
// start a terminal escape sequence. Printable ASCII and any rune >= 0x20
// (UTF-8 glyphs) pass through unchanged.
func sanitizeTerminal(s string) string {
	if s == "" {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// rssiStr renders an RSSI for a table cell, leaving it blank when unknown (0).
func rssiStr(rssi int16) string {
	if rssi == 0 {
		return ""
	}
	return strconv.Itoa(int(rssi))
}

// stdoutIsTTY reports whether stdout is an interactive terminal. Used to gate
// cursor-control redraws: when stdout is a pipe/file we avoid ANSI escapes.
func stdoutIsTTY() bool {
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

func propsToDevice(path dbus.ObjectPath, props map[string]dbus.Variant) bluez.DeviceInfo {
	di := bluez.DeviceInfo{Path: path}
	updateDevice(&di, props)
	return di
}

func updateDevice(di *bluez.DeviceInfo, props map[string]dbus.Variant) {
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
		if uuids, ok := v.Value().([]string); ok {
			di.UUIDs = uuids
		}
	}
	if v, ok := props["Connected"]; ok {
		di.Connected, _ = v.Value().(bool)
	}
	if v, ok := props["Paired"]; ok {
		di.Paired, _ = v.Value().(bool)
	}
}

func merge(seen map[dbus.ObjectPath]bluez.DeviceInfo, di bluez.DeviceInfo) {
	if cur, ok := seen[di.Path]; ok {
		if di.Name == "" {
			di.Name = cur.Name
		}
		if di.Alias == "" {
			di.Alias = cur.Alias
		}
		if di.AddrType == "" {
			di.AddrType = cur.AddrType
		}
		if di.RSSI == 0 {
			di.RSSI = cur.RSSI
		}
		if di.Appearance == 0 {
			di.Appearance = cur.Appearance
		}
	}
	seen[di.Path] = di
}

func matchesScanFilter(di bluez.DeviceInfo) bool {
	if scanFlags.name != "" {
		hay := strings.ToLower(di.Name + " " + di.Alias)
		if !strings.Contains(hay, strings.ToLower(scanFlags.name)) {
			return false
		}
	}
	if scanFlags.prefix != "" {
		if !strings.HasPrefix(strings.ToUpper(di.Address), strings.ToUpper(scanFlags.prefix)) {
			return false
		}
	}
	return true
}
