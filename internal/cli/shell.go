package cli

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/chzyer/readline"
	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"caeruleus/internal/bluez"
)

func newShellCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "shell",
		Aliases: []string{"interactive"},
		Short:   "Open an interactive readline shell against a device",
		RunE:    runShell,
	}
}

type shell struct {
	s        *session
	rl       *readline.Instance // nil in headless modes (batch, serve)
	headless bool               // when true, suppress prompts/colour and async notification pumping
	in       io.Reader          // stdin for headless modes
	out      io.Writer          // stdout destination (defaults to os.Stdout if nil)
	err      io.Writer          // stderr destination when rl == nil
	// sessMu guards reassignment of sh.s.tree and sh.s.device against
	// the notification-pump goroutine. The readline goroutine writes
	// (in cmdConnect / cmdDisconnect); the pump reads. Other cmd*
	// methods that only read run in the same goroutine as the writers
	// so they don't need to take the lock themselves. RWMutex (over
	// plain Mutex) because reads outnumber writes by orders of
	// magnitude in any notification-heavy session.
	sessMu   sync.RWMutex
	notifyMu sync.Mutex
	notify   map[uint16]chan struct{} // active notification subscriptions
}

// sessSnap captures sh.s.tree under sessMu.RLock and returns the
// pointer. Once captured, GattTree itself is immutable (cmdConnect
// builds a new one and reassigns the field), so the caller can iterate
// .Characteristics safely without holding the lock.
func (sh *shell) sessSnap() *bluez.GattTree {
	sh.sessMu.RLock()
	defer sh.sessMu.RUnlock()
	return sh.s.tree
}

// stdOut returns the writer command output should go to.
func (sh *shell) stdOut() io.Writer {
	if sh.out != nil {
		return sh.out
	}
	return os.Stdout
}

// errOut returns the right writer for diagnostics, falling back gracefully
// when no readline instance is attached (batch / serve modes).
func (sh *shell) errOut() io.Writer {
	if sh.rl != nil {
		return sh.rl.Stderr()
	}
	if sh.err != nil {
		return sh.err
	}
	return os.Stderr
}

func runShell(cmd *cobra.Command, args []string) error {
	addr, err := requireBdaddr()
	if err != nil {
		// allow shell without bdaddr: user can `connect XX:..` later
		addr = ""
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	conn, err := bluez.Dial(root.adapter)
	if err != nil {
		return err
	}
	sess := &session{conn: conn}
	if addr != "" {
		sess.device = conn.Device(addr)
		if root.addrType != "" {
			_ = sess.device.SetAddressType(root.addrType)
		}
	}
	defer sess.close()

	rl, err := readline.NewEx(&readline.Config{
		Prompt:          shellPrompt(sess),
		HistoryFile:     historyFile(),
		InterruptPrompt: "^C",
		EOFPrompt:       "quit",
		AutoComplete:    shellCompleter(),
	})
	if err != nil {
		return err
	}
	defer rl.Close()

	// Convert non-graceful termination signals into a clean shutdown path
	// so the deferred BLE teardown actually runs. Without this, SIGHUP
	// (terminal close) and SIGTERM (`kill PID`) skip session.close, which
	// leaves bluetoothd thinking the peripheral is still Connected=true
	// for several seconds - and the next `caeruleus` invocation finds
	// itself talking to a stale link. SIGINT is intentionally left for
	// readline to handle as Ctrl-C / line interrupt.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(sigCh)
	go func() {
		sig, ok := <-sigCh
		if !ok {
			return
		}
		logf("received %s, shutting down", sig)
		_ = rl.Close() // unblocks Readline() with io.EOF
		cancel()
	}()

	sh := &shell{s: sess, rl: rl, notify: map[uint16]chan struct{}{}}

	// Start a background goroutine that prints async notifications above
	// the prompt while the user is typing.
	notifyCtx, stopNotify := context.WithCancel(ctx)
	defer stopNotify()
	sh.startNotificationPump(notifyCtx)

	if showBanner() {
		color.New(color.FgCyan).Fprint(rl.Stderr(), bannerArt)
	}
	color.New(color.FgHiBlack).Fprintln(rl.Stderr(), "caeruleus shell - type 'help' or 'quit'.")
	for {
		rl.SetPrompt(shellPrompt(sh.s))
		line, err := rl.Readline()
		if err == readline.ErrInterrupt {
			if len(line) == 0 {
				return nil
			}
			continue
		}
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if quit := sh.run(notifyCtx, line); quit {
			return nil
		}
	}
}

func shellPrompt(s *session) string {
	connected := false
	addr := "no device"
	if s.device != nil {
		connected, _ = s.device.Connected()
		a, _ := s.device.Address()
		if a == "" {
			a = strings.TrimPrefix(string(s.device.Path), "/org/bluez/hci0/dev_")
		}
		addr = a
	}
	dot := "○"
	if connected {
		dot = color.GreenString("●")
	} else {
		dot = color.RedString("○")
	}
	return fmt.Sprintf("%s [%s]> ", dot, addr)
}

func historyFile() string {
	if h, err := os.UserHomeDir(); err == nil {
		return h + "/.caeruleus_history"
	}
	return ""
}

func shellCompleter() readline.AutoCompleter {
	return readline.NewPrefixCompleter(
		readline.PcItem("help"),
		readline.PcItem("quit"),
		readline.PcItem("exit"),
		readline.PcItem("connect"),
		readline.PcItem("disconnect"),
		readline.PcItem("primary"),
		readline.PcItem("characteristics"),
		readline.PcItem("enumerate"),
		readline.PcItem("mtu"),
		readline.PcItem("char-read-hnd"),
		readline.PcItem("read"),
		readline.PcItem("char-write-cmd"),
		readline.PcItem("char-write-req"),
		readline.PcItem("write"),
		readline.PcItem("write-string"),
		readline.PcItem("listen"),
		readline.PcItem("notify-on"),
		readline.PcItem("notify-off"),
		readline.PcItem("brute"),
		readline.PcItem("loop-read"),
	)
}

func (sh *shell) run(ctx context.Context, line string) (quit bool) {
	fields := splitFields(line)
	if len(fields) == 0 {
		return false
	}
	cmd, args := fields[0], fields[1:]
	switch strings.ToLower(cmd) {
	case "quit", "exit", "q":
		return true
	case "help", "?":
		printShellHelp(sh.errOut())
	case "connect":
		sh.cmdConnect(ctx, args)
	case "disconnect":
		sh.cmdDisconnect()
	case "primary":
		sh.cmdPrimary()
	case "characteristics", "chars":
		sh.cmdCharacteristics()
	case "enumerate", "enum":
		sh.cmdEnumerate()
	case "mtu":
		sh.cmdMTU(args)
	case "char-read-hnd", "char-read", "read":
		sh.cmdRead(args)
	case "char-write-cmd", "write":
		sh.cmdWrite(args, false)
	case "char-write-req":
		sh.cmdWrite(args, true)
	case "write-string", "char-write-str":
		sh.cmdWriteString(args, false)
	case "write-string-req":
		sh.cmdWriteString(args, true)
	case "listen":
		sh.cmdListen(args)
	case "notify-on":
		sh.cmdNotifyOn(args)
	case "notify-off":
		sh.cmdNotifyOff(args)
	case "brute":
		sh.cmdBrute(args)
	case "loop-read":
		sh.cmdLoopRead(args)
	default:
		fmt.Fprintf(sh.errOut(), "unknown command: %s (try 'help')\n", cmd)
	}
	return false
}

func printShellHelp(w io.Writer) {
	fmt.Fprintln(w, `commands:
  connect [BDADDR]              connect to current or new device
  disconnect                    drop the GATT link
  primary                       list primary services
  characteristics               list characteristics
  enumerate                     print full GATT tree with values
  mtu                           show negotiated ATT MTU
  char-read-hnd 0xNNNN          read a handle (hex or decimal)
  char-write-cmd 0xNNNN HEX     write without response
  char-write-req 0xNNNN HEX     write with response
  write-string  0xNNNN STRING   write an ASCII string (no response)
  write-string-req 0xNNNN STR   write an ASCII string (with response)
  listen 0xNNNN [seconds]       subscribe + wait + auto-unsubscribe
  notify-on 0xNNNN              enable async notifications on a handle
  notify-off 0xNNNN             disable a previously-enabled subscription
  brute 0xWHND 0xRHND [start end]
                                write each value start..end to WHND, read RHND,
                                print the resulting hex/ascii for each step
  loop-read 0xNNNN N            read a handle N times in a row (prints changes)
  quit                          exit`)
}

// --- handlers ---

func (sh *shell) ensureConnected() bool {
	if sh.s.device == nil {
		fmt.Fprintln(sh.errOut(), "no device - try: connect XX:XX:XX:XX:XX:XX")
		return false
	}
	connected, _ := sh.s.device.Connected()
	if !connected {
		fmt.Fprintln(sh.errOut(), "not connected - try: connect")
		return false
	}
	if sh.s.tree == nil {
		t, err := sh.s.conn.EnumerateGatt(sh.s.device.Path)
		if err != nil {
			fmt.Fprintln(sh.errOut(), "enumerate:", err)
			return false
		}
		sh.sessMu.Lock()
		sh.s.tree = t
		sh.sessMu.Unlock()
	}
	return true
}

func (sh *shell) cmdConnect(ctx context.Context, args []string) {
	addr := ""
	if len(args) > 0 {
		addr = strings.ToUpper(args[0])
	}
	if addr != "" {
		if !validMAC(addr) {
			fmt.Fprintln(sh.errOut(), "invalid BD_ADDR")
			return
		}
		sh.sessMu.Lock()
		sh.s.device = sh.s.conn.Device(addr)
		if root.addrType != "" {
			_ = sh.s.device.SetAddressType(root.addrType)
		}
		sh.s.tree = nil
		sh.sessMu.Unlock()
	}
	if sh.s.device == nil {
		fmt.Fprintln(sh.errOut(), "no address - usage: connect XX:XX:XX:XX:XX:XX")
		return
	}
	timeout := time.Duration(root.timeout) * time.Second
	t0 := time.Now()
	if err := sh.s.device.Connect(ctx, timeout); err != nil {
		fmt.Fprintln(sh.errOut(), "connect:", err)
		return
	}
	tree, err := sh.s.conn.EnumerateGatt(sh.s.device.Path)
	if err != nil {
		fmt.Fprintln(sh.errOut(), "enumerate:", err)
		return
	}
	sh.sessMu.Lock()
	sh.s.tree = tree
	sh.sessMu.Unlock()
	if !root.quiet {
		// Route via sh.errOut() so serve-mode clients see this on the
		// response socket; statusf would short-circuit to os.Stderr and
		// the daemon-side terminal instead of the client.
		fmt.Fprintf(sh.errOut(), "[+] connected in %s - %d services, %d chars, %d descs\n",
			time.Since(t0).Round(time.Millisecond), len(tree.Services), len(tree.Characteristics), len(tree.Descriptors))
	}
}

func (sh *shell) cmdDisconnect() {
	if sh.s.device == nil {
		return
	}
	_ = sh.s.device.Disconnect()
	sh.sessMu.Lock()
	sh.s.tree = nil
	sh.sessMu.Unlock()
}

func (sh *shell) cmdPrimary() {
	if !sh.ensureConnected() {
		return
	}
	for _, l := range computeServiceRanges(sh.s.tree) {
		fmt.Fprintf(sh.stdOut(), "attr handle: 0x%04x, end grp handle: 0x%04x uuid: %s\n", l.Start, l.End, l.UUID)
	}
}

func (sh *shell) cmdCharacteristics() {
	if !sh.ensureConnected() {
		return
	}
	// sort by handle
	chars := append([]bluez.GattObject(nil), sh.s.tree.Characteristics...)
	for i := 0; i < len(chars); i++ {
		for j := i + 1; j < len(chars); j++ {
			if chars[j].Handle < chars[i].Handle {
				chars[i], chars[j] = chars[j], chars[i]
			}
		}
	}
	for _, ch := range chars {
		decl := ch.Handle
		if decl > 0 {
			decl--
		}
		fmt.Fprintf(sh.stdOut(), "handle: 0x%04x, char properties: 0x%02x, char value handle: 0x%04x, uuid: %s\n",
			decl, propsMask(ch.Flags), ch.Handle, ch.UUID)
	}
}

func (sh *shell) cmdEnumerate() {
	if !sh.ensureConnected() {
		return
	}
	rows := buildEnumRows(sh.s)
	for _, r := range rows {
		fmt.Fprintf(sh.stdOut(), "0x%04x  %s  [%s]\n", r.CharHandle, r.CharUUID, r.Properties)
		if r.ValueHex != "" {
			fmt.Fprintf(sh.stdOut(), "        hex   : %s\n", r.ValueHex)
			fmt.Fprintf(sh.stdOut(), "        ascii : %s\n", r.ValueASCII)
		}
		for _, d := range r.DescriptorRows {
			fmt.Fprintf(sh.stdOut(), "  ↳ desc 0x%04x  %s  %s\n", d.Handle, d.UUID, d.Value)
		}
	}
}

func (sh *shell) cmdMTU(args []string) {
	if !sh.ensureConnected() {
		return
	}
	// Find any characteristic and read its MTU property.
	for _, ch := range sh.s.tree.Characteristics {
		c := sh.s.conn.Characteristic(ch.Path)
		if m, err := c.MTU(); err == nil && m > 0 {
			fmt.Fprintf(sh.stdOut(), "MTU: %d\n", m)
			return
		}
	}
	fmt.Fprintln(sh.stdOut(), "MTU property unavailable on this BlueZ")
}

func (sh *shell) cmdRead(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(sh.errOut(), "usage: char-read-hnd 0xNNNN")
		return
	}
	if !sh.ensureConnected() {
		return
	}
	h, err := parseHandle(args[0])
	if err != nil {
		fmt.Fprintln(sh.errOut(), err)
		return
	}
	obj, ok := sh.s.tree.ByHandle[h]
	if !ok {
		fmt.Fprintf(sh.errOut(), "no object at handle 0x%04x\n", h)
		return
	}
	var v []byte
	if obj.Kind == "descriptor" {
		v, err = sh.s.conn.Descriptor(obj.Path).ReadValue(0)
	} else {
		v, err = sh.s.conn.Characteristic(obj.Path).ReadValue(0)
	}
	if err != nil {
		fmt.Fprintln(sh.errOut(), "read:", err)
		return
	}
	fmt.Fprintln(sh.stdOut(), formatReadLine(obj.Handle, v))
}

func (sh *shell) cmdWrite(args []string, withResponse bool) {
	if len(args) < 2 {
		fmt.Fprintln(sh.errOut(), "usage: char-write-{cmd,req} 0xNNNN HEXVALUE")
		return
	}
	if !sh.ensureConnected() {
		return
	}
	h, err := parseHandle(args[0])
	if err != nil {
		fmt.Fprintln(sh.errOut(), err)
		return
	}
	payload, err := parseHexBytes(args[1])
	if err != nil {
		fmt.Fprintln(sh.errOut(), err)
		return
	}
	sh.writeBytes(h, payload, withResponse)
}

func (sh *shell) cmdWriteString(args []string, withResponse bool) {
	if len(args) < 2 {
		fmt.Fprintln(sh.errOut(), "usage: write-string 0xNNNN STRING")
		return
	}
	if !sh.ensureConnected() {
		return
	}
	h, err := parseHandle(args[0])
	if err != nil {
		fmt.Fprintln(sh.errOut(), err)
		return
	}
	// re-join args[1:] preserving spaces from the user's input
	val := strings.Join(args[1:], " ")
	sh.writeBytes(h, []byte(val), withResponse)
}

func (sh *shell) writeBytes(h uint16, payload []byte, withResponse bool) {
	obj, ok := sh.s.tree.ByHandle[h]
	if !ok {
		fmt.Fprintf(sh.errOut(), "no object at handle 0x%04x\n", h)
		return
	}
	if obj.Kind == "descriptor" {
		if err := sh.s.conn.Descriptor(obj.Path).WriteValue(payload); err != nil {
			fmt.Fprintln(sh.errOut(), "write:", err)
			return
		}
		fmt.Fprintf(sh.stdOut(), "0x%04x written=%d type=descriptor\n", obj.Handle, len(payload))
		return
	}
	wt := bluez.WriteCommand
	if withResponse || (!propsCan(obj.Flags, "write-without-response") && propsCan(obj.Flags, "write")) {
		wt = bluez.WriteRequest
	}
	if err := sh.s.conn.Characteristic(obj.Path).WriteValue(payload, wt); err != nil {
		fmt.Fprintln(sh.errOut(), "write:", err)
		return
	}
	fmt.Fprintln(sh.stdOut(), formatWriteLine(obj.Handle, payload, wt))
}

func (sh *shell) cmdListen(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(sh.errOut(), "usage: listen 0xNNNN [seconds]")
		return
	}
	if !sh.ensureConnected() {
		return
	}
	h, err := parseHandle(args[0])
	if err != nil {
		fmt.Fprintln(sh.errOut(), err)
		return
	}
	secs := 5
	if len(args) >= 2 {
		if n, err := strconv.Atoi(args[1]); err == nil {
			secs = n
		}
	}
	obj, ok := sh.s.tree.ByHandle[h]
	if !ok || obj.Kind != "characteristic" {
		fmt.Fprintf(sh.errOut(), "no characteristic at 0x%04x\n", h)
		return
	}
	c := sh.s.conn.Characteristic(obj.Path)

	// IMPORTANT: subscribe to PropertiesChanged BEFORE StartNotify, otherwise
	// peripherals that push a notification immediately on subscribe will
	// race past us and we'll silently miss the first event.
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(secs)*time.Second)
	defer cancel()
	ch, err := sh.s.conn.Subscribe(ctx, sh.s.device.Path, 64)
	if err != nil {
		fmt.Fprintln(sh.errOut(), "subscribe:", err)
		return
	}
	if err := c.StartNotify(); err != nil {
		fmt.Fprintln(sh.errOut(), "StartNotify:", err)
		return
	}
	defer func() { _ = c.StopNotify() }()

	deadline := time.After(time.Duration(secs) * time.Second)
	got := 0
	for {
		select {
		case <-deadline:
			if got == 0 && sh.headless {
				// Common batch-mode trap: the trigger write went out *before* we
				// subscribed, so the firmware-emitted notification raced past us.
				// Point the user at the atomic alternative.
				fmt.Fprintf(sh.errOut(),
					"listen 0x%04x: 0 events in %ds - note that batch mode subscribes only when this line runs, so a trigger write earlier in the script may have already fired. For atomic trigger-then-listen use the standalone subcommand: `caeruleus listen -a 0x%04x --trigger-value 01`\n",
					obj.Handle, secs, obj.Handle)
			}
			return
		case ev, ok := <-ch:
			if !ok {
				return
			}
			if ev.Path != obj.Path || ev.Interface != bluez.IfaceCharacteristic {
				continue
			}
			raw, ok := ev.Changed["Value"]
			if !ok {
				continue
			}
			b, _ := raw.Value().([]byte)
			fmt.Fprintf(sh.stdOut(), "Notification handle = 0x%04x value: %s\n", obj.Handle, spacedHex(b))
			if a := asciiize(b); a != "" {
				fmt.Fprintf(sh.stdOut(), "                          ascii: %s\n", a)
			}
			got++
		}
	}
}

// cmdBrute writes each byte value in [start,end] to a write handle, reads a
// response handle after every step, and prints (input, response) pairs.
// Default: only print when the response differs from the previous iteration
// - most fuzzes have one or two distinct responses across 256 inputs and
// dumping every iteration is noise. Append the literal token "all" as an
// extra arg to force printing every step (e.g. `brute 0xW 0xR 0 255 all`).
func (sh *shell) cmdBrute(args []string) {
	if len(args) < 2 {
		fmt.Fprintln(sh.errOut(), "usage: brute 0xWHND 0xRHND [START END] [all]")
		return
	}
	if !sh.ensureConnected() {
		return
	}
	whnd, err := parseHandle(args[0])
	if err != nil {
		fmt.Fprintln(sh.errOut(), err)
		return
	}
	rhnd, err := parseHandle(args[1])
	if err != nil {
		fmt.Fprintln(sh.errOut(), err)
		return
	}
	start, end := uint(0), uint(255)
	printAll := false
	// Trailing positional args. Accepted shapes:
	//   brute W R - default range, changes-only
	//   brute W R all - default range, every step
	//   brute W R START END - custom range, changes-only
	//   brute W R START END all - custom range, every step
	rest := args[2:]
	if len(rest) > 0 && strings.EqualFold(rest[len(rest)-1], "all") {
		printAll = true
		rest = rest[:len(rest)-1]
	}
	if len(rest) >= 2 {
		if v, err := strconv.ParseUint(rest[0], 0, 16); err == nil {
			start = uint(v)
		}
		if v, err := strconv.ParseUint(rest[1], 0, 16); err == nil {
			end = uint(v)
		}
	}
	wobj, ok := sh.s.tree.ByHandle[whnd]
	if !ok {
		fmt.Fprintf(sh.errOut(), "no write handle 0x%04x\n", whnd)
		return
	}
	robj, ok := sh.s.tree.ByHandle[rhnd]
	if !ok {
		fmt.Fprintf(sh.errOut(), "no read handle 0x%04x\n", rhnd)
		return
	}
	wc := sh.s.conn.Characteristic(wobj.Path)
	rc := sh.s.conn.Characteristic(robj.Path)
	wt := bluez.WriteCommand
	if !propsCan(wobj.Flags, "write-without-response") && propsCan(wobj.Flags, "write") {
		wt = bluez.WriteRequest
	}

	t0 := time.Now()
	var prev []byte
	first := true
	distinct := 0
	for v := start; v <= end; v++ {
		payload := []byte{byte(v)}
		if err := wc.WriteValue(payload, wt); err != nil {
			fmt.Fprintf(sh.errOut(), "write %02x: %v\n", v, err)
			continue
		}
		got, err := rc.ReadValue(0)
		if err != nil {
			fmt.Fprintf(sh.errOut(), "read after %02x: %v\n", v, err)
			continue
		}
		changed := first || !bytesEqual(prev, got)
		if changed {
			distinct++
		}
		if printAll || changed {
			fmt.Fprintf(sh.stdOut(), "%02x -> hex=%s ascii=%q\n", v, spacedHex(got), asciiize(got))
		}
		prev = append(prev[:0], got...)
		first = false
	}
	fmt.Fprintf(sh.errOut(), "brute done in %s; %d distinct response(s)\n",
		time.Since(t0).Round(time.Millisecond), distinct)
}

// cmdLoopRead reads a handle N times. It prints the iteration index every
// time the value changes (or every iteration if --print-all is desired by
// the caller - kept simple here), plus the final value.
func (sh *shell) cmdLoopRead(args []string) {
	if len(args) < 2 {
		fmt.Fprintln(sh.errOut(), "usage: loop-read 0xNNNN N")
		return
	}
	if !sh.ensureConnected() {
		return
	}
	h, err := parseHandle(args[0])
	if err != nil {
		fmt.Fprintln(sh.errOut(), err)
		return
	}
	n, err := strconv.Atoi(args[1])
	if err != nil || n <= 0 {
		fmt.Fprintln(sh.errOut(), "N must be a positive integer")
		return
	}
	obj, ok := sh.s.tree.ByHandle[h]
	if !ok {
		fmt.Fprintf(sh.errOut(), "no object at handle 0x%04x\n", h)
		return
	}
	c := sh.s.conn.Characteristic(obj.Path)
	t0 := time.Now()
	var last, prev []byte
	for i := 1; i <= n; i++ {
		v, err := c.ReadValue(0)
		if err != nil {
			fmt.Fprintf(sh.errOut(), "read #%d: %v\n", i, err)
			return
		}
		if !bytesEqual(prev, v) {
			fmt.Fprintf(sh.stdOut(), "#%d hex=%s ascii=%q\n", i, spacedHex(v), asciiize(v))
			prev = append(prev[:0], v...)
		}
		last = v
	}
	fmt.Fprintf(sh.errOut(), "loop-read done in %s, final=%s ascii=%q\n",
		time.Since(t0).Round(time.Millisecond), spacedHex(last), asciiize(last))
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// notify-on/notify-off - long-lived background subscriptions; events printed
// asynchronously above the prompt by startNotificationPump.
func (sh *shell) cmdNotifyOn(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(sh.errOut(), "usage: notify-on 0xNNNN")
		return
	}
	if !sh.ensureConnected() {
		return
	}
	h, err := parseHandle(args[0])
	if err != nil {
		fmt.Fprintln(sh.errOut(), err)
		return
	}
	obj, ok := sh.s.tree.ByHandle[h]
	if !ok || obj.Kind != "characteristic" {
		fmt.Fprintf(sh.errOut(), "no characteristic at 0x%04x\n", h)
		return
	}
	sh.notifyMu.Lock()
	if _, exists := sh.notify[h]; exists {
		sh.notifyMu.Unlock()
		fmt.Fprintf(sh.errOut(), "already listening on 0x%04x\n", h)
		return
	}
	sh.notifyMu.Unlock()

	c := sh.s.conn.Characteristic(obj.Path)
	if err := c.StartNotify(); err != nil {
		fmt.Fprintln(sh.errOut(), "StartNotify:", err)
		return
	}
	sh.notifyMu.Lock()
	sh.notify[h] = make(chan struct{})
	sh.notifyMu.Unlock()
	fmt.Fprintf(sh.errOut(), "notifications enabled on 0x%04x\n", h)
}

func (sh *shell) cmdNotifyOff(args []string) {
	if len(args) < 1 || !sh.ensureConnected() {
		return
	}
	h, err := parseHandle(args[0])
	if err != nil {
		fmt.Fprintln(sh.errOut(), err)
		return
	}
	obj, ok := sh.s.tree.ByHandle[h]
	if !ok {
		return
	}
	c := sh.s.conn.Characteristic(obj.Path)
	_ = c.StopNotify()
	sh.notifyMu.Lock()
	delete(sh.notify, h)
	sh.notifyMu.Unlock()
}

// startNotificationPump prints PropertiesChanged events for any characteristic
// the user has enabled via notify-on.
func (sh *shell) startNotificationPump(ctx context.Context) {
	if sh.s.device == nil {
		return
	}
	ch, err := sh.s.conn.Subscribe(ctx, sh.s.device.Path, 128)
	if err != nil {
		return
	}
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case ev, ok := <-ch:
				if !ok {
					return
				}
				if ev.Interface != bluez.IfaceCharacteristic {
					continue
				}
				raw, ok := ev.Changed["Value"]
				if !ok {
					continue
				}
				b, _ := raw.Value().([]byte)
				// Snapshot the tree under the lock; iteration is safe
				// because GattTree itself is immutable once built.
				tree := sh.sessSnap()
				h := uint16(0)
				if tree != nil {
					for _, c := range tree.Characteristics {
						if c.Path == ev.Path {
							h = c.Handle
							break
						}
					}
				}
				sh.notifyMu.Lock()
				_, watching := sh.notify[h]
				sh.notifyMu.Unlock()
				if !watching {
					continue
				}
				// Print above the prompt when interactive; otherwise just
				// emit the line verbatim.
				if sh.rl != nil {
					sh.rl.Clean()
				}
				fmt.Fprintf(sh.stdOut(), "[notify 0x%04x] hex=%s ascii=%s\n", h, hex.EncodeToString(b), asciiize(b))
				if sh.rl != nil {
					sh.rl.Refresh()
				}
			}
		}
	}()
}

func splitFields(line string) []string {
	// Whitespace tokenizer with quoted-string + backslash-escape support.
	// `\"` and `\\` inside a quoted string emit a literal quote / backslash;
	// outside quotes the escape is also honoured so things like
	// `write-string 0xH foo\ bar` (a single payload with a space) work.
	var out []string
	var cur strings.Builder
	inq := false
	escape := false
	for _, r := range line {
		if escape {
			cur.WriteRune(r)
			escape = false
			continue
		}
		switch {
		case r == '\\':
			escape = true
		case r == '"':
			inq = !inq
		case (r == ' ' || r == '\t') && !inq:
			if cur.Len() > 0 {
				out = append(out, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteRune(r)
		}
	}
	// A trailing lone backslash emits itself rather than vanishing - most
	// shells diverge here but "treat as literal" matches user expectation
	// when typing interactively.
	if escape {
		cur.WriteRune('\\')
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}
