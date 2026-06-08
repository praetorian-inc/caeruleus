package cli

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/spf13/cobra"

	"caeruleus/internal/bluez"
)

var serveFlags struct {
	socket string
}

const (
	// Sentinel terminating each command's response. Single-character lines
	// are unlikely to collide with real shell output, and the framing keeps
	// the protocol streamable.
	serveOK  = "__CAER_OK__"
	serveERR = "__CAER_ERR__"
)

func newServeCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "serve",
		Short: "Run a long-lived daemon holding one GATT link; clients dispatch over a Unix socket",
		Long: `serve opens a Unix-domain socket and accepts shell-syntax commands
(one per line) from clients. The daemon owns one bluez connection plus one
connected Device, so subsequent operations skip the ~1.5s reconnect cost
per CLI invocation.

The MVP runs single-client serial - one connection at a time, requests
processed in order. Concurrent multi-client support is a future iteration.

Protocol: client connects, sends one or more newline-terminated commands,
reads the daemon's stdout for each until a sentinel line:

  __CAER_OK__   command succeeded
  __CAER_ERR__  command failed (preceding lines describe the error)

Clients can use 'caeruleus send' to send a single command, or speak the
protocol directly. The CAERULEUS_SOCK env var, if set, makes 'send'
default to that path.`,
		RunE: runServe,
	}
	c.Flags().StringVar(&serveFlags.socket, "socket", defaultServeSocket(), "Unix socket path to listen on")
	return c
}

func defaultServeSocket() string {
	if home, err := os.UserHomeDir(); err == nil {
		dir := filepath.Join(home, ".cache", "caeruleus")
		_ = os.MkdirAll(dir, 0o700)
		return filepath.Join(dir, "serve.sock")
	}
	return "/tmp/caeruleus.sock"
}

func runServe(cmd *cobra.Command, args []string) error {
	addr := root.bdaddr
	if addr != "" && !validMAC(addr) {
		return fmt.Errorf("invalid BD_ADDR %q", addr)
	}

	if err := os.Remove(serveFlags.socket); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove stale socket %s: %w", serveFlags.socket, err)
	}
	listener, err := net.Listen("unix", serveFlags.socket)
	if err != nil {
		return fmt.Errorf("listen %s: %w", serveFlags.socket, err)
	}
	defer listener.Close()
	defer os.Remove(serveFlags.socket)

	// Tight perms so other users on the box can't drive this daemon.
	if err := os.Chmod(serveFlags.socket, 0o600); err != nil {
		logf("chmod socket: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// SIGINT/SIGTERM → close listener so Accept returns and we exit cleanly.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		cancel()
		listener.Close()
	}()

	conn, err := bluez.Dial(root.adapter)
	if err != nil {
		return err
	}
	sess := &session{conn: conn}
	if addr != "" {
		sess.device = conn.Device(strings.ToUpper(addr))
		if root.addrType != "" {
			_ = sess.device.SetAddressType(root.addrType)
		}
	}
	defer sess.close()

	sh := &shell{
		s:        sess,
		headless: true,
		notify:   map[uint16]chan struct{}{},
	}

	// Auto-connect to the configured peripheral so the first client request
	// doesn't pay the connect cost.
	if addr != "" {
		// Temporarily route output to stderr so the connect log appears in
		// the daemon's own stderr, not nowhere.
		sh.out, sh.err = os.Stderr, os.Stderr
		sh.cmdConnect(ctx, nil)
		sh.out, sh.err = nil, nil
	}

	logf("serving on %s (bdaddr=%s adapter=%s)", serveFlags.socket, addr, root.adapter)
	fmt.Printf("listening on %s\n", serveFlags.socket)

	// Serial handler - one client at a time. Accept blocks, then we run
	// handleServeConn synchronously in the same goroutine, then loop.
	// That synchronous pattern is what makes operations serial; no mutex
	// needed. Going concurrent (goroutine per Accept) would need a real
	// lock around the shell's state - left for the multi-client iteration.
	for {
		c, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("accept: %w", err)
		}
		handleServeConn(ctx, c, sh)
	}
}

// handleServeConn services one client connection. Each newline-terminated
// line is dispatched as a shell command; the response is the command's
// stdout/stderr followed by a sentinel line.
func handleServeConn(ctx context.Context, c net.Conn, sh *shell) {
	defer c.Close()

	// Route shell output to this client for the duration of the connection.
	sh.out = c
	sh.err = c
	defer func() {
		sh.out = nil
		sh.err = nil
	}()

	scanner := bufio.NewScanner(c)
	// Match batch.go / write.go's explicit 64 KiB ceiling so the line-size
	// contract is consistent across every stdin-driven entry point.
	scanner.Buffer(make([]byte, 0, 4096), 65536)
	scanner.Buffer(make([]byte, 0, 4096), 65536)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			fmt.Fprintln(c, serveOK)
			continue
		}
		if line == "quit" || line == "exit" {
			fmt.Fprintln(c, serveOK)
			return
		}
		quit := sh.run(ctx, line)
		fmt.Fprintln(c, serveOK)
		if quit {
			return
		}
	}
}

// --- client (`send`) ---

var sendFlags struct {
	socket string
}

func newSendCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "send",
		Short: "Send one shell command to a running 'caeruleus serve' daemon",
		Long: `send opens the daemon's Unix socket, writes a single command line, and
streams the response back to stdout until the sentinel. Useful for scripting
against a persistent connection without paying the per-call connect cost.

The socket path comes from --socket, or $CAERULEUS_SOCK, or the default
~/.cache/caeruleus/serve.sock - in that order.

Example:

  caeruleus serve -b 6C:C8:40:87:29:36 &
  export CAERULEUS_SOCK=~/.cache/caeruleus/serve.sock
  caeruleus send "read 0x0029"
  caeruleus send "write 0x002b -s 'BLE{FOO}' --req"`,
		// Exactly one argument: the full command line. Multi-arg invocations
		// were previously silently joined with spaces, which made shell
		// quoting subtly wrong. Force the caller to quote the command as a
		// single argument so what they typed is what we send.
		Args: cobra.ExactArgs(1),
		RunE: runSend,
	}
	c.Flags().StringVar(&sendFlags.socket, "socket", "", "Unix socket path (default: $CAERULEUS_SOCK or ~/.cache/caeruleus/serve.sock)")
	return c
}

func runSend(cmd *cobra.Command, args []string) error {
	socket := sendFlags.socket
	if socket == "" {
		socket = os.Getenv("CAERULEUS_SOCK")
	}
	if socket == "" {
		socket = defaultServeSocket()
	}
	// ExactArgs(1) above guarantees args has length 1.
	line := args[0]

	c, err := net.Dial("unix", socket)
	if err != nil {
		return fmt.Errorf("dial %s: %w (is 'caeruleus serve' running?)", socket, err)
	}
	defer c.Close()

	if _, err := fmt.Fprintln(c, line); err != nil {
		return fmt.Errorf("write command: %w", err)
	}

	scanner := bufio.NewScanner(c)
	// Match batch.go / write.go's explicit 64 KiB ceiling so the line-size
	// contract is consistent across every stdin-driven entry point.
	scanner.Buffer(make([]byte, 0, 4096), 65536)
	scanner.Buffer(make([]byte, 0, 4096), 1<<20)
	for scanner.Scan() {
		l := scanner.Text()
		if l == serveOK {
			return nil
		}
		if l == serveERR {
			return fmt.Errorf("daemon reported error (see preceding output)")
		}
		fmt.Println(l)
	}
	if err := scanner.Err(); err != nil && err != io.EOF {
		return fmt.Errorf("read response: %w", err)
	}
	return nil
}
