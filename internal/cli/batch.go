package cli

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"goatttool/internal/bluez"
)

func newBatchCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "batch",
		Short: "Run shell commands from stdin against a single persistent connection",
		Long: `batch reads shell-mode commands from stdin (one per line) and executes them
against a single GATT connection. Unlike shell, there is no readline UI, no
async notification pump, and no prompt — output goes straight to stdout so
it's safe to pipe and grep.

Commands are the same as the interactive shell (run "shell" then "help" to
see the list). Blank lines and lines starting with "#" are ignored.

Notifications: the inline 'listen' shell-mode command works in batch but is
strictly sequential — it subscribes only when its line is reached, so any
notification fired by an earlier 'write' may already be gone. For atomic
trigger-then-listen, use the standalone subcommand instead:

  goatttool listen -a 0xNNNN --trigger-value 01

It performs StartNotify *before* the trigger write inside a single call.

Example:

  ./goatttool batch -b $ADDR <<'EOF'
  read 0x0015
  write 0x002b -s "BLE{FOO}" --req
  read 0x0029
  EOF`,
		RunE: runBatch,
	}
	return c
}

func runBatch(cmd *cobra.Command, args []string) error {
	// If -b was supplied at root level, open the session up front so the
	// first command doesn't pay the connect cost mid-line.
	addr := root.bdaddr
	if addr != "" && !validMAC(addr) {
		return fmt.Errorf("invalid BD_ADDR %q", addr)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

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
		in:       os.Stdin,
		err:      os.Stderr,
		notify:   map[uint16]chan struct{}{},
	}

	// Auto-connect if a bdaddr was supplied — saves the user from typing
	// `connect` as the first line of every batch.
	if addr != "" {
		sh.cmdConnect(ctx, nil)
	}

	scanner := bufio.NewScanner(os.Stdin)
	// 16k tokens per line; long flag values fit easily.
	scanner.Buffer(make([]byte, 0, 4096), 65536)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if quit := sh.run(ctx, line); quit {
			break
		}
	}
	if err := scanner.Err(); err != nil && err != io.EOF {
		return fmt.Errorf("read stdin: %w", err)
	}
	return nil
}
