// shell-harness drives caeruleus's interactive `shell` subcommand through a
// pty so we can validate the readline-based interactive UI in CI / automation.
//
// The interactive shell uses chzyer/readline which refuses to function
// when stdin isn't a TTY, so piping stdin (as `batch` does) bypasses the
// most interesting parts of the shell — the prompt rendering, the
// notification pump that prints above the prompt, history file handling,
// and the keystroke-level dispatch. This harness allocates a pty so the
// shell sees a "real" terminal and we can drive it programmatically.
//
// Usage:
//
//	go run ./cmd/shell-harness                # smoke tests only
//	go run ./cmd/shell-harness --addr XX:..   # smoke + device tests
//	go run ./cmd/shell-harness --bin /path/to/caeruleus
//
// Exit code: 0 if every test passed, 1 otherwise.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/creack/pty"
)

var (
	flagBinary  = flag.String("bin", "./caeruleus", "path to the caeruleus binary under test")
	flagAddr    = flag.String("addr", "", "BD_ADDR to use for the device-touching tests; smoke tests run regardless")
	flagTimeout = flag.Duration("timeout", 12*time.Second, "per-step regex-match timeout")
	flagKeep    = flag.Bool("keep-running", false, "print one PASS/FAIL line per check rather than abort on first FAIL")
)

// shellSession wraps a caeruleus shell child running on a pty.
type shellSession struct {
	cmd *exec.Cmd
	pty *os.File
	mu  sync.Mutex
	buf bytes.Buffer
}

// startShell forks caeruleus shell on a pty. The child's stdout+stderr are
// captured into buf for waitFor to scan; writes to pty arrive at the
// child's stdin.
func startShell(args ...string) (*shellSession, error) {
	cmd := exec.Command(*flagBinary, append([]string{"shell"}, args...)...)
	f, err := pty.Start(cmd)
	if err != nil {
		return nil, fmt.Errorf("pty.Start: %w", err)
	}
	s := &shellSession{cmd: cmd, pty: f}
	go func() {
		// io.Copy logs both the prompt+banner output and async events;
		// waitFor scans the cumulative buffer.
		buf := make([]byte, 1024)
		for {
			n, err := f.Read(buf)
			if n > 0 {
				s.mu.Lock()
				s.buf.Write(buf[:n])
				s.mu.Unlock()
			}
			if err != nil {
				return
			}
		}
	}()
	return s, nil
}

// waitFor blocks until pattern matches the cumulative receive buffer or
// the timeout elapses. Returns the matched substring on success and the
// full buffer-so-far on timeout (for diagnostic logging).
func (s *shellSession) waitFor(pattern *regexp.Regexp, timeout time.Duration) (string, error) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		s.mu.Lock()
		got := s.buf.String()
		s.mu.Unlock()
		if m := pattern.FindString(got); m != "" {
			return m, nil
		}
		time.Sleep(40 * time.Millisecond)
	}
	s.mu.Lock()
	got := s.buf.String()
	s.mu.Unlock()
	return "", fmt.Errorf("timeout waiting for %s\n--- buffer ---\n%s\n--- end ---",
		pattern, stripANSI(got))
}

// send writes a command line (no newline included).
func (s *shellSession) send(line string) error {
	_, err := io.WriteString(s.pty, line+"\n")
	return err
}

// reset zeroes the receive buffer so the next waitFor sees only new bytes.
// Use between distinct prompt-driven steps.
func (s *shellSession) reset() {
	s.mu.Lock()
	s.buf.Reset()
	s.mu.Unlock()
}

// close attempts a graceful shutdown — sends "quit" and waits up to 3s
// for the child's deferred cleanup to run (including session.close which
// waits for BlueZ Connected=false). Falls back to Kill on timeout so the
// harness never hangs on a wedged child.
//
// Graceful close matters: SIGKILL skips the caeruleus process's deferred
// cleanup, leaving BLE link state in flight at process exit. The next
// test then starts on a half-disconnected peripheral and operations like
// StartNotify fail with "Not Connected" even though Adapter1.Connected
// still reports true (bluetoothd's state lags the actual link).
func (s *shellSession) close() {
	if s.cmd.Process == nil {
		_ = s.pty.Close()
		return
	}
	_, _ = io.WriteString(s.pty, "quit\n")
	done := make(chan error, 1)
	go func() { done <- s.cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		_ = s.cmd.Process.Kill()
		<-done
	}
	_ = s.pty.Close()
}

var ansiRe = regexp.MustCompile(`\x1b\[[0-9;]*[A-Za-z]`)

func stripANSI(s string) string { return ansiRe.ReplaceAllString(s, "") }

// --- test framework -------------------------------------------------------

type tcase struct {
	name string
	args []string // extra args to `caeruleus shell`
	run  func(*shellSession) error
}

func (tc tcase) execute() (ok bool, msg string) {
	s, err := startShell(tc.args...)
	if err != nil {
		return false, fmt.Sprintf("startShell: %v", err)
	}
	defer s.close()
	if err := tc.run(s); err != nil {
		return false, err.Error()
	}
	return true, ""
}

// matchers ----------------------------------------------------------------

// promptRe matches the `]> ` suffix of the shell prompt. We don't anchor
// at end-of-string because readline emits trailing terminal control bytes
// (cursor reposition, attribute reset) after the visible prompt — those
// are fine to ignore. The literal `]> ` is unique to the prompt and won't
// false-match in any command output we care about.
var promptRe = regexp.MustCompile(`\]> `)

// waitForPrompt waits until the next prompt is on screen.
func waitForPrompt(s *shellSession) error {
	_, err := s.waitFor(promptRe, *flagTimeout)
	return err
}

// expect waits until pattern matches; returns the matched substring.
func expect(s *shellSession, pattern string) (string, error) {
	return s.waitFor(regexp.MustCompile(pattern), *flagTimeout)
}

// step runs a "send + expect" pair with a reset so the receive buffer
// doesn't carry over.
func step(s *shellSession, line, expectPat string) error {
	s.reset()
	if err := s.send(line); err != nil {
		return fmt.Errorf("send %q: %w", line, err)
	}
	if _, err := s.waitFor(regexp.MustCompile(expectPat), *flagTimeout); err != nil {
		return fmt.Errorf("after %q: %w", line, err)
	}
	return nil
}

// --- tests ---------------------------------------------------------------

func smokeTests() []tcase {
	return []tcase{
		{
			name: "banner appears",
			run: func(s *shellSession) error {
				_, err := expect(s, `caeruleus shell`)
				return err
			},
		},
		{
			name: "initial prompt appears",
			run: func(s *shellSession) error {
				return waitForPrompt(s)
			},
		},
		{
			name: "help lists commands",
			run: func(s *shellSession) error {
				if err := waitForPrompt(s); err != nil {
					return err
				}
				return step(s, "help", `commands:`)
			},
		},
		{
			name: "unknown command reports error",
			run: func(s *shellSession) error {
				if err := waitForPrompt(s); err != nil {
					return err
				}
				return step(s, "frobnicate", `unknown command`)
			},
		},
		{
			name: "primary without connection prints no-device hint",
			run: func(s *shellSession) error {
				if err := waitForPrompt(s); err != nil {
					return err
				}
				return step(s, "primary", `no device`)
			},
		},
		{
			name: "quit exits the shell cleanly",
			run: func(s *shellSession) error {
				if err := waitForPrompt(s); err != nil {
					return err
				}
				if err := s.send("quit"); err != nil {
					return err
				}
				done := make(chan error, 1)
				go func() { done <- s.cmd.Wait() }()
				select {
				case err := <-done:
					if err != nil && !isSignalExit(err) {
						return fmt.Errorf("exited with: %w", err)
					}
					return nil
				case <-time.After(*flagTimeout):
					return fmt.Errorf("did not exit after `quit`")
				}
			},
		},
	}
}

func deviceTests(addr string) []tcase {
	return []tcase{
		{
			name: "connect from inside shell",
			args: []string{"-b", addr},
			run: func(s *shellSession) error {
				if err := waitForPrompt(s); err != nil {
					return err
				}
				return step(s, "connect", `connected in \d+`)
			},
		},
		{
			name: "read returns the one-line format",
			args: []string{"-b", addr},
			run: func(s *shellSession) error {
				if err := waitForPrompt(s); err != nil {
					return err
				}
				if err := step(s, "connect", `connected in \d+`); err != nil {
					return err
				}
				if err := waitForPrompt(s); err != nil {
					return err
				}
				return step(s, "read 0x0029", `0x0029 hex=[0-9a-f]+ ascii="`)
			},
		},
		{
			name: "primary lists services after connect",
			args: []string{"-b", addr},
			run: func(s *shellSession) error {
				if err := waitForPrompt(s); err != nil {
					return err
				}
				if err := step(s, "connect", `connected in \d+`); err != nil {
					return err
				}
				if err := waitForPrompt(s); err != nil {
					return err
				}
				return step(s, "primary", `attr handle:\s*0x`)
			},
		},
		{
			name: "characteristics lists handles after connect",
			args: []string{"-b", addr},
			run: func(s *shellSession) error {
				if err := waitForPrompt(s); err != nil {
					return err
				}
				if err := step(s, "connect", `connected in \d+`); err != nil {
					return err
				}
				if err := waitForPrompt(s); err != nil {
					return err
				}
				return step(s, "characteristics", `char value handle:\s*0x`)
			},
		},
		{
			name: "disconnect after connect",
			args: []string{"-b", addr},
			run: func(s *shellSession) error {
				if err := waitForPrompt(s); err != nil {
					return err
				}
				if err := step(s, "connect", `connected in \d+`); err != nil {
					return err
				}
				if err := waitForPrompt(s); err != nil {
					return err
				}
				// disconnect prints nothing on success; just wait for prompt
				s.reset()
				if err := s.send("disconnect"); err != nil {
					return err
				}
				return waitForPrompt(s)
			},
		},
		{
			// Without the SIGTERM/SIGHUP handler installed in shell.go,
			// `kill -TERM` is the OS default — it terminates the process
			// directly, skipping the deferred BLE cleanup. With the
			// handler, rl.Close() makes Readline return io.EOF, the main
			// loop returns nil, defers run (session.close waits up to 2s
			// for Connected=false), and we exit status 0.
			//
			// This test discriminates by checking how the process exited:
			// clean status 0 = handler worked; "signaled" = handler missing.
			name: "SIGTERM converts to graceful shutdown",
			args: []string{"-b", addr},
			run: func(s *shellSession) error {
				if err := waitForPrompt(s); err != nil {
					return err
				}
				if err := step(s, "connect", `connected in \d+`); err != nil {
					return err
				}
				if err := waitForPrompt(s); err != nil {
					return err
				}
				if err := s.cmd.Process.Signal(syscall.SIGTERM); err != nil {
					return fmt.Errorf("kill -TERM: %w", err)
				}
				done := make(chan error, 1)
				go func() { done <- s.cmd.Wait() }()
				select {
				case err := <-done:
					if err == nil {
						return nil
					}
					if exitErr, ok := err.(*exec.ExitError); ok {
						if ws, ok := exitErr.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
							return fmt.Errorf(
								"process terminated by signal %v rather than exiting cleanly — signal handler did not run",
								ws.Signal())
						}
					}
					return fmt.Errorf("unexpected exit error: %w", err)
				case <-time.After(5 * time.Second):
					return fmt.Errorf("did not exit within 5s after SIGTERM")
				}
			},
		},
		{
			// The notification pump is the most subtle piece of the shell:
			// async PropertiesChanged events arrive while the user is
			// composing the next command, so the pump has to redraw the
			// prompt without garbling the in-progress input. We can't easily
			// test the redraw fidelity, but we *can* verify that an event
			// triggered after notify-on actually surfaces in the terminal.
			//
			// Uses 0x0043 (the BLECTF multi-notify char) — writing to it
			// triggers the firmware to start emitting. The "[notify ...]"
			// marker is unique to the pump's print path.
			name: "notify-on surfaces async events",
			args: []string{"-b", addr},
			run: func(s *shellSession) error {
				if err := waitForPrompt(s); err != nil {
					return err
				}
				if err := step(s, "connect", `connected in \d+`); err != nil {
					return err
				}
				if err := waitForPrompt(s); err != nil {
					return err
				}
				if err := step(s, "notify-on 0x0043", `notifications enabled`); err != nil {
					return err
				}
				if err := waitForPrompt(s); err != nil {
					return err
				}
				// Trigger the firmware to start emitting.
				s.reset()
				if err := s.send("char-write-cmd 0x0043 01"); err != nil {
					return err
				}
				// Wait for the pump's async print marker. 8s window is
				// generous — multi-notify usually fires within ~100ms.
				if _, err := s.waitFor(regexp.MustCompile(`\[notify 0x0043\]`), 8*time.Second); err != nil {
					return err
				}
				// Clean up the subscription so we don't leave the BLECTF
				// firing notifications at us when we close the pty.
				s.reset()
				if err := s.send("notify-off 0x0043"); err != nil {
					return err
				}
				return waitForPrompt(s)
			},
		},
	}
}

// historyTests verify side-effect outputs of the shell — history file
// writes, etc. They don't need a peripheral.
func historyTests() []tcase {
	return []tcase{
		{
			name: "history file is created at HOME/.caeruleus_history",
			run: func(s *shellSession) error {
				if err := waitForPrompt(s); err != nil {
					return err
				}
				if err := step(s, "help", `commands:`); err != nil {
					return err
				}
				if err := waitForPrompt(s); err != nil {
					return err
				}
				if err := s.send("quit"); err != nil {
					return err
				}
				done := make(chan error, 1)
				go func() { done <- s.cmd.Wait() }()
				select {
				case <-done:
				case <-time.After(*flagTimeout):
					return fmt.Errorf("did not exit after `quit`")
				}
				// chzyer/readline writes the history file on Close. The
				// path is HOME/.caeruleus_history (see shell.go's
				// historyFile()).
				home, err := os.UserHomeDir()
				if err != nil {
					return err
				}
				path := home + "/.caeruleus_history"
				st, err := os.Stat(path)
				if err != nil {
					return fmt.Errorf("history file not present at %s: %w", path, err)
				}
				if st.Size() == 0 {
					return fmt.Errorf("history file %s is empty", path)
				}
				return nil
			},
		},
	}
}

// isSignalExit returns true when err is an *exec.ExitError due to a signal
// we sent ourselves (Kill in close()). Cleaner than treating those as test
// failures.
func isSignalExit(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "signal: killed") ||
		strings.Contains(err.Error(), "signal: terminated")
}

// --- main ----------------------------------------------------------------

func main() {
	flag.Parse()

	if _, err := os.Stat(*flagBinary); err != nil {
		fmt.Fprintf(os.Stderr, "harness: binary not found at %s: %v\n", *flagBinary, err)
		os.Exit(2)
	}

	cases := smokeTests()
	cases = append(cases, historyTests()...)
	if *flagAddr != "" {
		cases = append(cases, deviceTests(*flagAddr)...)
	}

	var pass, fail int
	for _, tc := range cases {
		ok, msg := tc.execute()
		if ok {
			fmt.Printf("PASS  %s\n", tc.name)
			pass++
		} else {
			fmt.Printf("FAIL  %s\n        %s\n", tc.name, indentMsg(msg))
			fail++
			if !*flagKeep {
				break
			}
		}
	}

	fmt.Printf("\nresults: %d pass, %d fail (of %d)\n", pass, fail, len(cases))
	if fail > 0 {
		os.Exit(1)
	}
}

func indentMsg(s string) string {
	return strings.ReplaceAll(strings.TrimSuffix(s, "\n"), "\n", "\n        ")
}
