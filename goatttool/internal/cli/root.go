// Package cli wires the cobra command tree.
package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

// rootFlags hold options shared by every subcommand.
type rootFlags struct {
	adapter  string
	bdaddr   string
	addrType string
	timeout  int    // seconds
	format   string // "text" (default) | "json" (indented) | "jsonl" (one obj/line)
	jsonShim bool   // set when the deprecated --json shim flag is used
	verbose  bool
	quiet    bool
}

var root rootFlags

func newRoot() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "goatttool",
		Short: "BLE GATT toolkit (gatttool/gratttool-style, written in Go)",
		Long: `goatttool is a small command-line client for BLE GATT servers.

It talks to bluetoothd over D-Bus (BlueZ Adapter1/Device1/GattCharacteristic1)
and provides subcommands for scanning, enumerating, reading, writing, and
subscribing to notifications. Privileged subcommands (monitor, bdaddr,
mtu --set/--reset) require root.

Shell completion: source the cobra-generated script for your shell, e.g.
  source <(goatttool completion bash)    # or: zsh, fish, powershell
Install permanently via the manifest your distro uses for completions.`,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	pf := cmd.PersistentFlags()
	pf.StringVarP(&root.adapter, "adapter", "i", "hci0", "HCI adapter name (e.g. hci0)")
	pf.StringVarP(&root.bdaddr, "bdaddr", "b", "", "remote BD_ADDR (XX:XX:XX:XX:XX:XX)")
	// --addr-type lost its -t short form to --timeout (org-wide convention).
	pf.StringVar(&root.addrType, "addr-type", "", "address type: public | random (auto if blank)")
	pf.IntVarP(&root.timeout, "timeout", "t", 25, "operation timeout, seconds")
	pf.StringVarP(&root.format, "format", "o", "text", "output format: text | json | jsonl")
	// --json is kept as a deprecated alias for --format jsonl. Hidden so
	// the help output points users at the canonical -o/--format flag.
	pf.BoolVar(&root.jsonShim, "json", false, "deprecated alias for --format jsonl")
	_ = pf.MarkHidden("json")
	pf.BoolVarP(&root.verbose, "verbose", "v", false, "verbose diagnostic logging on stderr")
	pf.BoolVarP(&root.quiet, "quiet", "q", false, "suppress informational status lines on stderr (data + errors still emitted)")

	// Validate / canonicalize --format before any subcommand runs. Also
	// translate the --json shim into format=jsonl so downstream code only
	// has to switch on root.format.
	cmd.PersistentPreRunE = func(cmd *cobra.Command, args []string) error {
		if root.jsonShim {
			root.format = "jsonl"
		}
		switch root.format {
		case "text", "json", "jsonl":
			return nil
		default:
			return fmt.Errorf("invalid --format %q: must be text, json, or jsonl", root.format)
		}
	}

	cmd.AddCommand(
		newScanCmd(),
		newEnumerateCmd(),
		newReadCmd(),
		newWriteCmd(),
		newListenCmd(),
		newShellCmd(),
		newPrimaryCmd(),
		newCharacteristicsCmd(),
		newMonitorCmd(),
		newMTUCmd(),
		newBdaddrCmd(),
		newDisconnectCmd(),
		newForgetCmd(),
		newBatchCmd(),
		newServeCmd(),
		newSendCmd(),
		newCCCDCmd(),
		newAdapterCmd(),
		newDoctorCmd(),
		newFuzzCmd(),
		newRawWriteCmd(),
	)
	return cmd
}

// Execute runs the root command and returns any error.
func Execute() error {
	return newRoot().Execute()
}
