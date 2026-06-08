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
	// Preserve our grouped insertion order in help instead of alphabetising.
	cobra.EnableCommandSorting = false

	const desc = `caeruleus is a command-line client for BLE GATT servers.

It talks to bluetoothd over D-Bus (BlueZ Adapter1/Device1/GattCharacteristic1)
and provides subcommands for scanning, enumerating, reading, writing, and
subscribing to notifications. Privileged subcommands (monitor, bdaddr,
mtu --set/--reset) require root.`

	// Show the wordmark only when the terminal is wide enough for it.
	long := desc
	if showBanner() {
		long = bannerArt + desc
	}

	cmd := &cobra.Command{
		Use:           "caeruleus",
		Short:         "BLE GATT toolkit (gatttool/gratttool-style, written in Go)",
		Long:          long,
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

	// Group commands in help the same way the README does, in a sensible
	// workflow order within each group (discovery -> interaction; recon ->
	// active tests; fuzzing; adapter/diagnostics). `help` and `completion`
	// stay ungrouped under "Additional Commands".
	cmd.AddGroup(
		&cobra.Group{ID: "interact", Title: "Discovery & interaction:"},
		&cobra.Group{ID: "assess", Title: "Security assessment:"},
		&cobra.Group{ID: "fuzz", Title: "Fuzzing:"},
		&cobra.Group{ID: "diag", Title: "Adapter & diagnostics:"},
	)
	add := func(group string, cmds ...*cobra.Command) {
		for _, c := range cmds {
			c.GroupID = group
			cmd.AddCommand(c)
		}
	}
	add("interact",
		newScanCmd(), newEnumerateCmd(), newPrimaryCmd(), newCharacteristicsCmd(),
		newReadCmd(), newWriteCmd(), newListenCmd(), newCCCDCmd(), newMTUCmd(),
		newShellCmd(), newBatchCmd(), newServeCmd(), newSendCmd(),
	)
	add("assess",
		newReconCmd(), newAssessCmd(), newPairCmd(), newUnpairCmd(), newConnParamsCmd(),
	)
	add("fuzz", newFuzzCmd())
	add("diag",
		newDoctorCmd(), newAdapterCmd(), newDisconnectCmd(), newForgetCmd(),
		newBdaddrCmd(), newMonitorCmd(), newRawWriteCmd(),
	)
	return cmd
}

// Execute runs the root command and returns any error.
func Execute() error {
	return newRoot().Execute()
}
