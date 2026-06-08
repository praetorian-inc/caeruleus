package cli

import "github.com/spf13/cobra"

// newFuzzCmd assembles `caeruleus fuzz` — the parent for all fuzzing
// subcommands. The work lives in the subcommands; this just hangs them
// off a common prefix so help text groups them together.
func newFuzzCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "fuzz",
		Short: "Fuzz a GATT server (mutates writes, classifies responses)",
		Long: `Fuzzing subsystem. Drives a target characteristic with mutated values,
classifies the responses (AFLNet-style response-tuple hashing), and saves
inputs that produced new states or crash signals to an on-disk corpus.

Subcommands:

  fuzz write    drive writes against a single characteristic
  fuzz replay   re-send saved inputs from a previous run

See docs/fuzzing-plan.md for the design.`,
	}
	c.AddCommand(newFuzzWriteCmd())
	c.AddCommand(newFuzzReplayCmd())
	return c
}
