package cli

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

type recipe struct {
	Title   string
	Tags    []string
	Example string
}

var recipes = []recipe{
	{
		Title: "Discover nearby devices",
		Tags:  []string{"scan", "discover", "find"},
		Example: `  caeruleus scan
  caeruleus scan --duration 30          # longer window
  caeruleus scan -o json                # structured output`,
	},
	{
		Title: "Map a device's GATT tree",
		Tags:  []string{"enumerate", "gatt", "services", "characteristics", "map"},
		Example: `  caeruleus enumerate -b $ADDR
  caeruleus enumerate -b $ADDR --values   # also read every characteristic`,
	},
	{
		Title: "Read a characteristic",
		Tags:  []string{"read", "value"},
		Example: `  caeruleus read -b $ADDR -a 0x0029
  caeruleus read -b $ADDR -u 00002a00-0000-1000-8000-00805f9b34fb`,
	},
	{
		Title: "Write to a characteristic",
		Tags:  []string{"write", "send", "command"},
		Example: `  caeruleus write -b $ADDR -a 0x002c -n deadbeef
  caeruleus write -b $ADDR -a 0x002c -s "hello"      # ASCII
  caeruleus write -b $ADDR -a 0x002c -n 01 --req      # write-with-response`,
	},
	{
		Title: "Write to one handle, capture notification on another",
		Tags:  []string{"trigger", "notification", "write", "listen", "response", "request-response", "rcsp"},
		Example: `  # Subscribe on 0x0083, then write to 0x0081, then capture the response:
  caeruleus listen -b $ADDR -a 0x0083 \
    --trigger-handle 0x0081 --trigger-value FEDCBA0003000101EF

  # Capture multiple responses from repeated triggers:
  caeruleus listen -b $ADDR -a 0x0083 \
    --trigger-handle 0x0081 --trigger-value 01 \
    --trigger-count 5 --count 0`,
	},
	{
		Title: "Capture notifications (passive)",
		Tags:  []string{"listen", "notify", "subscribe", "notification", "indication"},
		Example: `  caeruleus listen -b $ADDR -a 0x0025
  caeruleus listen -b $ADDR -a 0x0025 -d 30 --count 10   # up to 10 events or 30s
  caeruleus listen -b $ADDR -a 0x0025 --extract           # hex-only (pipeable)`,
	},
	{
		Title: "Capture notifications on chars that hide NOTIFY property",
		Tags:  []string{"hidden", "cccd", "notify", "monitor", "startnotify"},
		Example: `  # Use the HCI monitor socket to see wire events BlueZ hides:
  sudo caeruleus listen -b $ADDR -a 0x0025 --hidden --monitor on`,
	},
	{
		Title: "Sniff all notifications passively (no connection needed)",
		Tags:  []string{"monitor", "sniff", "passive", "btmon"},
		Example: `  # Raw HCI monitor (like btmon, but decoded ATT only):
  sudo caeruleus monitor -d 30
  sudo caeruleus monitor --handle 0x0025 --count 5`,
	},
	{
		Title: "Interactive exploration (human)",
		Tags:  []string{"shell", "interactive", "explore", "repl"},
		Example: `  caeruleus shell -b $ADDR
  # Then: enumerate, read 0x0029, write 0x002c deadbeef, listen 0x0025, etc.`,
	},
	{
		Title: "Scripted exploration (LLM / automation)",
		Tags:  []string{"serve", "send", "llm", "agent", "automation", "daemon", "persistent"},
		Example: `  # Terminal 1: start daemon with persistent connection
  sudo caeruleus serve -b $ADDR

  # Terminal 2 (or from an LLM agent via Bash):
  caeruleus send "enumerate"
  caeruleus send "read 0x0029"
  caeruleus send "write 0x002c deadbeef"
  caeruleus send "read 0x002c"              # read back after write`,
	},
	{
		Title: "Batch multiple operations over one connection",
		Tags:  []string{"batch", "script", "pipeline"},
		Example: `  caeruleus batch -b $ADDR <<'EOF'
  read 0x0015
  write 0x002b -s "test" --req
  read 0x0029
  EOF`,
	},
	{
		Title: "Pipe multiple payloads to one handle",
		Tags:  []string{"each-line", "pipe", "write", "bulk"},
		Example: `  echo -e "deadbeef\ncafebabe\n01020304" | \
    caeruleus write -b $ADDR -a 0x002c --each-line`,
	},
	{
		Title: "Brute-force a byte range and observe responses",
		Tags:  []string{"brute", "fuzz", "sweep", "byte-range"},
		Example: `  # In shell/batch: write 0x00..0xFF to 0x002c, read 0x0029 each time:
  caeruleus batch -b $ADDR <<'EOF'
  brute 0x002c 0x0029 0 255
  EOF`,
	},
	{
		Title: "Pair / bond to access protected characteristics",
		Tags:  []string{"pair", "bond", "encrypt", "passkey", "pin", "protected"},
		Example: `  caeruleus pair -b $ADDR                      # Just Works
  caeruleus pair -b $ADDR --passkey 123456     # Passkey Entry`,
	},
	{
		Title: "Run a full security recon",
		Tags:  []string{"recon", "assess", "security", "audit", "fingerprint"},
		Example: `  caeruleus recon -b $ADDR
  caeruleus recon -b $ADDR -o json             # structured output`,
	},
	{
		Title: "Check what's readable without pairing",
		Tags:  []string{"checkauth", "unauthenticated", "access-control"},
		Example: `  caeruleus assess checkauth -b $ADDR
  caeruleus assess checkauth -b $ADDR --probe-write  # also probe writes`,
	},
	{
		Title: "Test write-without-response resilience (DoS)",
		Tags:  []string{"wwr", "dos", "overflow", "rapid-fire", "watchdog"},
		Example: `  caeruleus assess wwr -b $ADDR
  caeruleus assess wwr -b $ADDR --burst 200   # heavier rapid-fire burst`,
	},
	{
		Title: "Fuzz a writable characteristic",
		Tags:  []string{"fuzz", "mutate", "crash"},
		Example: `  caeruleus fuzz write -b $ADDR -a 0x002c --seed deadbeef --max-iter 1000`,
	},
	{
		Title: "Troubleshoot adapter issues",
		Tags:  []string{"doctor", "adapter", "health", "reset", "debug"},
		Example: `  caeruleus doctor
  caeruleus adapter info
  sudo caeruleus adapter power off && sudo caeruleus adapter power on`,
	},
}

func newRecipesCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "recipes [search term]",
		Short: "Find the right command by describing what you want to do",
		Long: `recipes shows common BLE workflows indexed by use case, not by command name.
Search by keyword to narrow results:

  caeruleus recipes trigger       # "write then capture notification"
  caeruleus recipes llm           # LLM/automation-friendly patterns
  caeruleus recipes pair          # pairing and bonding
  caeruleus recipes               # show all recipes`,
		RunE: runRecipes,
	}
}

func runRecipes(cmd *cobra.Command, args []string) error {
	query := strings.ToLower(strings.Join(args, " "))

	var matched []recipe
	for _, r := range recipes {
		if query == "" {
			matched = append(matched, r)
			continue
		}
		if strings.Contains(strings.ToLower(r.Title), query) {
			matched = append(matched, r)
			continue
		}
		for _, t := range r.Tags {
			if strings.Contains(t, query) {
				matched = append(matched, r)
				break
			}
		}
	}

	if len(matched) == 0 {
		fmt.Printf("No recipes matching %q. Run 'caeruleus recipes' to see all.\n", query)
		return nil
	}

	for i, r := range matched {
		if i > 0 {
			fmt.Println()
		}
		fmt.Printf("── %s ──\n%s\n", r.Title, r.Example)
	}
	return nil
}
