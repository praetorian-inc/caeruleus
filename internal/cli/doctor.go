package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"caeruleus/internal/bdaddr"
	"caeruleus/internal/bluez"
)

func newDoctorCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "doctor",
		Short: "One-shot adapter / bluetoothd health summary with suggested fixes",
		Long: `doctor walks the BlueZ + kernel state we care about and prints a
checklist with OK/WARN/FAIL plus a suggested fix per finding. Useful as
the first command when something goes wrong, or as a pre-flight before
disruptive operations.

Checks (per adapter):
  - bluetoothd active?
  - Adapter1.Powered
  - Adapter1.Discovering (anything wedged from earlier?)
  - BlueZ-cached Address vs MGMT chip-live Address (mismatch = stale cache)
  - LE scan healthy (brief 2s discovery probe)
  - ExchangeMTU configured (in safe band for typical peripherals?)`,
		RunE: runDoctor,
	}
}

type doctorFinding struct {
	Check  string `json:"check"`
	Status string `json:"status"` // OK | WARN | FAIL | SKIP
	Value  string `json:"value"`
	Fix    string `json:"fix,omitempty"`
}

func runDoctor(cmd *cobra.Command, args []string) error {
	findings := make([]doctorFinding, 0, 10)
	add := func(f doctorFinding) { findings = append(findings, f) }

	// bluetoothd alive?
	if err := exec.Command("systemctl", "is-active", "--quiet", "bluetooth").Run(); err != nil {
		add(doctorFinding{Check: "bluetoothd", Status: "FAIL", Value: "inactive", Fix: "sudo systemctl start bluetooth"})
	} else {
		add(doctorFinding{Check: "bluetoothd", Status: "OK", Value: "active"})
	}

	// BlueZ-level adapter checks.
	conn, err := bluez.Dial(root.adapter)
	if err != nil {
		add(doctorFinding{Check: root.adapter, Status: "FAIL", Value: err.Error(), Fix: "check `hciconfig` and `systemctl status bluetooth`"})
		writeDoctor(os.Stdout, findings)
		return nil
	}
	defer conn.Close()

	powered, _ := conn.Powered()
	if powered {
		add(doctorFinding{Check: "Powered", Status: "OK", Value: "true"})
	} else {
		add(doctorFinding{Check: "Powered", Status: "FAIL", Value: "false", Fix: "caeruleus adapter power on"})
	}

	if discV, err := conn.AdpObj.GetProperty(bluez.IfaceAdapter + ".Discovering"); err == nil {
		disc, _ := discV.Value().(bool)
		if disc {
			add(doctorFinding{Check: "Discovering", Status: "WARN", Value: "true (a prior discovery may be leaked)", Fix: "caeruleus adapter power cycle"})
		} else {
			add(doctorFinding{Check: "Discovering", Status: "OK", Value: "false"})
		}
	}

	// Address-source agreement (F6).
	bluezAddr := ""
	if addrV, err := conn.AdpObj.GetProperty(bluez.IfaceAdapter + ".Address"); err == nil {
		bluezAddr, _ = addrV.Value().(string)
	}
	mgmtAddr := ""
	if idx, err := adapterIndex(root.adapter); err == nil {
		if mgr, err := bdaddr.OpenManager(idx); err == nil {
			defer mgr.Close()
			if info, err := mgr.ReadControllerInfo(); err == nil {
				mgmtAddr = info.Address
			}
		}
	}
	switch {
	case mgmtAddr == "":
		add(doctorFinding{Check: "Address agreement", Status: "SKIP", Value: "MGMT read unavailable (need root)"})
	case strings.EqualFold(bluezAddr, mgmtAddr):
		add(doctorFinding{Check: "Address agreement", Status: "OK", Value: bluezAddr})
	default:
		add(doctorFinding{
			Check:  "Address agreement",
			Status: "WARN",
			Value:  fmt.Sprintf("BlueZ=%s MGMT=%s", bluezAddr, mgmtAddr),
			Fix:    "caeruleus bdaddr --refresh-bluez (note: may revert volatile spoof)",
		})
	}

	// LE scan health probe (F5).
	if powered {
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		defer cancel()
		if err := verifyLEHealthy(ctx, 2500*time.Millisecond); err != nil {
			add(doctorFinding{
				Check:  "LE scan healthy",
				Status: "WARN",
				Value:  err.Error(),
				Fix:    "caeruleus adapter power cycle",
			})
		} else {
			add(doctorFinding{Check: "LE scan healthy", Status: "OK", Value: "saw advertisements"})
		}
	}

	// ExchangeMTU configured (F1).
	confMTU, err := readMainConfMTU(filepath.Join("/etc/bluetooth", "main.conf"))
	switch {
	case err != nil:
		add(doctorFinding{Check: "ExchangeMTU", Status: "SKIP", Value: err.Error()})
	case confMTU < mtuSafeMin || confMTU > mtuSafeMax:
		add(doctorFinding{
			Check:  "ExchangeMTU",
			Status: "WARN",
			Value:  fmt.Sprintf("%d (outside safe band %d..%d)", confMTU, mtuSafeMin, mtuSafeMax),
			Fix:    fmt.Sprintf("caeruleus mtu --set %d", mtuDefault),
		})
	default:
		add(doctorFinding{Check: "ExchangeMTU", Status: "OK", Value: fmt.Sprintf("%d", confMTU)})
	}

	if formatIsJSON() {
		_ = emitJSON(struct {
			Adapter  string          `json:"adapter"`
			Findings []doctorFinding `json:"findings"`
		}{root.adapter, findings})
	} else {
		writeDoctor(os.Stdout, findings)
	}
	// Surface a non-zero exit code when any check failed. Returning an
	// ExitError instead of calling os.Exit directly keeps the exit-point
	// in main.go and lets cobra finish its own cleanup first. Code 2
	// distinguishes "checks failed" from cobra's default 1 ("command
	// itself errored") - convention shared with grep / diff.
	for _, f := range findings {
		if f.Status == "FAIL" {
			return &ExitError{Code: 2}
		}
	}
	return nil
}

func writeDoctor(w io.Writer, findings []doctorFinding) {
	fmt.Fprintf(w, "adapter: %s\n", root.adapter)
	for _, f := range findings {
		mark := f.Status
		switch f.Status {
		case "OK":
			mark = "  OK"
		case "WARN":
			mark = "WARN"
		case "FAIL":
			mark = "FAIL"
		case "SKIP":
			mark = "SKIP"
		}
		fmt.Fprintf(w, "  [%s] %-22s %s\n", mark, f.Check, f.Value)
		if f.Fix != "" {
			fmt.Fprintf(w, "           Fix: %s\n", f.Fix)
		}
	}
}
