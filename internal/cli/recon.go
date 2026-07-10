package cli

import (
	"encoding/binary"
	"fmt"
	"sort"
	"strings"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/spf13/cobra"

	"github.com/praetorian-inc/caeruleus/internal/bluez"
)

// deviceProfile is the passive identity recovered from advertising + GATT.
type deviceProfile struct {
	Name           string        `json:"name,omitempty"`
	DeviceType     string        `json:"device_type,omitempty"`
	Manufacturer   string        `json:"manufacturer,omitempty"`
	Model          string        `json:"model,omitempty"`
	Serial         string        `json:"serial,omitempty"`
	FirmwareRev    string        `json:"firmware_rev,omitempty"`
	HardwareRev    string        `json:"hardware_rev,omitempty"`
	SoftwareRev    string        `json:"software_rev,omitempty"`
	PreferredConn  string        `json:"preferred_conn_params,omitempty"`
	Services       []serviceInfo `json:"services"`
	CustomServices int           `json:"custom_service_count"`
	DFUPresent     bool          `json:"dfu_present"`
}

type serviceInfo struct {
	Handle    uint16 `json:"handle"`
	UUID      string `json:"uuid"`
	Custom    bool   `json:"custom"`
	CharCount int    `json:"char_count"`
}

type reconResult struct {
	Address  string        `json:"address"`
	Profile  deviceProfile `json:"profile"`
	Findings []Finding     `json:"findings"`
}

func newReconCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "recon",
		Short: "Profile -b BDADDR: fingerprint (DIS), service map, and GATT audit",
		Long: `Connects, enumerates the GATT tree, and builds a passive device profile:
Device Information (manufacturer / model / serial / revisions), preferred
connection parameters, and a service map split into adopted vs custom/vendor
services. It also audits structure for attack surface:

  - DFU service present (firmware-update attack surface)
  - serial number exposed (aids chipset / CVE correlation)
  - permission mismatch: characteristics readable despite not advertising the
    read property (hidden attributes)

This is reconnaissance, not an attack: it only reads. Use -o json to feed
the fingerprint / report layer.`,
		RunE: runRecon,
	}
}

// adopted 16-bit UUIDs we surface in the profile.
const (
	uuidGAPName      = 0x2A00
	uuidPPCP         = 0x2A04
	uuidManufacturer = 0x2A29
	uuidModel        = 0x2A24
	uuidSerial       = 0x2A25
	uuidFirmwareRev  = 0x2A26
	uuidHardwareRev  = 0x2A27
	uuidSoftwareRev  = 0x2A28
)

func runRecon(cmd *cobra.Command, args []string) error {
	addr, err := requireBdaddr()
	if err != nil {
		return err
	}
	ctx, cancel := ctxWithRootTimeout()
	defer cancel()

	s, err := openSession(ctx, addr, true)
	if err != nil {
		return err
	}
	defer s.close()

	res := reconResult{Address: addr}
	p := &res.Profile

	// --- Device Information / GAP fingerprint ---
	var appearance uint16
	if raw, err := s.readSIG16Raw(0x2A01); err == nil && len(raw) >= 2 {
		appearance = uint16(raw[0]) | uint16(raw[1])<<8
	}

	p.Name, _ = s.readSIG16(uuidGAPName)
	p.Manufacturer, _ = s.readSIG16(uuidManufacturer)
	p.Model, _ = s.readSIG16(uuidModel)
	p.Serial, _ = s.readSIG16(uuidSerial)
	p.FirmwareRev, _ = s.readSIG16(uuidFirmwareRev)
	p.HardwareRev, _ = s.readSIG16(uuidHardwareRev)
	p.SoftwareRev, _ = s.readSIG16(uuidSoftwareRev)
	p.PreferredConn = s.readPPCP()

	// --- Service map (adopted vs custom) ---
	charsBySvc := map[string]int{}
	svcByPath := map[string]bluez.GattObject{}
	for _, sv := range s.tree.Services {
		svcByPath[string(sv.Path)] = sv
	}
	for _, ch := range s.tree.Characteristics {
		charsBySvc[string(ch.Parent)]++
	}
	svcs := append([]bluez.GattObject(nil), s.tree.Services...)
	sort.Slice(svcs, func(i, j int) bool { return svcs[i].Handle < svcs[j].Handle })
	for _, sv := range svcs {
		custom := !isSIGBaseUUID(sv.UUID)
		if custom {
			p.CustomServices++
		}
		if strings.Contains(strings.ToLower(sv.UUID), "fe59") {
			p.DFUPresent = true
		}
		p.Services = append(p.Services, serviceInfo{
			Handle:    sv.Handle,
			UUID:      sv.UUID,
			Custom:    custom,
			CharCount: charsBySvc[string(sv.Path)],
		})
	}

	// --- Device type from Appearance + service UUIDs ---
	var svcUUIDs []string
	for _, sv := range svcs {
		svcUUIDs = append(svcUUIDs, sv.UUID)
	}
	p.DeviceType = inferDeviceType(appearance, svcUUIDs)

	// --- Audit findings ---
	if p.DFUPresent {
		res.Findings = append(res.Findings, Finding{
			Title:    "DFU service present",
			Severity: SevMedium,
			Detail:   "A device firmware update service (0xFE59) is exposed - firmware-update attack surface. Run 'caeruleus assess dfu' to test whether entry is authenticated.",
		})
	}
	if p.Serial != "" {
		res.Findings = append(res.Findings, Finding{
			Title:    "Serial number exposed",
			Severity: SevLow,
			UUID:     fmt.Sprintf("0000%04x-0000-1000-8000-00805f9b34fb", uuidSerial),
			Evidence: p.Serial,
			Detail:   "Serial / device identifiers aid chipset fingerprinting and CVE correlation.",
		})
	}
	if p.CustomServices > 0 {
		res.Findings = append(res.Findings, Finding{
			Title:    fmt.Sprintf("%d custom/vendor service(s)", p.CustomServices),
			Severity: SevInfo,
			Detail:   "Custom services are outside the SIG spec and are the most likely place for proprietary, under-tested logic.",
		})
	}

	// permission mismatch: try reading characteristics that do NOT advertise read.
	for _, ch := range s.tree.Characteristics {
		if propsCan(ch.Flags, "read") {
			continue
		}
		c := s.conn.Characteristic(ch.Path)
		if v, e := c.ReadValue(0); e == nil {
			res.Findings = append(res.Findings, Finding{
				Title:    "Hidden readable characteristic (no read property advertised)",
				Severity: SevMedium,
				Handle:   ch.Handle,
				UUID:     ch.UUID,
				Evidence: fmt.Sprintf("%x (%q)", v[:min(len(v), 32)], truncate(asciiize(v), 32)),
				Detail:   "Characteristic returned data despite not advertising the read property.",
			})
		}
	}

	if formatIsJSON() {
		return emitJSON(res)
	}
	printReconText(res)
	return nil
}

// readPPCP reads the Peripheral Preferred Connection Parameters (0x2A04) and
// formats them in human terms (interval 1.25ms/unit, timeout 10ms/unit).
func (s *session) readPPCP() string {
	full := fmt.Sprintf("0000%04x-0000-1000-8000-00805f9b34fb", uuidPPCP)
	chs := s.tree.ByUUID[full]
	if len(chs) == 0 {
		return ""
	}
	v, err := s.conn.Characteristic(chs[0].Path).ReadValue(0)
	if err != nil || len(v) < 8 {
		return ""
	}
	minI := float64(binary.LittleEndian.Uint16(v[0:2])) * 1.25
	maxI := float64(binary.LittleEndian.Uint16(v[2:4])) * 1.25
	lat := binary.LittleEndian.Uint16(v[4:6])
	to := int(binary.LittleEndian.Uint16(v[6:8])) * 10
	return fmt.Sprintf("interval %.2f-%.2fms latency %d timeout %dms", minI, maxI, lat, to)
}

func printReconText(res reconResult) {
	p := res.Profile
	fmt.Printf("# recon - %s\n", res.Address)
	line := func(k, v string) {
		if v != "" {
			fmt.Printf("  %-14s %s\n", k+":", v)
		}
	}
	line("name", p.Name)
	line("device-type", p.DeviceType)
	line("manufacturer", p.Manufacturer)
	line("model", p.Model)
	line("serial", p.Serial)
	line("firmware", p.FirmwareRev)
	line("hardware", p.HardwareRev)
	line("software", p.SoftwareRev)
	line("pref-conn", p.PreferredConn)
	fmt.Printf("  services:      %d (%d custom) dfu=%v\n", len(p.Services), p.CustomServices, p.DFUPresent)

	t := newTable()
	t.AppendHeader(table.Row{"SVC HND", "UUID", "KIND", "CHARS"})
	for _, sv := range p.Services {
		kind := "adopted"
		if sv.Custom {
			kind = "custom"
		}
		t.AppendRow(table.Row{fmt.Sprintf("0x%04x", sv.Handle), sv.UUID, kind, sv.CharCount})
	}
	t.Render()

	if len(res.Findings) > 0 {
		fmt.Println()
		out := assessResult{Address: res.Address, Test: "recon-audit", Findings: res.Findings}
		_ = emitAssess(out)
	}
}
