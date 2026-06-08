package bdaddr

import (
	"strings"
)

// VendorCmd describes a per-vendor "write BD_ADDR" HCI command.
type VendorCmd struct {
	Name        string
	Opcode      uint16             // HCI opcode (OGF<<10 | OCF); OGF=0x3F (vendor) usually
	Description string             // short hint shown by --list-vendors
	Build       func([6]byte) ([]byte, error) // build the parameters from a LE address
}

// Generic helpers reused by several vendors.
func plainLEAddr(addr [6]byte) ([]byte, error) {
	return addr[:], nil
}

// vendorCmds is keyed by lower-case vendor name (also matched against the
// manufacturer code via VendorForManufacturer).
var vendorCmds = map[string]VendorCmd{
	// Broadcom / Cypress: OCF 0x001 in OGF 0x3F → 0xFC01, params = 6-byte LE addr.
	"broadcom": {
		Name:        "broadcom",
		Opcode:      0xFC01,
		Description: "OCF 0x001, params: 6B LE BD_ADDR",
		Build:       plainLEAddr,
	},
	"cypress": {
		Name:        "cypress",
		Opcode:      0xFC01,
		Description: "(Broadcom-derived) OCF 0x001, params: 6B LE BD_ADDR",
		Build:       plainLEAddr,
	},
	"zeevo": {
		Name:        "zeevo",
		Opcode:      0xFC01,
		Description: "OCF 0x001, params: 6B LE BD_ADDR",
		Build:       plainLEAddr,
	},
	"st": {
		Name:        "st",
		Opcode:      0xFC22,
		Description: "OCF 0x022, params: 6B LE BD_ADDR",
		Build:       plainLEAddr,
	},
	"ti": {
		Name:        "ti",
		Opcode:      0xFC06,
		Description: "OCF 0x006, params: 6B LE BD_ADDR",
		Build:       plainLEAddr,
	},
	"ericsson": {
		Name:        "ericsson",
		Opcode:      0xFC0D,
		Description: "OCF 0x00D, params: 6B LE BD_ADDR",
		Build:       plainLEAddr,
	},
	// Intel: most modern Intel BLE chips (AX2xx) don't accept HCI BD_ADDR
	// writes, but some development variants accept OCF 0x031 "Write_BD_Data".
	"intel": {
		Name:        "intel",
		Opcode:      0xFC31,
		Description: "OCF 0x031 (Write_BD_Data), 6B LE BD_ADDR (often refused by AX chips)",
		Build:       plainLEAddr,
	},
	// CSR is much more complex (PSKey writes via vendor-specific PDUs).
	// We provide a simplified single-shot write that's known to work on some
	// older USB dongles; real CSR work needs a PSKey transaction.
	"csr": {
		Name:        "csr",
		Opcode:      0xFC00,
		Description: "OCF 0x000 (PSKey-style packet; works on older BC04/BC06 dongles)",
		Build: func(addr [6]byte) ([]byte, error) {
			// 16-byte payload: 0x02 0x00 0x0c 0x00 0x11 0x47 0x03 0x70 0x00
			// 0x01 0x00 0x04 0x00 plus LSB-MSB swap of the address pair-wise.
			// Layout cribbed from the canonical "bdaddr.c" CSR section.
			p := []byte{
				0x02, 0x00, 0x0c, 0x00, 0x11, 0x47, 0x03, 0x70,
				0x00, 0x01, 0x00, 0x04, 0x00,
				addr[2], addr[0], addr[3], addr[4], addr[5], addr[1],
			}
			return p, nil
		},
	},
}

// KnownVendors returns the list in a stable order for --list-vendors.
func KnownVendors() []VendorCmd {
	order := []string{"broadcom", "cypress", "zeevo", "ti", "st", "ericsson", "intel", "csr"}
	out := make([]VendorCmd, 0, len(order))
	for _, n := range order {
		if v, ok := vendorCmds[n]; ok {
			out = append(out, v)
		}
	}
	return out
}

// lookupVendor finds a vendor table entry by name, case-insensitive.
func lookupVendor(name string) (VendorCmd, bool) {
	v, ok := vendorCmds[strings.ToLower(name)]
	return v, ok
}

// VendorForManufacturer maps a Bluetooth SIG company-identifier to the vendor
// name in vendorCmds, or "" if we don't have a table entry for it.
// SIG assignments: https://www.bluetooth.com/specifications/assigned-numbers/company-identifiers/
func VendorForManufacturer(id uint16) string {
	switch id {
	case 0:
		return "ericsson"
	case 2:
		return "intel"
	case 10:
		return "csr"
	case 13:
		return "ti"
	case 15:
		return "broadcom"
	case 18:
		return "zeevo"
	case 48:
		return "st"
	case 305:
		return "cypress"
	}
	return ""
}

// manufacturerName returns a friendly name for the SIG company ID; falls back
// to "Unknown".
func manufacturerName(id uint16) string {
	switch id {
	case 0:
		return "Ericsson Technology Licensing"
	case 1:
		return "Nokia Mobile Phones"
	case 2:
		return "Intel Corp."
	case 3:
		return "IBM Corp."
	case 4:
		return "Toshiba Corp."
	case 5:
		return "3Com"
	case 6:
		return "Microsoft"
	case 7:
		return "Lucent"
	case 8:
		return "Motorola"
	case 9:
		return "Infineon Technologies AG"
	case 10:
		return "Cambridge Silicon Radio"
	case 13:
		return "Texas Instruments Inc."
	case 15:
		return "Broadcom Corporation"
	case 18:
		return "Zeevo, Inc."
	case 48:
		return "ST Microelectronics"
	case 305:
		return "Cypress Semiconductor"
	}
	return "Unknown"
}

// describeSettings unpacks the MGMT supported/current settings bitfields into
// human-readable flag names so --show output is useful.
func describeSettings(supported, current uint32) []string {
	all := []struct {
		bit  uint32
		name string
	}{
		{1 << 0, "powered"},
		{1 << 1, "connectable"},
		{1 << 2, "fast-connectable"},
		{1 << 3, "discoverable"},
		{1 << 4, "bondable"},
		{1 << 5, "link-security"},
		{1 << 6, "ssp"},
		{1 << 7, "br/edr"},
		{1 << 8, "high-speed"},
		{1 << 9, "le"},
		{1 << 10, "advertising"},
		{1 << 11, "secure-conn"},
		{1 << 12, "debug-keys"},
		{1 << 13, "privacy"},
		{1 << 14, "configuration"},
		{1 << 15, "static-address"},
		{1 << 16, "phy-config"},
		{1 << 17, "wideband-speech"},
		{1 << 18, "cis-central"},
		{1 << 19, "cis-peripheral"},
		{1 << 20, "iso-broadcaster"},
		{1 << 21, "sync-receiver"},
	}
	var out []string
	for _, b := range all {
		if supported&b.bit == 0 {
			continue
		}
		mark := b.name
		if current&b.bit != 0 {
			mark = "+" + b.name
		} else {
			mark = "-" + b.name
		}
		out = append(out, mark)
	}
	return out
}

