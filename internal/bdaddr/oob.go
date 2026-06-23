package bdaddr

import "time"

const (
	mgmtOpAddRemoteOOB    = 0x0021
	mgmtOpRemoveRemoteOOB = 0x0022
)

// AddRemoteOOBData provisions OOB pairing data for a remote LE device via the
// BlueZ management socket (MGMT_OP_ADD_REMOTE_OOB_DATA). Once provisioned,
// the next Device1.Pair() through BlueZ will use the OOB association model.
//
// addrType: 1 = LE public, 2 = LE random.
// For LE SC OOB: hash256 = confirmation, rand256 = random.
// For LE legacy OOB: hash256 = TK, rand256 = all zeros.
func (m *Manager) AddRemoteOOBData(addr [6]byte, addrType uint8, hash256, rand256 [16]byte) error {
	var buf [71]byte
	copy(buf[0:6], addr[:])
	buf[6] = addrType
	// buf[7:23]  = hash192  — zeros (BR/EDR only)
	// buf[23:39] = rand192  — zeros (BR/EDR only)
	copy(buf[39:55], hash256[:])
	copy(buf[55:71], rand256[:])
	if err := m.sendMgmt(mgmtOpAddRemoteOOB, buf[:]); err != nil {
		return err
	}
	_, err := m.waitCmdComplete(mgmtOpAddRemoteOOB, 2*time.Second)
	return err
}

// RemoveRemoteOOBData removes previously provisioned OOB data for a remote
// device. Call after pairing to avoid stale OOB data affecting future attempts.
func (m *Manager) RemoveRemoteOOBData(addr [6]byte, addrType uint8) error {
	var buf [7]byte
	copy(buf[0:6], addr[:])
	buf[6] = addrType
	if err := m.sendMgmt(mgmtOpRemoveRemoteOOB, buf[:]); err != nil {
		return err
	}
	_, err := m.waitCmdComplete(mgmtOpRemoveRemoteOOB, 2*time.Second)
	return err
}
