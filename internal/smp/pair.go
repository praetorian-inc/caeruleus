package smp

import "time"

// ProbeResult is the outcome of one Pairing Feature Exchange: either the peer
// sent a Pairing Response (it is willing to proceed with the offered request)
// or a Pairing Failed (it rejected the request outright).
type ProbeResult struct {
	Responded  bool
	Peer       PairingPDU // valid when Responded
	Failed     bool
	FailReason byte
}

// Probe sends one Pairing Request with the given parameters, reads the peer's
// reply, and aborts pairing (we only want the feature exchange, not a completed
// bond - which would need the LESC/legacy key exchange). It does not complete
// pairing, so it never establishes encryption.
func Probe(d *Dev, req PairingPDU, timeout time.Duration) (ProbeResult, error) {
	if err := d.WriteSMP(req.Encode(OpPairingRequest)); err != nil {
		return ProbeResult{}, err
	}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		pdu, err := d.ReadSMP(time.Until(deadline))
		if err != nil {
			return ProbeResult{}, err
		}
		if len(pdu) == 0 {
			continue
		}
		switch pdu[0] {
		case OpPairingResponse:
			_, p, perr := ParsePairing(pdu)
			if perr != nil {
				return ProbeResult{}, perr
			}
			// Abort cleanly: we have the features, don't proceed to key gen.
			_ = d.WriteSMP(EncodeFailed(0x08)) // Unspecified Reason
			return ProbeResult{Responded: true, Peer: p}, nil
		case OpPairingFailed:
			var reason byte = 0x08
			if len(pdu) >= 2 {
				reason = pdu[1]
			}
			return ProbeResult{Failed: true, FailReason: reason}, nil
		case OpSecurityRequest:
			continue // peripheral nudging us to start security; we already did
		default:
			continue // confirm/random/public-key etc. - ignore in a probe
		}
	}
	return ProbeResult{}, errTimeout
}

// CapableRequest is a maximally-capable Pairing Request used to learn the
// peer's declared requirements: KeyboardDisplay IO, bonding + MITM + SC, full
// 16-byte key, distributing LTK + IRK both ways.
func CapableRequest() PairingPDU {
	return PairingPDU{
		IOCap:       IOKeyboardDisplay,
		OOB:         0,
		AuthReq:     AuthReq{Bonding: true, MITM: true, SC: true},
		MaxKeySize:  16,
		InitKeyDist: KeyEnc | KeyID,
		RespKeyDist: KeyEnc | KeyID,
	}
}
