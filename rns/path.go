package rns

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/bits"
	"sync"
	"time"
)

// PathRequestDestHashHex is the well-known PLAIN destination address that
// path? requests are sent to (SPEC §7.1, §1.2). Verified against upstream
// RNS 1.2.0 — `RNS.Transport.path_request_destination.hash`.
//
// PLAIN destinations have NO identity hash component (per upstream
// `RNS.Destination.hash`: when `identity is None`, `addr_hash_material`
// is just the 10-byte name_hash with nothing appended — NOT name_hash
// concatenated with 16 zero bytes, which is what an earlier draft of our
// notes incorrectly said). Computation:
//
//	name_hash = SHA-256("rnstransport.path.request")[:10]
//	          = 7926bbe7dd7f9aba88b0
//	dest_hash = SHA-256(name_hash)[:16]
//	          = 6b9f66014d9853faab220fba47d02761
//
// TestPathRequestDestHashRecomputes guards against drift in either step.
const PathRequestDestHashHex = "6b9f66014d9853faab220fba47d02761"

// Path-request payload lengths. Since RNS 1.6.0 these are the only three a
// receiver accepts; anything else is a protocol violation (SPEC §7.2.1).
const (
	// PathRequestLegacyLen is target(16) || tag(16), what a leaf sent
	// through RNS 1.5.7. Upstream marks it for removal.
	PathRequestLegacyLen = 32
	// PathRequestUnstampedLen is target(16) || transport_id(16) || tag(16).
	// Upstream marks it for removal.
	PathRequestUnstampedLen = 48
	// PathRequestStampedLen is the unstamped form followed by
	// 0xC1 || flags || stamp(14), the form RNS 1.6.0+ emits by default.
	PathRequestStampedLen = 64
)

// PathRequestPayloadLen is the length of the payload BuildPathRequest
// emits: the stamped form (SPEC §7.1).
const PathRequestPayloadLen = PathRequestStampedLen

const (
	// pathRequestExtMarker opens the stamp extension
	// (RNS.Identity.EXTPAYLOADMARKER).
	pathRequestExtMarker = 0xC1
	// pathRequestStampOwn flags a stamp made by the requester itself.
	pathRequestStampOwn = 0x00
	// pathRequestStampPlaceholder flags the never-valid all-zero stamp a
	// relay substitutes when forwarding an unstamped request.
	pathRequestStampPlaceholder = 0xFF
	// PathRequestStampLen is RNS.Identity.STAMPLENGTH.
	PathRequestStampLen = 14
)

// PathRequestStampCost is the proof-of-work we put into a path-request
// stamp, in leading zero bits of SHA256(target || tag || stamp).
//
// Upstream emits PR_VALUE = 15.8 and receivers require pr_cost, default
// PR_COST = 15.8 (SPEC §7.1). A fractional target needs upstream's
// mantissa table (SPEC §5.7.2), but a stamp that clears ceil(c) also
// clears c (SPEC §4.3), so 16 whole bits is accepted by every default
// receiver for about 15% more work than 15.8 and no table.
const PathRequestStampCost = 16

// PathRequestStampTimeout caps how long BuildPathRequest grinds for a
// stamp, mirroring upstream PR_STAMP_TIMEOUT. At 16 bits the expected
// work is 65536 hashes, so hitting it means something else is wrong.
const PathRequestStampTimeout = 15 * time.Second

var (
	ephemeralTransportIDOnce sync.Once
	ephemeralTransportID     []byte
	ephemeralTransportIDErr  error
)

// EphemeralTransportID returns the 16-byte transport_id this process puts in
// its path requests. Since RNS 1.6.0 every node sends one; a node without a
// persistent transport identity uses an ephemeral one generated at start-up
// (SPEC §7.1). Receivers use it only to spot "the next hop is the
// requester" (SPEC §7.2.3 branch 2), so it carries no authority and a
// random value per process is equivalent.
func EphemeralTransportID() ([]byte, error) {
	ephemeralTransportIDOnce.Do(func() {
		id := make([]byte, IdentityHashLen)
		if _, err := rand.Read(id); err != nil {
			ephemeralTransportIDErr = fmt.Errorf("ephemeral transport id entropy: %w", err)
			return
		}
		ephemeralTransportID = id
	})
	if ephemeralTransportIDErr != nil {
		return nil, ephemeralTransportIDErr
	}
	out := make([]byte, IdentityHashLen)
	copy(out, ephemeralTransportID)
	return out, nil
}

// BuildPathRequest constructs a SPEC §7.1 path? request for the given target
// destination_hash, in the stamped 64-byte form RNS 1.6.0+ emits:
//
//	target(16) || transport_id(16) || tag(16) || 0xC1 0x00 || stamp(14)
//
// tag is 16 fresh random bytes that relays dedup on (SPEC §7.2.2), and the
// stamp is proof-of-work bound to target and tag (PathRequestStampCost).
// Receivers that enforce stamps drop the 32- and 48-byte forms.
//
// Grinding the stamp takes a few milliseconds and blocks the caller.
func BuildPathRequest(targetDestHash []byte) (*Packet, error) {
	if len(targetDestHash) != IdentityHashLen {
		return nil, fmt.Errorf("target dest_hash must be %d bytes, got %d", IdentityHashLen, len(targetDestHash))
	}

	wellKnown, err := hex.DecodeString(PathRequestDestHashHex)
	if err != nil {
		return nil, fmt.Errorf("decode path-request dest hash: %w", err)
	}

	transportID, err := EphemeralTransportID()
	if err != nil {
		return nil, err
	}

	tag := make([]byte, IdentityHashLen)
	if _, err := rand.Read(tag); err != nil {
		return nil, fmt.Errorf("path request tag entropy: %w", err)
	}

	stamp, err := generatePathRequestStamp(targetDestHash, tag, PathRequestStampCost, PathRequestStampTimeout)
	if err != nil {
		return nil, err
	}

	payload := make([]byte, 0, PathRequestStampedLen)
	payload = append(payload, targetDestHash...)
	payload = append(payload, transportID...)
	payload = append(payload, tag...)
	payload = append(payload, pathRequestExtMarker, pathRequestStampOwn)
	payload = append(payload, stamp...)

	return &Packet{
		HeaderType:      HeaderType1,
		ContextFlag:     false,
		TransportType:   BroadcastTransport,
		DestinationType: DestinationPlain,
		PacketType:      PacketData,
		Hops:            0,
		DestHash:        wellKnown,
		Context:         ContextNone,
		Data:            payload,
	}, nil
}

// PathRequest is a parsed path-request payload (SPEC §7.2.1,
// Transport.parse_path_request).
type PathRequest struct {
	Target []byte // 16 bytes
	// TransportID is the requester's transport_id, nil for the 32-byte
	// legacy form. Ephemeral on leaves: do not use it to identify anyone.
	TransportID []byte
	Tag         []byte // 16 bytes
	// Ext is the 16-byte stamp extension (0xC1 || flags || stamp), nil
	// unless the request is the 64-byte form.
	Ext []byte
}

// ParsePathRequest splits a path-request payload the way upstream's
// Transport.parse_path_request does, accepting only the 32-, 48- and 64-byte
// forms RNS 1.6.0+ accepts (SPEC §7.2.1). The tag is never the trailing 16
// bytes of a 64-byte request: those are the stamp extension, and on every
// relayed unstamped request they are the same 0xC1 0xFF placeholder.
//
// The returned slices alias payload.
func ParsePathRequest(payload []byte) (*PathRequest, error) {
	var pr PathRequest
	switch len(payload) {
	case PathRequestLegacyLen:
		pr.Tag = payload[16:32]
	case PathRequestUnstampedLen:
		pr.TransportID = payload[16:32]
		pr.Tag = payload[32:48]
	case PathRequestStampedLen:
		pr.TransportID = payload[16:32]
		pr.Tag = payload[32:48]
		pr.Ext = payload[48:64]
	case IdentityHashLen:
		return nil, errors.New("tagless path request")
	default:
		return nil, fmt.Errorf("invalid path request size %d", len(payload))
	}
	pr.Target = payload[:16]
	return &pr, nil
}

// StampValid reports whether the request carries its requester's own stamp
// and that stamp clears cost leading zero bits. A relay's placeholder and
// the unstamped forms never validate.
func (pr *PathRequest) StampValid(cost int) bool {
	if len(pr.Ext) != 2+PathRequestStampLen || pr.Ext[0] != pathRequestExtMarker || pr.Ext[1] != pathRequestStampOwn {
		return false
	}
	return pathRequestStampValid(pr.Target, pr.Tag, pr.Ext[2:], cost)
}

// PathRequestTarget extracts the target destination_hash from a path-request
// packet payload (the first 16 bytes).
func PathRequestTarget(payload []byte) ([]byte, error) {
	if len(payload) < IdentityHashLen {
		return nil, errors.New("path request payload too short")
	}
	out := make([]byte, IdentityHashLen)
	copy(out, payload[:IdentityHashLen])
	return out, nil
}

// pathRequestStampValid checks SHA256(target || tag || stamp) against cost.
// The workblock is target || tag used directly, with no HKDF expansion
// (SPEC §7.1).
func pathRequestStampValid(target, tag, stamp []byte, cost int) bool {
	buf := make([]byte, 0, len(target)+len(tag)+len(stamp))
	buf = append(buf, target...)
	buf = append(buf, tag...)
	buf = append(buf, stamp...)
	d := sha256.Sum256(buf)
	return leadingZeroBits(d[:]) >= cost
}

func leadingZeroBits(b []byte) int {
	n := 0
	for _, by := range b {
		if by != 0 {
			return n + bits.LeadingZeros8(by)
		}
		n += 8
	}
	return n
}

// generatePathRequestStamp grinds random 14-byte stamps until one clears
// cost bits over target || tag, or timeout passes.
func generatePathRequestStamp(target, tag []byte, cost int, timeout time.Duration) ([]byte, error) {
	buf := make([]byte, 0, len(target)+len(tag)+PathRequestStampLen)
	buf = append(buf, target...)
	buf = append(buf, tag...)
	prefix := len(buf)
	buf = buf[:prefix+PathRequestStampLen]
	stamp := buf[prefix:]

	// Draw entropy in batches; one rand.Read per attempt would cost more
	// than the hash.
	const batch = 1024
	pool := make([]byte, batch*PathRequestStampLen)
	deadline := time.Now().Add(timeout)
	for {
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("path request stamp: no %d-bit stamp within %s", cost, timeout)
		}
		if _, err := rand.Read(pool); err != nil {
			return nil, fmt.Errorf("path request stamp entropy: %w", err)
		}
		for i := 0; i < batch; i++ {
			copy(stamp, pool[i*PathRequestStampLen:(i+1)*PathRequestStampLen])
			d := sha256.Sum256(buf)
			if leadingZeroBits(d[:]) >= cost {
				out := make([]byte, PathRequestStampLen)
				copy(out, stamp)
				return out, nil
			}
		}
	}
}
