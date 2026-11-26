package rns

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

// TestPathRequestDestHashRecomputes is a regression guard: if either NameHash
// or the PLAIN-destination derivation rule (16 zero bytes for identity_hash)
// ever changes, this test fails before users hit a silent network bug.
func TestPathRequestDestHashRecomputes(t *testing.T) {
	nh := NameHash("rnstransport.path.request")
	expectedNameHashHex := "7926bbe7dd7f9aba88b0"
	if hex.EncodeToString(nh) != expectedNameHashHex {
		t.Errorf("NameHash(rnstransport.path.request) = %x, want %s", nh, expectedNameHashHex)
	}

	// For PLAIN destinations, the identity hash is OMITTED — not zero-padded.
	// Per upstream RNS.Destination.hash: addr_hash_material = name_hash only
	// when identity is None.
	d := sha256.Sum256(nh)
	got := hex.EncodeToString(d[:IdentityHashLen])
	if got != PathRequestDestHashHex {
		t.Errorf("path-request dest hash recompute mismatch\n got %s\nwant %s", got, PathRequestDestHashHex)
	}
}

func TestBuildPathRequestStructure(t *testing.T) {
	target := newDummyHash(0xAB)
	pkt, err := BuildPathRequest(target)
	if err != nil {
		t.Fatal(err)
	}

	if pkt.PacketType != PacketData {
		t.Errorf("packet_type = %d, want PacketData", pkt.PacketType)
	}
	if pkt.DestinationType != DestinationPlain {
		t.Errorf("dest_type = %d, want DestinationPlain", pkt.DestinationType)
	}
	if pkt.TransportType != BroadcastTransport {
		t.Errorf("transport_type = %d, want BroadcastTransport", pkt.TransportType)
	}
	if pkt.HeaderType != HeaderType1 {
		t.Errorf("header_type = %d, want HEADER_1", pkt.HeaderType)
	}
	if pkt.Context != ContextNone {
		t.Errorf("context = 0x%02x, want 0x00", pkt.Context)
	}
	expectedDest, _ := hex.DecodeString(PathRequestDestHashHex)
	if !bytes.Equal(pkt.DestHash, expectedDest) {
		t.Errorf("dest_hash = %x, want well-known %x", pkt.DestHash, expectedDest)
	}
	if len(pkt.Data) != PathRequestPayloadLen {
		t.Fatalf("payload length = %d, want %d", len(pkt.Data), PathRequestPayloadLen)
	}
	if !bytes.Equal(pkt.Data[:IdentityHashLen], target) {
		t.Errorf("payload target prefix mismatch: got %x, want %x", pkt.Data[:IdentityHashLen], target)
	}
}

func TestBuildPathRequestRejectsBadTarget(t *testing.T) {
	if _, err := BuildPathRequest(nil); err == nil {
		t.Error("expected error for nil target")
	}
	if _, err := BuildPathRequest(make([]byte, 8)); err == nil {
		t.Error("expected error for short target")
	}
}

func TestBuildPathRequestUsesFreshTagEachCall(t *testing.T) {
	target := newDummyHash(0xCD)
	a, _ := BuildPathRequest(target)
	b, _ := BuildPathRequest(target)
	// Tags are random; two builds back-to-back should differ.
	if bytes.Equal(a.Data[IdentityHashLen:], b.Data[IdentityHashLen:]) {
		t.Error("two BuildPathRequest calls produced the same tag (expected random)")
	}
	// Targets are stable.
	if !bytes.Equal(a.Data[:IdentityHashLen], b.Data[:IdentityHashLen]) {
		t.Error("target half changed between calls")
	}
}

func TestPathRequestTargetExtracts(t *testing.T) {
	target := newDummyHash(0x77)
	pkt, _ := BuildPathRequest(target)
	got, err := PathRequestTarget(pkt.Data)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, target) {
		t.Errorf("target extraction mismatch")
	}
}

// TestHandlePathRequestEmitsPathResponseAnnounce is the regression test
// for the SPEC §7.2 path-request responder. When an inbound path?
// request targets one of our local destinations, we must broadcast a
// path-response (announce with context = ContextPathResponse) carrying
// our public key so the requester can build a path table entry.
//
// Without this, leaf clients can't bootstrap a path to us via path? —
// they have to wait up to one announce_interval (10 min default) for
// our periodic announce.
func TestHandlePathRequestEmitsPathResponseAnnounce(t *testing.T) {
	transport := NewTransport(nil)
	captured := newFakeInterface()
	transport.AddInterface(captured)

	id, _ := NewIdentity()
	destHash := id.DestinationHashFor(FullName("lxmf", "delivery"))
	if err := transport.RegisterLocal(&LocalDestination{
		DestHash: destHash,
		Identity: id,
		OnPacket: func(*Packet) {},
		BuildAnnounce: func(ctx byte) (*Packet, error) {
			return BuildAnnounceWithContext(id, FullName("lxmf", "delivery"), nil, nil, ctx)
		},
	}); err != nil {
		t.Fatalf("RegisterLocal: %v", err)
	}

	req, err := BuildPathRequest(destHash)
	if err != nil {
		t.Fatalf("BuildPathRequest: %v", err)
	}
	transport.handlePathRequest(req)

	wires := captured.sentCopy()
	if len(wires) != 1 {
		t.Fatalf("expected 1 transmitted packet (path-response), got %d", len(wires))
	}
	resp, err := ParsePacket(wires[0])
	if err != nil {
		t.Fatalf("ParsePacket(response): %v", err)
	}
	if resp.PacketType != PacketAnnounce {
		t.Errorf("response packet_type = %d, want PacketAnnounce", resp.PacketType)
	}
	if resp.Context != ContextPathResponse {
		t.Errorf("response context = 0x%02x, want ContextPathResponse (0x0B)", resp.Context)
	}
	if !bytes.Equal(resp.DestHash, destHash) {
		t.Errorf("response dest_hash = %x, want %x", resp.DestHash, destHash)
	}
	a, err := ParseAnnounce(resp)
	if err != nil {
		t.Fatalf("ParseAnnounce: %v", err)
	}
	if err := a.Verify(); err != nil {
		t.Errorf("path-response announce signature does not verify: %v", err)
	}
}

// TestHandlePathRequestIgnoresUnrelatedTarget pins that we don't emit
// path-responses for destinations we don't own — preventing us from
// turning into an inadvertent transit relay for arbitrary path queries.
func TestHandlePathRequestIgnoresUnrelatedTarget(t *testing.T) {
	transport := NewTransport(nil)
	captured := newFakeInterface()
	transport.AddInterface(captured)

	id, _ := NewIdentity()
	ourHash := id.DestinationHashFor(FullName("lxmf", "delivery"))
	if err := transport.RegisterLocal(&LocalDestination{
		DestHash: ourHash,
		Identity: id,
		OnPacket: func(*Packet) {},
		BuildAnnounce: func(ctx byte) (*Packet, error) {
			return BuildAnnounceWithContext(id, FullName("lxmf", "delivery"), nil, nil, ctx)
		},
	}); err != nil {
		t.Fatalf("RegisterLocal: %v", err)
	}

	someOtherTarget := newDummyHash(0xAB)
	req, _ := BuildPathRequest(someOtherTarget)
	transport.handlePathRequest(req)

	if got := captured.sentCopy(); len(got) != 0 {
		t.Errorf("expected no transmission for unrelated target, got %d packets", len(got))
	}
}

// TestHandlePathRequestDedupsByTag pins that re-receiving the same
// request (same 16-byte tag) within PathResponseTagDedupWindow does
// NOT cause us to emit a second response — protects against amplifying
// when a single request reaches us via multiple relay hops.
func TestHandlePathRequestDedupsByTag(t *testing.T) {
	transport := NewTransport(nil)
	captured := newFakeInterface()
	transport.AddInterface(captured)

	id, _ := NewIdentity()
	destHash := id.DestinationHashFor(FullName("lxmf", "delivery"))
	if err := transport.RegisterLocal(&LocalDestination{
		DestHash: destHash,
		Identity: id,
		OnPacket: func(*Packet) {},
		BuildAnnounce: func(ctx byte) (*Packet, error) {
			return BuildAnnounceWithContext(id, FullName("lxmf", "delivery"), nil, nil, ctx)
		},
	}); err != nil {
		t.Fatalf("RegisterLocal: %v", err)
	}

	req, _ := BuildPathRequest(destHash)

	transport.handlePathRequest(req)
	transport.handlePathRequest(req) // same tag → suppress

	if got := captured.sentCopy(); len(got) != 1 {
		t.Errorf("expected exactly 1 transmission with tag dedup, got %d", len(got))
	}
}

// TestBuildPathRequestStampedForm pins the SPEC §7.1 stamped layout RNS
// 1.6.0+ emits: target || transport_id || tag || 0xC1 0x00 || stamp(14),
// with the stamp clearing PathRequestStampCost bits over target || tag.
func TestBuildPathRequestStampedForm(t *testing.T) {
	target := newDummyHash(0x5A)
	pkt, err := BuildPathRequest(target)
	if err != nil {
		t.Fatal(err)
	}
	if len(pkt.Data) != PathRequestStampedLen {
		t.Fatalf("payload length = %d, want %d", len(pkt.Data), PathRequestStampedLen)
	}
	tid, err := EphemeralTransportID()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pkt.Data[16:32], tid) {
		t.Errorf("transport_id = %x, want ephemeral %x", pkt.Data[16:32], tid)
	}
	if pkt.Data[48] != 0xC1 || pkt.Data[49] != 0x00 {
		t.Errorf("stamp extension header = %x, want c100", pkt.Data[48:50])
	}
	// Independent of the package's own helpers: SHA256(dest || tag || stamp).
	d := sha256.Sum256(append(append(append([]byte{}, target...), pkt.Data[32:48]...), pkt.Data[50:]...))
	lz := 0
	for _, b := range d {
		if b == 0 {
			lz += 8
			continue
		}
		for b&0x80 == 0 {
			lz++
			b <<= 1
		}
		break
	}
	if lz < PathRequestStampCost {
		t.Errorf("stamp has %d leading zero bits, want >= %d", lz, PathRequestStampCost)
	}

	req, err := ParsePathRequest(pkt.Data)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(req.Target, target) || !bytes.Equal(req.Tag, pkt.Data[32:48]) || !bytes.Equal(req.TransportID, tid) {
		t.Errorf("ParsePathRequest did not round-trip: %+v", req)
	}
	if !req.StampValid(PathRequestStampCost) {
		t.Error("StampValid rejected our own stamp")
	}
}

func TestPathRequestStampBoundToTargetAndTag(t *testing.T) {
	pkt, err := BuildPathRequest(newDummyHash(0x11))
	if err != nil {
		t.Fatal(err)
	}
	other := append([]byte{}, pkt.Data...)
	copy(other[:16], newDummyHash(0x22))
	req, _ := ParsePathRequest(other)
	// 2^-16 chance the stamp happens to clear another target too.
	if req.StampValid(PathRequestStampCost) {
		t.Error("stamp validated against a different target")
	}
	other = append([]byte{}, pkt.Data...)
	other[32] ^= 0xFF
	req, _ = ParsePathRequest(other)
	if req.StampValid(PathRequestStampCost) {
		t.Error("stamp validated against a different tag")
	}
}

func TestPathRequestPlaceholderNeverValid(t *testing.T) {
	data := make([]byte, 0, PathRequestStampedLen)
	data = append(data, newDummyHash(0x33)...)
	data = append(data, newDummyHash(0x44)...)
	data = append(data, newDummyHash(0x55)...)
	data = append(data, pathRequestExtMarker, pathRequestStampPlaceholder)
	data = append(data, make([]byte, PathRequestStampLen)...)
	req, err := ParsePathRequest(data)
	if err != nil {
		t.Fatal(err)
	}
	if req.StampValid(0) {
		t.Error("relay placeholder stamp validated")
	}
}

// TestParsePathRequestLengths pins the SPEC §7.2.1 ingress rule: only 32,
// 48 and 64 bytes are path requests, and the tag position depends on which.
func TestParsePathRequestLengths(t *testing.T) {
	buf := make([]byte, 80)
	for i := range buf {
		buf[i] = byte(i)
	}
	for _, tc := range []struct {
		n      int
		ok     bool
		tagAt  int
		hasTID bool
		hasExt bool
	}{
		{16, false, 0, false, false},
		{17, false, 0, false, false},
		{31, false, 0, false, false},
		{32, true, 16, false, false},
		{33, false, 0, false, false},
		{48, true, 32, true, false},
		{63, false, 0, false, false},
		{64, true, 32, true, true},
		{65, false, 0, false, false},
	} {
		req, err := ParsePathRequest(buf[:tc.n])
		if (err == nil) != tc.ok {
			t.Errorf("len %d: err = %v, want ok=%v", tc.n, err, tc.ok)
			continue
		}
		if !tc.ok {
			continue
		}
		if !bytes.Equal(req.Tag, buf[tc.tagAt:tc.tagAt+16]) {
			t.Errorf("len %d: tag = %x, want bytes %d..%d", tc.n, req.Tag, tc.tagAt, tc.tagAt+16)
		}
		if (req.TransportID != nil) != tc.hasTID || (req.Ext != nil) != tc.hasExt {
			t.Errorf("len %d: tid=%x ext=%x", tc.n, req.TransportID, req.Ext)
		}
	}
}

func registerTestLXMF(t *testing.T, transport *Transport) []byte {
	t.Helper()
	id, _ := NewIdentity()
	destHash := id.DestinationHashFor(FullName("lxmf", "delivery"))
	if err := transport.RegisterLocal(&LocalDestination{
		DestHash: destHash,
		Identity: id,
		OnPacket: func(*Packet) {},
		BuildAnnounce: func(ctx byte) (*Packet, error) {
			return BuildAnnounceWithContext(id, FullName("lxmf", "delivery"), nil, nil, ctx)
		},
	}); err != nil {
		t.Fatalf("RegisterLocal: %v", err)
	}
	return destHash
}

func pathRequestPacket(data []byte) *Packet {
	wellKnown, _ := hex.DecodeString(PathRequestDestHashHex)
	return &Packet{DestinationType: DestinationPlain, PacketType: PacketData, DestHash: wellKnown, Data: data}
}

// TestHandlePathRequestRelayedUnstampedNotDeduped is the regression test for
// deduping on the trailing 16 bytes. A relay forwarding an unstamped request
// appends the fixed 0xC1 0xFF placeholder, so two different requests share
// their last 16 bytes; only their tags differ. Both must be answered.
func TestHandlePathRequestRelayedUnstampedNotDeduped(t *testing.T) {
	transport := NewTransport(nil)
	captured := newFakeInterface()
	transport.AddInterface(captured)
	destHash := registerTestLXMF(t, transport)

	relayed := func(tagByte byte) *Packet {
		data := make([]byte, 0, PathRequestStampedLen)
		data = append(data, destHash...)
		data = append(data, newDummyHash(0x99)...)
		data = append(data, newDummyHash(tagByte)...)
		data = append(data, pathRequestExtMarker, pathRequestStampPlaceholder)
		data = append(data, make([]byte, PathRequestStampLen)...)
		return pathRequestPacket(data)
	}
	transport.handlePathRequest(relayed(0x01))
	transport.handlePathRequest(relayed(0x02))

	if got := captured.sentCopy(); len(got) != 2 {
		t.Errorf("expected 2 path responses for 2 distinct tags, got %d", len(got))
	}
}

// TestHandlePathRequestAcceptsOlderForms pins that the 32- and 48-byte
// forms older nodes send are still answered, as upstream 1.6 does.
func TestHandlePathRequestAcceptsOlderForms(t *testing.T) {
	transport := NewTransport(nil)
	captured := newFakeInterface()
	transport.AddInterface(captured)
	destHash := registerTestLXMF(t, transport)

	legacy := append(append([]byte{}, destHash...), newDummyHash(0x01)...)
	unstamped := append(append(append([]byte{}, destHash...), newDummyHash(0x02)...), newDummyHash(0x03)...)
	transport.handlePathRequest(pathRequestPacket(legacy))
	transport.handlePathRequest(pathRequestPacket(unstamped))
	transport.handlePathRequest(pathRequestPacket(append(legacy, 0x00))) // 33 bytes: invalid

	if got := captured.sentCopy(); len(got) != 2 {
		t.Errorf("expected 2 path responses (32B + 48B, not 33B), got %d", len(got))
	}
}

func BenchmarkBuildPathRequest(b *testing.B) {
	target := newDummyHash(0x42)
	for i := 0; i < b.N; i++ {
		if _, err := BuildPathRequest(target); err != nil {
			b.Fatal(err)
		}
	}
}
