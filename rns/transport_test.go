package rns

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeInterface is an in-memory Interface implementation for tests.
type fakeInterface struct {
	inbox chan []byte
	sent  [][]byte
	done  chan struct{}
	mu    sync.Mutex
}

func newFakeInterface() *fakeInterface {
	return &fakeInterface{
		inbox: make(chan []byte, 16),
		done:  make(chan struct{}),
	}
}

func (f *fakeInterface) Send(p []byte) error {
	f.mu.Lock()
	f.sent = append(f.sent, append([]byte(nil), p...))
	f.mu.Unlock()
	return nil
}

func (f *fakeInterface) Inbox() <-chan []byte  { return f.inbox }
func (f *fakeInterface) Done() <-chan struct{} { return f.done }
func (f *fakeInterface) close()                { close(f.done) }
func (f *fakeInterface) sentCopy() [][]byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([][]byte, len(f.sent))
	for i, b := range f.sent {
		out[i] = append([]byte(nil), b...)
	}
	return out
}

type recordingHandler struct {
	mu       sync.Mutex
	received []*Announce
	filter   []byte
}

func (h *recordingHandler) AspectMatch(nameHash []byte) bool {
	if h.filter == nil {
		return true
	}
	return bytes.Equal(h.filter, nameHash)
}
func (h *recordingHandler) OnAnnounce(a *Announce) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.received = append(h.received, a)
}
func (h *recordingHandler) snapshot() []*Announce {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]*Announce(nil), h.received...)
}

func TestTransportDispatchesVerifiedAnnounceToHandlers(t *testing.T) {
	id, _ := NewIdentity()
	pkt, _ := BuildAnnounce(id, FullName("lxmf", "delivery"), nil, nil)
	wire, _ := pkt.Pack()

	iface := newFakeInterface()
	handler := &recordingHandler{filter: NameHash(FullName("lxmf", "delivery"))}

	tr := NewTransport(nil)
	tr.AddInterface(iface)
	tr.RegisterAnnounceHandler(handler)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go tr.Run(ctx)

	iface.inbox <- wire

	deadline := time.After(500 * time.Millisecond)
	for {
		if len(handler.snapshot()) == 1 {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("handler never fired (got %d announces)", len(handler.snapshot()))
		case <-time.After(5 * time.Millisecond):
		}
	}

	known := tr.Recall(id.DestinationHashFor(FullName("lxmf", "delivery")))
	if known == nil {
		t.Fatal("Recall returned nil for known dest")
	}
	if !bytes.Equal(known.PublicKey, id.PublicKey()) {
		t.Errorf("known.PublicKey mismatch")
	}
}

// TestAnnounceRejectsPublicKeyCollision covers SPEC §4.5 step 4
// (first-announcer-wins): an announce for a dest_hash already bound to a
// DIFFERENT public key is rejected. A verifiable announce can never produce
// this (dest_hash is bound to the key), so we pre-seed a bogus key under the
// real announce's dest_hash and confirm the genuine announce doesn't
// overwrite it.
func TestAnnounceRejectsPublicKeyCollision(t *testing.T) {
	tr := NewTransport(nil)
	id, _ := NewIdentity()
	pkt, _ := BuildAnnounce(id, FullName("lxmf", "delivery"), nil, nil)
	dest := id.DestinationHashFor(FullName("lxmf", "delivery"))

	other := bytes.Repeat([]byte{0x42}, PublicKeyLen)
	tr.mu.Lock()
	tr.known[hex.EncodeToString(dest)] = &KnownIdentity{DestHash: dest, PublicKey: other}
	tr.mu.Unlock()

	tr.handleAnnounce(pkt) // genuine, verifiable — but a colliding key is cached

	got := tr.Recall(dest)
	if got == nil || !bytes.Equal(got.PublicKey, other) {
		t.Fatalf("collision announce was not rejected: cached key changed")
	}
}

func TestTransportRoutesDataToLocalDest(t *testing.T) {
	tr := NewTransport(nil)
	iface := newFakeInterface()
	tr.AddInterface(iface)

	deliveredCh := make(chan *Packet, 1)
	dest := newDummyHash(0xCC)
	tr.RegisterLocal(&LocalDestination{
		DestHash: dest,
		OnPacket: func(p *Packet) { deliveredCh <- p },
	})

	pkt := &Packet{
		HeaderType:      HeaderType1,
		DestinationType: DestinationSingle,
		PacketType:      PacketData,
		DestHash:        dest,
		Context:         ContextNone,
		Data:            []byte("ciphertext"),
	}
	wire, _ := pkt.Pack()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go tr.Run(ctx)

	iface.inbox <- wire

	select {
	case got := <-deliveredCh:
		if !bytes.Equal(got.DestHash, dest) {
			t.Errorf("delivered to wrong dest: %x", got.DestHash)
		}
		if !bytes.Equal(got.Data, []byte("ciphertext")) {
			t.Errorf("data mismatch: %x", got.Data)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("data never delivered to local dest")
	}
}

func TestTransportIgnoresDataForUnknownDest(t *testing.T) {
	tr := NewTransport(nil)
	iface := newFakeInterface()
	tr.AddInterface(iface)

	pkt := &Packet{
		HeaderType:      HeaderType1,
		DestinationType: DestinationSingle,
		PacketType:      PacketData,
		DestHash:        newDummyHash(0xFF),
		Context:         ContextNone,
		Data:            []byte("not ours"),
	}
	wire, _ := pkt.Pack()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go tr.Run(ctx)

	iface.inbox <- wire
	time.Sleep(50 * time.Millisecond) // give dispatcher time
	// No assertion: just verify nothing panics and the goroutine cleans up.
}

func TestTransportBroadcastFansOut(t *testing.T) {
	tr := NewTransport(nil)
	a, b := newFakeInterface(), newFakeInterface()
	tr.AddInterface(a)
	tr.AddInterface(b)

	pkt := &Packet{
		HeaderType:      HeaderType1,
		DestinationType: DestinationSingle,
		PacketType:      PacketData,
		DestHash:        newDummyHash(0xAA),
		Context:         ContextNone,
		Data:            []byte("hi"),
	}
	if err := tr.Broadcast(pkt); err != nil {
		t.Fatal(err)
	}
	if len(a.sentCopy()) != 1 || len(b.sentCopy()) != 1 {
		t.Errorf("broadcast didn't reach both interfaces (a=%d, b=%d)", len(a.sentCopy()), len(b.sentCopy()))
	}
}

func TestRequestPathAfterHonoursItsInterval(t *testing.T) {
	iface := newFakeInterface()
	tr := NewTransport(nil)
	tr.AddInterface(iface)
	target := newDummyHash(0x56)
	const interval = 40 * time.Millisecond

	for i := 0; i < 2; i++ {
		if err := tr.RequestPathAfter(target, interval); err != nil {
			t.Fatal(err)
		}
	}
	if n := len(iface.sentCopy()); n != 1 {
		t.Fatalf("%d requests inside the interval, want 1", n)
	}
	time.Sleep(2 * interval)
	if err := tr.RequestPathAfter(target, interval); err != nil {
		t.Fatal(err)
	}
	sent := iface.sentCopy()
	if len(sent) != 2 {
		t.Fatalf("%d requests after the interval, want 2", len(sent))
	}
	// SPEC §7.2.2: relays drop a repeated destination+tag, so a retry that
	// reused its tag would never be answered.
	if bytes.Equal(sent[0], sent[1]) {
		t.Fatal("retry reused the first request's tag")
	}
	if err := tr.RequestPath(target); err != nil {
		t.Fatal(err)
	}
	if n := len(iface.sentCopy()); n != 2 {
		t.Fatal("RequestPath must keep its own longer window")
	}
}

func TestRecallReturnsASnapshot(t *testing.T) {
	id, _ := NewIdentity()
	tr := NewTransport(nil)
	announce := func() {
		t.Helper()
		pkt, err := BuildAnnounce(id, FullName("lxmf", "delivery"), nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := pkt.Pack()
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := ParsePacket(raw)
		if err != nil {
			t.Fatal(err)
		}
		tr.handleAnnounce(parsed)
	}
	announce()
	dest := id.DestinationHashFor(FullName("lxmf", "delivery"))
	snapshot := tr.Recall(dest)
	if snapshot == nil {
		t.Fatal("announce was not cached")
	}
	before := append([]byte(nil), snapshot.LastRandom...)
	announce()
	if !bytes.Equal(snapshot.LastRandom, before) {
		t.Fatal("a later announce changed an identity already returned by Recall")
	}
	if bytes.Equal(tr.Recall(dest).LastRandom, before) {
		t.Fatal("the cache did not take the later announce")
	}
}

func TestRequestPathBroadcastsAndDedups(t *testing.T) {
	iface := newFakeInterface()
	tr := NewTransport(nil)
	tr.AddInterface(iface)

	target := newDummyHash(0x55)

	if err := tr.RequestPath(target); err != nil {
		t.Fatal(err)
	}
	// Second + third calls within the dedup window must not re-broadcast.
	if err := tr.RequestPath(target); err != nil {
		t.Fatal(err)
	}
	if err := tr.RequestPath(target); err != nil {
		t.Fatal(err)
	}

	sent := iface.sentCopy()
	if len(sent) != 1 {
		t.Fatalf("expected exactly 1 path request broadcast (deduped), got %d", len(sent))
	}

	pkt, err := ParsePacket(sent[0])
	if err != nil {
		t.Fatal(err)
	}
	if pkt.PacketType != PacketData || pkt.DestinationType != DestinationPlain {
		t.Errorf("not a path-request shaped packet: type=%d destType=%d", pkt.PacketType, pkt.DestinationType)
	}
	if !bytes.Equal(pkt.Data[:IdentityHashLen], target) {
		t.Errorf("payload target mismatch")
	}
}

func TestRequestPathDedupesPerTarget(t *testing.T) {
	// Distinct targets should NOT dedup — each gets its own request.
	iface := newFakeInterface()
	tr := NewTransport(nil)
	tr.AddInterface(iface)

	_ = tr.RequestPath(newDummyHash(0x01))
	_ = tr.RequestPath(newDummyHash(0x02))
	_ = tr.RequestPath(newDummyHash(0x03))

	if got := len(iface.sentCopy()); got != 3 {
		t.Errorf("expected 3 path requests for 3 distinct targets, got %d", got)
	}
}

func TestTransportEmitsProofForInboundData(t *testing.T) {
	id, _ := NewIdentity()
	destHash := id.DestinationHashFor(FullName("lxmf", "delivery"))

	iface := newFakeInterface()
	tr := NewTransport(nil)
	tr.AddInterface(iface)
	tr.RegisterLocal(&LocalDestination{
		DestHash: destHash,
		Identity: id,
		OnPacket: func(*Packet) {},
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go tr.Run(ctx)

	// Inject a fake DATA packet addressed to our local destination.
	dataPkt := &Packet{
		HeaderType:      HeaderType1,
		DestinationType: DestinationSingle,
		PacketType:      PacketData,
		DestHash:        destHash,
		Context:         ContextNone,
		Data:            []byte("ciphertext"),
	}
	dataWire, _ := dataPkt.Pack()
	iface.inbox <- dataWire

	// Expect to see a PROOF emitted on the same interface.
	deadline := time.After(500 * time.Millisecond)
	for {
		for _, sent := range iface.sentCopy() {
			parsed, err := ParsePacket(sent)
			if err != nil {
				continue
			}
			if parsed.PacketType == PacketProof {
				if parsed.Context != ContextNone {
					t.Errorf("proof context = 0x%02x, want 0x00", parsed.Context)
				}
				if len(parsed.Data) != ProofBodyImplicitLen {
					t.Errorf("proof body length = %d, want %d", len(parsed.Data), ProofBodyImplicitLen)
				}
				return
			}
		}
		select {
		case <-deadline:
			t.Fatalf("no PROOF emitted (sent %d packets)", len(iface.sentCopy()))
		case <-time.After(5 * time.Millisecond):
		}
	}
}

func TestTransportSkipsProofWhenIdentityAbsent(t *testing.T) {
	destHash := newDummyHash(0xDD)

	iface := newFakeInterface()
	tr := NewTransport(nil)
	tr.AddInterface(iface)
	tr.RegisterLocal(&LocalDestination{
		DestHash: destHash,
		// Identity intentionally nil — used by tests that don't care about proofs.
		OnPacket: func(*Packet) {},
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go tr.Run(ctx)

	dataPkt := &Packet{
		HeaderType:      HeaderType1,
		DestinationType: DestinationSingle,
		PacketType:      PacketData,
		DestHash:        destHash,
		Context:         ContextNone,
		Data:            []byte("c"),
	}
	dataWire, _ := dataPkt.Pack()
	iface.inbox <- dataWire

	time.Sleep(80 * time.Millisecond)
	for _, sent := range iface.sentCopy() {
		p, err := ParsePacket(sent)
		if err == nil && p.PacketType == PacketProof {
			t.Error("transport emitted a proof when LocalDestination.Identity was nil")
		}
	}
}

func TestTransportCapturesTransportIDFromHeader2Announce(t *testing.T) {
	id, _ := NewIdentity()
	pkt, _ := BuildAnnounce(id, FullName("lxmf", "delivery"), nil, nil)
	// Mutate to HEADER_2 with a known transport_id.
	pkt.HeaderType = HeaderType2
	pkt.TransportType = NetworkTransport
	pkt.TransportID = newDummyHash(0x99)
	pkt.Hops = 3
	wire, _ := pkt.Pack()

	iface := newFakeInterface()
	tr := NewTransport(nil)
	tr.AddInterface(iface)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go tr.Run(ctx)

	iface.inbox <- wire

	deadline := time.After(500 * time.Millisecond)
	for {
		known := tr.Recall(id.DestinationHashFor(FullName("lxmf", "delivery")))
		if known != nil && known.TransportID != nil {
			if !bytes.Equal(known.TransportID, newDummyHash(0x99)) {
				t.Errorf("transport_id mismatch: got %x", known.TransportID)
			}
			if known.Hops != 3 {
				t.Errorf("hops = %d, want 3", known.Hops)
			}
			return
		}
		select {
		case <-deadline:
			t.Fatal("transport_id never captured into KnownIdentity")
		case <-time.After(5 * time.Millisecond):
		}
	}
}

func TestTransportDedupesIdenticalRandomHash(t *testing.T) {
	id, _ := NewIdentity()
	pkt, _ := BuildAnnounce(id, FullName("lxmf", "delivery"), nil, nil)
	wire, _ := pkt.Pack()

	iface := newFakeInterface()
	handler := &recordingHandler{}
	tr := NewTransport(nil)
	tr.AddInterface(iface)
	tr.RegisterAnnounceHandler(handler)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go tr.Run(ctx)

	// Send the same announce three times; handler should fire only once.
	iface.inbox <- wire
	iface.inbox <- wire
	iface.inbox <- wire

	time.Sleep(100 * time.Millisecond)

	if got := len(handler.snapshot()); got != 1 {
		t.Errorf("dedup failed: handler fired %d times, want 1", got)
	}
}

// makePinTestAnnounce builds a verifiable announce for a fresh identity.
func makePinTestAnnounce(t *testing.T) (*Identity, *Packet) {
	t.Helper()
	id, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	appData, _ := EncodeLXMFAppData([]byte("peer"), nil)
	pkt, err := BuildAnnounce(id, FullName("lxmf", "delivery"), appData, nil)
	if err != nil {
		t.Fatal(err)
	}
	return id, pkt
}

// TestPinnedDestinationSurvivesEvictionChurn is the regression for the
// real-world failure: a hub carries far more announcing peers than the
// cache holds, so stranger churn evicted the group members we depend on
// being able to verify. Their next message then looked like it came from
// an unknown sender and was dropped.
func TestPinnedDestinationSurvivesEvictionChurn(t *testing.T) {
	tr := NewTransport(nil)

	// A peer we care about announces first — so it is the OLDEST entry,
	// exactly the one plain oldest-first eviction would discard.
	memberID, memberPkt := makePinTestAnnounce(t)
	tr.handleAnnounce(memberPkt)
	memberDest := memberID.DestinationHashFor(FullName("lxmf", "delivery"))
	if tr.Recall(memberDest) == nil {
		t.Fatal("member not cached after its announce")
	}
	tr.PinDestinations([][]byte{memberDest})

	// Now flood the cache well past capacity with strangers.
	for i := 0; i < KnownIdentityCapacity+64; i++ {
		_, pkt := makePinTestAnnounce(t)
		tr.handleAnnounce(pkt)
	}

	if tr.Recall(memberDest) == nil {
		t.Error("pinned member was evicted by stranger churn — the bug this prevents")
	}
	tr.mu.RLock()
	n := len(tr.known)
	tr.mu.RUnlock()
	if n > KnownIdentityCapacity {
		t.Errorf("cache holds %d entries, above capacity %d", n, KnownIdentityCapacity)
	}
}

// TestUnpinnedIsEvictedNormally confirms pinning is selective rather
// than disabling eviction.
func TestUnpinnedIsEvictedNormally(t *testing.T) {
	tr := NewTransport(nil)
	strangerID, strangerPkt := makePinTestAnnounce(t)
	tr.handleAnnounce(strangerPkt)
	strangerDest := strangerID.DestinationHashFor(FullName("lxmf", "delivery"))

	for i := 0; i < KnownIdentityCapacity+8; i++ {
		_, pkt := makePinTestAnnounce(t)
		tr.handleAnnounce(pkt)
	}
	if tr.Recall(strangerDest) != nil {
		t.Error("unpinned oldest entry survived a full cache churn")
	}
}

// TestPinningCannotWedgeTheCache: if everything is pinned there must
// still be room for new peers, or an over-large pinned set would stop
// the service learning anyone new.
func TestPinningCannotWedgeTheCache(t *testing.T) {
	tr := NewTransport(nil)
	var all [][]byte
	for i := 0; i < 64; i++ {
		id, pkt := makePinTestAnnounce(t)
		tr.handleAnnounce(pkt)
		all = append(all, id.DestinationHashFor(FullName("lxmf", "delivery")))
	}
	tr.PinDestinations(all)
	if got := tr.PinnedCount(); got != 64 {
		t.Fatalf("PinnedCount = %d, want 64", got)
	}

	// Force eviction with every existing entry pinned.
	tr.mu.Lock()
	for len(tr.known) < KnownIdentityCapacity {
		tr.known[fmt.Sprintf("filler%d", len(tr.known))] = &KnownIdentity{LastSeen: time.Now()}
	}
	tr.mu.Unlock()

	newID, newPkt := makePinTestAnnounce(t)
	tr.handleAnnounce(newPkt)
	if tr.Recall(newID.DestinationHashFor(FullName("lxmf", "delivery"))) == nil {
		t.Error("new peer could not be admitted; pinning wedged the cache")
	}
}

// TestPinReleaseOnRemoval: re-asserting the set without a peer releases
// it, which is how membership loss (leave/kick/prune) unpins.
func TestPinReleaseOnRemoval(t *testing.T) {
	tr := NewTransport(nil)
	id, pkt := makePinTestAnnounce(t)
	tr.handleAnnounce(pkt)
	dest := id.DestinationHashFor(FullName("lxmf", "delivery"))

	tr.PinDestinations([][]byte{dest})
	if tr.PinnedCount() != 1 {
		t.Fatal("pin not applied")
	}
	tr.PinDestinations(nil) // peer left the roster
	if tr.PinnedCount() != 0 {
		t.Error("pin not released when the set was re-asserted without it")
	}

	for i := 0; i < KnownIdentityCapacity+8; i++ {
		_, p := makePinTestAnnounce(t)
		tr.handleAnnounce(p)
	}
	if tr.Recall(dest) != nil {
		t.Error("released peer still protected from eviction")
	}
}

// announceLines returns the logged announce-verified lines for dest.
func announceLines(rec *recordingLeveledLogger, dest []byte) []string {
	var out []string
	needle := fmt.Sprintf("dest=%x ", dest[:4])
	for _, r := range rec.got {
		if strings.HasPrefix(r.line, "announce verified") && strings.Contains(r.line, needle) {
			out = append(out, r.line)
		}
	}
	return out
}

// TestEvictedPeerIsNotLoggedAsNew is the regression for the journal
// flood: on a hub with more peers than the identity cache holds, a peer
// evicted between its periodic announces was logged as
// `announce verified (new)` every time it came back.
func TestEvictedPeerIsNotLoggedAsNew(t *testing.T) {
	rec := &recordingLeveledLogger{}
	tr := NewTransport(rec)

	id, pkt := makePinTestAnnounce(t)
	dest := id.DestinationHashFor(FullName("lxmf", "delivery"))
	tr.handleAnnounce(pkt)
	if got := announceLines(rec, dest); len(got) != 1 || !strings.Contains(got[0], "(new)") {
		t.Fatalf("first announce logged %q, want one (new) line", got)
	}

	for i := 0; i < KnownIdentityCapacity+8; i++ {
		_, p := makePinTestAnnounce(t)
		tr.handleAnnounce(p)
	}
	if tr.Recall(dest) != nil {
		t.Fatal("peer was not evicted; the test is not exercising churn")
	}

	// Start from a clean log and an unspent rate limit, so an absent
	// line means "not logged", not "suppressed by the flood above".
	rec.got = nil
	tr.rlog.counters = map[string]*logCounter{}

	again, err := BuildAnnounce(id, FullName("lxmf", "delivery"), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	tr.handleAnnounce(again)
	if tr.Recall(dest) == nil {
		t.Fatal("returning peer was not re-cached")
	}
	if got := announceLines(rec, dest); len(got) != 0 {
		t.Errorf("evicted peer re-announcing on schedule logged %q, want nothing", got)
	}

	// After a long silence it is still reported, as returning.
	tr.mu.Lock()
	tr.known[hex.EncodeToString(dest)].LastSeen = time.Now().Add(-AnnounceLogReturnThreshold - time.Minute)
	tr.mu.Unlock()
	late, err := BuildAnnounce(id, FullName("lxmf", "delivery"), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	tr.handleAnnounce(late)
	if got := announceLines(rec, dest); len(got) != 1 || !strings.Contains(got[0], "(returning after") {
		t.Errorf("long-silent peer logged %q, want one (returning after …) line", got)
	}
}

// TestEvictedPeerReturningAfterSilence: the gap for an evicted peer comes
// from the heard record, so a long absence is still reported as a return
// rather than lost along with the cache entry.
func TestEvictedPeerReturningAfterSilence(t *testing.T) {
	rec := &recordingLeveledLogger{}
	tr := NewTransport(rec)
	id, _ := makePinTestAnnounce(t)
	dest := id.DestinationHashFor(FullName("lxmf", "delivery"))

	var key [IdentityHashLen]byte
	copy(key[:], dest)
	tr.mu.Lock()
	tr.heard[key] = time.Now().Add(-AnnounceLogReturnThreshold - time.Hour).Unix()
	tr.mu.Unlock()

	pkt, err := BuildAnnounce(id, FullName("lxmf", "delivery"), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	tr.handleAnnounce(pkt)
	if got := announceLines(rec, dest); len(got) != 1 || !strings.Contains(got[0], "(returning after") {
		t.Errorf("logged %q, want one (returning after …) line", got)
	}
}

// TestNewAnnounceLogIsRateLimited: fresh identities cost nothing to mint,
// so the (new) line must be capped regardless of how many arrive.
func TestNewAnnounceLogIsRateLimited(t *testing.T) {
	rec := &recordingLeveledLogger{}
	tr := NewTransport(rec)
	for i := 0; i < 50; i++ {
		_, p := makePinTestAnnounce(t)
		tr.handleAnnounce(p)
	}
	n := 0
	for _, r := range rec.got {
		if strings.HasPrefix(r.line, "announce verified (new)") {
			if r.level != LogInfo {
				t.Errorf("(new) line at %v, want info", r.level)
			}
			n++
		}
	}
	if n != defaultLogBurst {
		t.Errorf("50 fresh identities logged %d (new) lines, want the burst of %d", n, defaultLogBurst)
	}
}

// TestHeardRecordIsBounded: the heard record must not grow past
// AnnounceLogMemory however many identities announce.
func TestHeardRecordIsBounded(t *testing.T) {
	tr := NewTransport(nil)
	tr.mu.Lock()
	for i := 0; len(tr.heard) < AnnounceLogMemory; i++ {
		var k [IdentityHashLen]byte
		binary.BigEndian.PutUint64(k[:], uint64(i))
		tr.heard[k] = time.Now().Unix()
	}
	tr.mu.Unlock()

	id, pkt := makePinTestAnnounce(t)
	tr.handleAnnounce(pkt)

	var key [IdentityHashLen]byte
	copy(key[:], id.DestinationHashFor(FullName("lxmf", "delivery")))
	tr.mu.RLock()
	defer tr.mu.RUnlock()
	if len(tr.heard) != AnnounceLogMemory {
		t.Errorf("heard holds %d entries, want exactly the cap %d", len(tr.heard), AnnounceLogMemory)
	}
	if _, ok := tr.heard[key]; !ok {
		t.Error("newly heard peer was not recorded when the record was full")
	}
}
