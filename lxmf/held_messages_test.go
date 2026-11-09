package lxmf

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/thatSFguy/reticulum-go/rns"
)

type heldFixture struct {
	t         *testing.T
	transport *rns.Transport
	delivery  *Delivery
	sender    *rns.Identity
	mu        sync.Mutex
	got       []string
	errs      []string
}

func newHeldFixture(t *testing.T) *heldFixture {
	t.Helper()
	id, _ := rns.NewIdentity()
	sender, _ := rns.NewIdentity()
	f := &heldFixture{t: t, transport: rns.NewTransport(nil), sender: sender}
	d, err := NewDelivery(f.transport, id, nil)
	if err != nil {
		t.Fatal(err)
	}
	f.delivery = d
	d.OnMessage = func(m *Message) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.got = append(f.got, string(m.Content))
	}
	d.OnError = func(err error) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.errs = append(f.errs, err.Error())
	}
	return f
}

func (f *heldFixture) senderHash() []byte { return f.sender.DestinationHashFor(FullName()) }

func (f *heldFixture) body(text string) []byte {
	f.t.Helper()
	wire, _, err := SignAndPackDirect(f.sender, f.senderHash(), f.delivery.Hash(), nil, []byte(text), nil)
	if err != nil {
		f.t.Fatal(err)
	}
	return wire
}

// announce makes the sender's key known and fires the release handler,
// the same order the transport uses.
func (f *heldFixture) announce() {
	f.transport.Restore(&rns.KnownIdentity{
		DestHash:  f.senderHash(),
		PublicKey: f.sender.PublicKey(),
		NameHash:  rns.NameHash(FullName()),
	})
	h := &heldReleaseHandler{d: f.delivery, nameHash: rns.NameHash(FullName())}
	h.OnAnnounce(&rns.Announce{DestHash: f.senderHash()})
}

func (f *heldFixture) received() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.got...)
}

func (f *heldFixture) waitReceived(n int) []string {
	f.t.Helper()
	if !waitFor(time.Second, func() bool { return len(f.received()) >= n }) {
		f.t.Fatalf("got %d messages, want %d", len(f.received()), n)
	}
	return f.received()
}

func (f *heldFixture) heldCount() int {
	f.delivery.held.mu.Lock()
	defer f.delivery.held.mu.Unlock()
	return f.delivery.held.count
}

func TestUnknownSenderIsDeliveredWhenItsAnnounceArrives(t *testing.T) {
	alice, _ := rns.NewIdentity()
	bob, _ := rns.NewIdentity()
	aIface, bIface, stop := pairedInterfaces()
	defer stop()
	tA := rns.NewTransport(nil)
	tA.AddInterface(aIface)
	tB := rns.NewTransport(nil)
	tB.AddInterface(bIface)
	delA, err := NewDelivery(tA, alice, nil)
	if err != nil {
		t.Fatal(err)
	}
	delB, err := NewDelivery(tB, bob, nil)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var got []string
	delB.OnMessage = func(m *Message) {
		mu.Lock()
		defer mu.Unlock()
		got = append(got, string(m.Content))
	}
	count := func() int {
		mu.Lock()
		defer mu.Unlock()
		return len(got)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go tA.Run(ctx)
	go tB.Run(ctx)

	announce := func(tr *rns.Transport, id *rns.Identity) {
		appData, _ := rns.EncodeLXMFAppData([]byte(""), nil)
		pkt, err := rns.BuildAnnounce(id, FullName(), appData, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := tr.Broadcast(pkt); err != nil {
			t.Fatal(err)
		}
	}
	// Alice learns Bob, but Bob has never heard of Alice.
	announce(tB, bob)
	if !waitFor(time.Second, func() bool { return tA.Recall(delB.Hash()) != nil }) {
		t.Fatal("alice never learned bob")
	}
	if err := delA.Send(delB.Hash(), nil, []byte("hello"), nil); err != nil {
		t.Fatalf("send should get a delivery proof: %v", err)
	}
	time.Sleep(50 * time.Millisecond)
	if count() != 0 {
		t.Fatal("delivered before the sender could be verified")
	}

	announce(tA, alice)
	if !waitFor(time.Second, func() bool { return count() == 1 }) {
		t.Fatal("held message was not delivered after the announce")
	}
}

func TestHeldLinkMessageSurvivesCallerReusingItsBuffer(t *testing.T) {
	f := newHeldFixture(t)
	wire := f.body("hello")
	f.delivery.handleInboundLinkPlaintext(wire)
	for i := range wire {
		wire[i] = 0
	}
	f.announce()
	if got := f.waitReceived(1); got[0] != "hello" {
		t.Fatalf("got %q", got[0])
	}
}

func TestAllHeldMessagesAreReleased(t *testing.T) {
	f := newHeldFixture(t)
	for _, text := range []string{"one", "two", "three"} {
		f.delivery.handleInboundLinkPlaintext(f.body(text))
	}
	f.announce()
	// Not ordered: dispatchInbound runs each OnMessage on its own goroutine.
	got := f.waitReceived(3)
	sort.Strings(got)
	if fmt.Sprint(got) != "[one three two]" {
		t.Fatalf("got %v", got)
	}
	if f.heldCount() != 0 {
		t.Fatalf("%d still held", f.heldCount())
	}
}

func TestAnotherSendersAnnounceDoesNotRelease(t *testing.T) {
	f := newHeldFixture(t)
	f.delivery.handleInboundLinkPlaintext(f.body("hello"))
	other, _ := rns.NewIdentity()
	h := &heldReleaseHandler{d: f.delivery, nameHash: rns.NameHash(FullName())}
	h.OnAnnounce(&rns.Announce{DestHash: other.DestinationHashFor(FullName())})
	time.Sleep(20 * time.Millisecond)
	if len(f.received()) != 0 || f.heldCount() != 1 {
		t.Fatalf("received %v, held %d", f.received(), f.heldCount())
	}
}

func TestHeldMessageWithBadSignatureIsNotDelivered(t *testing.T) {
	f := newHeldFixture(t)
	wire := f.body("hello")
	wire[2*rns.IdentityHashLen] ^= 0xff // first signature byte
	f.delivery.handleInboundLinkPlaintext(wire)
	f.announce()
	if !waitFor(time.Second, func() bool {
		f.mu.Lock()
		defer f.mu.Unlock()
		return strings.Contains(strings.Join(f.errs, "\n"), "verify")
	}) {
		t.Fatalf("verify failure was not reported; delivered %v", f.received())
	}
	time.Sleep(20 * time.Millisecond)
	if len(f.received()) != 0 {
		t.Fatalf("forged message delivered: %v", f.received())
	}
}

func TestMessageForSomeoneElseIsNotHeld(t *testing.T) {
	f := newHeldFixture(t)
	other, _ := rns.NewIdentity()
	wire, _, err := SignAndPackDirect(f.sender, f.senderHash(), other.DestinationHashFor(FullName()), nil, []byte("x"), nil)
	if err != nil {
		t.Fatal(err)
	}
	f.delivery.handleInboundLinkPlaintext(wire)
	if f.heldCount() != 0 {
		t.Fatal("held a message addressed to someone else")
	}
}

func TestDuplicateIsHeldOnce(t *testing.T) {
	f := newHeldFixture(t)
	wire := f.body("hello")
	f.delivery.handleInboundLinkPlaintext(wire)
	f.delivery.handleInboundLinkPlaintext(wire)
	if f.heldCount() != 1 {
		t.Fatalf("held %d copies", f.heldCount())
	}
}

func TestExpiredMessageIsDropped(t *testing.T) {
	f := newHeldFixture(t)
	now := time.Now()
	f.delivery.held.now = func() time.Time { return now }
	f.delivery.handleInboundLinkPlaintext(f.body("hello"))
	now = now.Add(HeldMessageTTL - time.Second)
	f.delivery.expireHeld()
	if f.heldCount() != 1 {
		t.Fatal("expired too early")
	}
	now = now.Add(2 * time.Second)
	f.delivery.expireHeld()
	if f.heldCount() != 0 {
		t.Fatal("not expired after the TTL")
	}
	f.announce()
	time.Sleep(20 * time.Millisecond)
	if len(f.received()) != 0 {
		t.Fatalf("delivered after expiry: %v", f.received())
	}
}

func TestOneSenderCannotHoldMoreThanItsShare(t *testing.T) {
	f := newHeldFixture(t)
	for i := 0; i < MaxHeldMessagesPerSender+3; i++ {
		f.delivery.handleInboundLinkPlaintext(f.body(fmt.Sprintf("m%d", i)))
	}
	if f.heldCount() != MaxHeldMessagesPerSender {
		t.Fatalf("held %d", f.heldCount())
	}
}

func heldTestMessage(i int) *Message {
	source := make([]byte, rns.IdentityHashLen)
	source[0], source[1] = byte(i), byte(i>>8)
	return &Message{SourceHash: source, Content: []byte{byte(i), byte(i >> 8)}}
}

func TestHoldRefusesNewMessagesWhenFull(t *testing.T) {
	h := newHeldMessages()
	for i := 0; i < MaxHeldMessages; i++ {
		if r := h.add(heldTestMessage(i), 1, ""); r != holdAdded {
			t.Fatalf("message %d: %v", i, r)
		}
	}
	if r := h.add(heldTestMessage(MaxHeldMessages), 1, ""); r != holdFull {
		t.Fatalf("got %v", r)
	}
	if drainHeld(h, heldTestMessage(0).SourceHash) != 1 {
		t.Fatal("a flood must not displace a waiting message")
	}
	if r := h.add(heldTestMessage(MaxHeldMessages), 1, ""); r != holdAdded {
		t.Fatalf("taking a message should free a slot: %v", r)
	}
}

func TestHoldEnforcesItsByteLimit(t *testing.T) {
	h := newHeldMessages()
	if r := h.add(heldTestMessage(1), MaxHeldBytes, ""); r != holdAdded {
		t.Fatalf("got %v", r)
	}
	if r := h.add(heldTestMessage(2), 1, ""); r != holdFull {
		t.Fatalf("got %v", r)
	}
	drainHeld(h, heldTestMessage(1).SourceHash)
	if h.bytes != 0 || h.count != 0 {
		t.Fatalf("bytes %d count %d", h.bytes, h.count)
	}
}

// Announces can arrive far faster than messages can be verified, so a
// released message has to keep its place in the caps until it is picked up.
func TestReleasedMessagesStayCountedUntilPickedUp(t *testing.T) {
	h := newHeldMessages()
	if r := h.add(heldTestMessage(1), MaxHeldBytes, ""); r != holdAdded {
		t.Fatalf("got %v", r)
	}
	if !h.release(heldTestMessage(1).SourceHash, nil) {
		t.Fatal("the first release must start a worker")
	}
	if r := h.add(heldTestMessage(2), 1, ""); r != holdFull {
		t.Fatalf("released message stopped counting: %v", r)
	}
	if _, ok := h.next(); !ok {
		t.Fatal("released message was not queued")
	}
	if r := h.add(heldTestMessage(2), 1, ""); r != holdAdded {
		t.Fatalf("picking up a message should free its space: %v", r)
	}
}

func TestReleaseStartsOneWorker(t *testing.T) {
	h := newHeldMessages()
	h.add(heldTestMessage(1), 1, "")
	h.add(heldTestMessage(2), 1, "")
	if !h.release(heldTestMessage(1).SourceHash, nil) {
		t.Fatal("the first release must start a worker")
	}
	if h.release(heldTestMessage(2).SourceHash, nil) {
		t.Fatal("a second worker would make release validation concurrent")
	}
	for i := 0; i < 2; i++ {
		if _, ok := h.next(); !ok {
			t.Fatalf("message %d was not queued", i)
		}
	}
	if _, ok := h.next(); ok {
		t.Fatal("queue should be empty")
	}
	h.add(heldTestMessage(3), 1, "")
	if !h.release(heldTestMessage(3).SourceHash, nil) {
		t.Fatal("a release after the worker exits must start a new one")
	}
}

// A release must never shed: validation fails open once the shared slots are
// exhausted, so a burst of releases from fresh identities would otherwise
// walk under-stamped messages straight past EnforceStamps.
func TestReleasedMessagesAreValidatedWhenSlotsAreFull(t *testing.T) {
	const n = 3
	for i := 0; i < MaxConcurrentStampValidations; i++ {
		stampValidationSlots <- struct{}{}
	}
	defer func() {
		for i := 0; i < MaxConcurrentStampValidations; i++ {
			<-stampValidationSlots
		}
	}()
	f := newHeldFixture(t)
	// Cost 1 stamps clear 32 bits about once in 2^31 messages, so these
	// always fail on their merits.
	f.delivery.InboundStampCost = 32
	f.delivery.EnforceStamps = true

	senders := make([]*rns.Identity, n)
	for i := range senders {
		s, _ := rns.NewIdentity()
		senders[i] = s
		wire, _, err := SignAndPackDirectStamped(s, s.DestinationHashFor(FullName()), f.delivery.Hash(),
			nil, []byte("flood"), nil, StampOptions{Cost: 1})
		if err != nil {
			t.Fatal(err)
		}
		f.delivery.handleInboundLinkPlaintext(wire)
	}

	h := &heldReleaseHandler{d: f.delivery, nameHash: rns.NameHash(FullName())}
	for _, s := range senders {
		dest := s.DestinationHashFor(FullName())
		f.transport.Restore(&rns.KnownIdentity{DestHash: dest, PublicKey: s.PublicKey(), NameHash: rns.NameHash(FullName())})
		h.OnAnnounce(&rns.Announce{DestHash: dest})
	}

	dropped := func() int {
		f.mu.Lock()
		defer f.mu.Unlock()
		return strings.Count(strings.Join(f.errs, "\n"), "dropping message from")
	}
	if !waitFor(time.Minute, func() bool { return len(f.received())+dropped() == n }) {
		t.Fatalf("delivered %d, dropped %d, want %d settled", len(f.received()), dropped(), n)
	}
	if got := len(f.received()); got != 0 {
		t.Fatalf("%d under-stamped messages delivered with EnforceStamps on", got)
	}
}

// sendCounter is an Interface that only counts what is sent through it.
type sendCounter struct{ sends atomic.Int32 }

func (c *sendCounter) Send([]byte) error     { c.sends.Add(1); return nil }
func (c *sendCounter) Inbox() <-chan []byte  { return nil }
func (c *sendCounter) Done() <-chan struct{} { return nil }
func (c *sendCounter) count() int            { return int(c.sends.Load()) }

func TestHeldMessageRetriesItsPathRequestOnce(t *testing.T) {
	f := newHeldFixture(t)
	iface := &sendCounter{}
	f.transport.AddInterface(iface)
	f.delivery.held.retry = 20 * time.Millisecond
	f.delivery.handleInboundLinkPlaintext(f.body("hello"))
	if !waitFor(time.Second, func() bool { return iface.count() == 2 }) {
		t.Fatalf("%d path requests, want the original and one retry", iface.count())
	}
	time.Sleep(80 * time.Millisecond)
	if iface.count() != 2 {
		t.Fatalf("%d path requests, want exactly one retry", iface.count())
	}
}

func TestReleasedMessageDoesNotRetryItsPathRequest(t *testing.T) {
	f := newHeldFixture(t)
	iface := &sendCounter{}
	f.transport.AddInterface(iface)
	f.delivery.held.retry = 40 * time.Millisecond
	f.delivery.handleInboundLinkPlaintext(f.body("hello"))
	f.announce()
	f.waitReceived(1)
	time.Sleep(100 * time.Millisecond)
	if iface.count() != 1 {
		t.Fatalf("%d path requests after the key arrived, want 1", iface.count())
	}
}

// Covers an announce landing between the caller's Recall and the hold, which
// no later announce would release.
func TestMessageIsReleasedIfTheKeyArrivedWhileHolding(t *testing.T) {
	f := newHeldFixture(t)
	msg, err := ParseDirectBody(f.body("hello"))
	if err != nil {
		t.Fatal(err)
	}
	f.transport.Restore(&rns.KnownIdentity{
		DestHash:  f.senderHash(),
		PublicKey: f.sender.PublicKey(),
		NameHash:  rns.NameHash(FullName()),
	})
	f.delivery.holdUnknownSender(msg, 1, "link ")
	f.waitReceived(1)
}

func TestHeldOpportunisticMessageSurvivesPacketReuse(t *testing.T) {
	f := newHeldFixture(t)
	body, _, err := SignAndPackOpportunistic(f.sender, f.senderHash(), f.delivery.Hash(), nil, []byte("hello"), nil)
	if err != nil {
		t.Fatal(err)
	}
	id := f.delivery.Identity()
	ct, err := rns.TokenEncrypt(body, id.X25519Public(), identityHashFromPublic(id.PublicKey()))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := buildOutboundPacket(f.delivery.Hash(), ct, nil).Pack()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := rns.ParsePacket(raw)
	if err != nil {
		t.Fatal(err)
	}
	f.delivery.handleInbound(parsed)
	if f.heldCount() != 1 {
		t.Fatalf("held %d, want 1", f.heldCount())
	}
	for i := range parsed.DestHash {
		parsed.DestHash[i] = 0
	}
	for i := range raw {
		raw[i] = 0
	}
	f.announce()
	if got := f.waitReceived(1); got[0] != "hello" {
		t.Fatalf("got %q", got[0])
	}
}

func drainHeld(h *heldMessages, sender []byte) int {
	h.release(sender, nil)
	drained := 0
	for {
		if _, ok := h.next(); !ok {
			return drained
		}
		drained++
	}
}
