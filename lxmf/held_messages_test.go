package lxmf

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
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
	if len(h.take(heldTestMessage(0).SourceHash)) != 1 {
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
	h.take(heldTestMessage(1).SourceHash)
	if h.bytes != 0 || h.count != 0 {
		t.Fatalf("bytes %d count %d", h.bytes, h.count)
	}
}
