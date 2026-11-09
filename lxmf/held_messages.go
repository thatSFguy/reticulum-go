package lxmf

import (
	"bytes"
	"encoding/hex"
	"sync"
	"time"

	"github.com/thatSFguy/reticulum-go/rns"
)

// A message from a sender whose key we don't hold cannot be verified, but
// the sender has already received a delivery proof and will not retry.
// The key is usually one path? request away, so the message waits here
// until the sender's announce arrives instead of being lost.
//
// Everything held is unauthenticated, and anyone can send it with any
// source hash, so the limits below are what keep this from being a way to
// fill our memory. A full hold refuses new messages rather than evicting
// old ones, so a flood cannot push out a message that is already waiting.
const (
	// HeldMessageTTL is how long a message waits for its sender's key.
	// A path response normally takes about a second; this leaves room for
	// slow links without keeping unauthenticated data around for long.
	HeldMessageTTL = 30 * time.Second

	// MaxHeldMessages caps messages held across all senders.
	MaxHeldMessages = 256

	// MaxHeldMessagesPerSender caps messages held for one source hash.
	MaxHeldMessagesPerSender = 4

	// MaxHeldBytes caps the total size of held message bodies.
	MaxHeldBytes = 2 << 20
)

type heldMessage struct {
	msg    *Message
	label  string // log prefix: "" for opportunistic, "link " for direct
	size   int
	heldAt time.Time
}

type holdResult int

const (
	holdAdded holdResult = iota
	holdDuplicate
	holdFull
)

type heldMessages struct {
	mu       sync.Mutex
	bySender map[string][]heldMessage
	count    int
	bytes    int
	ttl      time.Duration
	now      func() time.Time
}

func newHeldMessages() *heldMessages {
	return &heldMessages{
		bySender: make(map[string][]heldMessage),
		ttl:      HeldMessageTTL,
		now:      time.Now,
	}
}

func (h *heldMessages) add(msg *Message, size int, label string) holdResult {
	h.mu.Lock()
	defer h.mu.Unlock()
	key := hex.EncodeToString(msg.SourceHash)
	queue := h.bySender[key]
	dedup := msg.DedupKey()
	for _, held := range queue {
		if dedup != nil && bytes.Equal(held.msg.DedupKey(), dedup) {
			return holdDuplicate
		}
	}
	if len(queue) >= MaxHeldMessagesPerSender ||
		h.count >= MaxHeldMessages ||
		h.bytes+size > MaxHeldBytes {
		return holdFull
	}
	h.bySender[key] = append(queue, heldMessage{msg: msg, label: label, size: size, heldAt: h.now()})
	h.count++
	h.bytes += size
	return holdAdded
}

// take removes and returns everything held for sender.
func (h *heldMessages) take(sender []byte) []heldMessage {
	h.mu.Lock()
	defer h.mu.Unlock()
	key := hex.EncodeToString(sender)
	queue := h.bySender[key]
	delete(h.bySender, key)
	for _, held := range queue {
		h.count--
		h.bytes -= held.size
	}
	return queue
}

// expire removes and returns everything past its TTL.
func (h *heldMessages) expire() []heldMessage {
	h.mu.Lock()
	defer h.mu.Unlock()
	cutoff := h.now().Add(-h.ttl)
	var expired []heldMessage
	for key, queue := range h.bySender {
		kept := queue[:0:0]
		for _, held := range queue {
			if held.heldAt.After(cutoff) {
				kept = append(kept, held)
				continue
			}
			expired = append(expired, held)
			h.count--
			h.bytes -= held.size
		}
		if len(kept) == 0 {
			delete(h.bySender, key)
		} else {
			h.bySender[key] = kept
		}
	}
	return expired
}

// holdUnknownSender keeps msg until its sender's announce arrives and asks
// the network for that announce.
func (d *Delivery) holdUnknownSender(msg *Message, size int, label string) {
	switch d.held.add(msg, size, label) {
	case holdFull:
		d.errorf("%ssender %x unknown — hold is full, message dropped", label, msg.SourceHash[:4])
	case holdDuplicate:
		// Already waiting; the path request below is rate limited.
	case holdAdded:
		d.errorf("%ssender %x unknown — holding message for its announce", label, msg.SourceHash[:4])
		time.AfterFunc(d.held.ttl+time.Millisecond, d.expireHeld)
	}
	if err := d.transport.RequestPath(msg.SourceHash); err != nil {
		d.errorf("path? request: %w", err)
	}
	// The announce may have landed between the caller's Recall and the
	// add above, in which case no later announce would release this.
	if d.transport.Recall(msg.SourceHash) != nil {
		d.releaseHeld(msg.SourceHash)
	}
}

func (d *Delivery) expireHeld() {
	for _, held := range d.held.expire() {
		d.errorf("%ssender %x never announced — held message dropped", held.label, held.msg.SourceHash[:4])
	}
}

// releaseHeld verifies and delivers whatever was waiting for sender. It
// runs from the announce handler on the dispatcher goroutine, and stamp
// validation is expensive, so the work moves off that goroutine; the
// per-sender cap bounds it.
func (d *Delivery) releaseHeld(sender []byte) {
	waiting := d.held.take(sender)
	if len(waiting) == 0 {
		return
	}
	known := d.transport.Recall(sender)
	if known == nil {
		return
	}
	go func() {
		for _, held := range waiting {
			d.verifyAndDispatch(held.msg, known, held.label)
		}
	}()
}

// heldReleaseHandler releases held messages when a verified lxmf.delivery
// announce arrives. The transport has already checked that the announced
// key hashes to DestHash, so a forged announce cannot supply a key.
type heldReleaseHandler struct {
	d        *Delivery
	nameHash []byte
}

func (h *heldReleaseHandler) AspectMatch(nameHash []byte) bool {
	return bytes.Equal(nameHash, h.nameHash)
}

func (h *heldReleaseHandler) OnAnnounce(a *rns.Announce) { h.d.releaseHeld(a.DestHash) }
