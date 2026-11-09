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

	// HeldPathRetryInterval is how long a held message waits before asking
	// for its sender's path again, and the minimum gap between requests for
	// one sender while messages are held. It matches upstream's
	// PATH_REQUEST_MI, the shortest interval at which RNS repeats a path
	// request itself, and leaves one retry inside HeldMessageTTL.
	HeldPathRetryInterval = 20 * time.Second
)

type heldMessage struct {
	msg    *Message
	label  string // log prefix: "" for opportunistic, "link " for direct
	size   int
	heldAt time.Time
	known  *rns.KnownIdentity // set on release
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
	ready    []heldMessage // released, waiting for the release worker
	draining bool          // a release worker is running
	count    int           // includes ready
	bytes    int           // includes ready
	ttl      time.Duration
	retry    time.Duration
	now      func() time.Time
}

func newHeldMessages() *heldMessages {
	return &heldMessages{
		bySender: make(map[string][]heldMessage),
		ttl:      HeldMessageTTL,
		retry:    HeldPathRetryInterval,
		now:      time.Now,
	}
}

func (h *heldMessages) add(msg *Message, size int, label string) holdResult {
	h.mu.Lock()
	defer h.mu.Unlock()
	key := hex.EncodeToString(msg.SourceHash)
	queue := h.bySender[key]
	// DedupKey is only trustworthy after Verify, but a forged twin would
	// need the signature of a message that travels encrypted to us.
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

// release moves everything held for sender onto the ready queue and reports
// whether the caller must start a worker to drain it. Released messages stay
// counted against the caps until next hands them out: verifying one can take
// far longer than an announce takes to arrive, so without that the queue
// would be unbounded.
func (h *heldMessages) release(sender []byte, known *rns.KnownIdentity) (startWorker bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	key := hex.EncodeToString(sender)
	queue := h.bySender[key]
	if len(queue) == 0 {
		return false
	}
	delete(h.bySender, key)
	for _, held := range queue {
		held.known = known
		h.ready = append(h.ready, held)
	}
	if h.draining {
		return false
	}
	h.draining = true
	return true
}

// waiting reports whether anything is still held for sender.
func (h *heldMessages) waiting(sender []byte) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.bySender[hex.EncodeToString(sender)]) > 0
}

// next hands the release worker its next message. When it returns false the
// worker must exit; a later release starts a new one.
func (h *heldMessages) next() (heldMessage, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.ready) == 0 {
		h.ready = nil
		h.draining = false
		return heldMessage{}, false
	}
	held := h.ready[0]
	h.ready[0] = heldMessage{} // don't pin the body through the backing array
	h.ready = h.ready[1:]
	h.count--
	h.bytes -= held.size
	return held, true
}

// expire removes and returns everything past its TTL. Released messages are
// not affected: their key has arrived and they are only waiting their turn.
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
	result := d.held.add(msg, size, label)
	switch result {
	case holdFull:
		d.errorf("%ssender %x unknown — hold is full, message dropped", label, msg.SourceHash[:4])
	case holdDuplicate:
		// Already waiting; the path request below is rate limited.
	case holdAdded:
		d.errorf("%ssender %x unknown — holding message for its announce", label, msg.SourceHash[:4])
		time.AfterFunc(d.held.ttl+time.Millisecond, d.expireHeld)
	}
	d.requestHeldPath(msg.SourceHash)
	if result == holdAdded {
		// Scheduled after the request above: started any earlier, the
		// retry would land just inside the interval and be suppressed.
		sender := msg.SourceHash
		time.AfterFunc(d.held.retry, func() {
			if d.held.waiting(sender) {
				d.requestHeldPath(sender)
			}
		})
	}
	// The announce may have landed between the caller's Recall and the
	// add above, in which case no later announce would release this.
	if d.transport.Recall(msg.SourceHash) != nil {
		d.releaseHeld(msg.SourceHash)
	}
}

// requestHeldPath asks for a held sender's path. A message can only wait
// for HeldMessageTTL, so it can't use RequestPath's longer default window:
// one lost request or response would outlast the message.
func (d *Delivery) requestHeldPath(sender []byte) {
	if err := d.transport.RequestPathAfter(sender, d.held.retry); err != nil {
		d.errorf("path? request: %w", err)
	}
}

func (d *Delivery) expireHeld() {
	for _, held := range d.held.expire() {
		d.errorf("%ssender %x never announced — held message dropped", held.label, held.msg.SourceHash[:4])
	}
}

// releaseHeld queues whatever was waiting for sender for verification and
// delivery. It runs from the announce handler on the dispatcher goroutine,
// and stamp validation is expensive, so the work moves off that goroutine.
//
// It moves to exactly one worker, never one goroutine per release. When
// MaxConcurrentStampValidations is exhausted, validation fails OPEN even
// under EnforceStamps (SPEC §5.7.4 policy, see validateInboundStamp).
// Holding messages from many fresh identities and then announcing them all
// in a burst would saturate that cap with one goroutine per release, and the
// per-sender failure budget cannot help because each identity is new.
func (d *Delivery) releaseHeld(sender []byte) {
	known := d.transport.Recall(sender)
	if known == nil {
		return
	}
	if d.held.release(sender, known) {
		go d.drainReleased()
	}
}

// drainReleased skips the concurrency slots because, as the only worker, it
// adds at most one validation per Delivery. The slots are shared across the
// process and shed fail-open, so taking one here could only let a burst of
// releases cost some other message its check, or lose this one its own.
func (d *Delivery) drainReleased() {
	for {
		held, ok := d.held.next()
		if !ok {
			return
		}
		d.verifyAndDispatch(held.msg, held.known, held.label, d.checkInboundStamp)
	}
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
