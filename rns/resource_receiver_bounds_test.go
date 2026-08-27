package rns

import (
	"bytes"
	"errors"
	"testing"
)

// makeBoundedReceiver builds a receiver whose hashmap actually matches
// the supplied parts, so placePart finds a slot for each, and whose ADV
// promised expectedSize bytes.
func makeBoundedReceiver(t *testing.T, parts [][]byte, expectedSize int) *ResourceReceiver {
	t.Helper()
	link, tp, _ := makeActiveTestLink(t)

	// ResourceMapHash returns a zero hash for a wrong-length random_hash,
	// which would make every part collide — the map_hash r is 4 bytes
	// (SPEC §10.2 step 5).
	randomR := bytes.Repeat([]byte{0xEE}, ResourceRandomHashSize)
	hashmap := make([]byte, 0, len(parts)*ResourceMapHashLen)
	for _, p := range parts {
		hashmap = append(hashmap, ResourceMapHash(p, randomR)...)
	}
	rr := &ResourceReceiver{
		transport:          tp,
		link:               link,
		logger:             noopLogger{},
		resourceHash:       bytes.Repeat([]byte{0xCD}, 32),
		randomR:            randomR,
		expectedSize:       expectedSize,
		hashmap:            hashmap,
		hashmapKnownPrefix: len(parts),
		consecutiveHeight:  -1,
		parts:              make([][]byte, len(parts)),
		receivedFlags:      make([]bool, len(parts)),
		partCh:             make(chan []byte, 32),
		cancelCh:           make(chan struct{}, 1),
		hmuCh:              make(chan *ResourceHmu, 4),
		done:               make(chan struct{}),
		linkSigning:        append([]byte(nil), link.Signing...),
		linkEncryption:     append([]byte(nil), link.Encryption...),
	}
	rr.state.Store(int32(ResourceStateTransferring))
	return rr
}

func buffered(rr *ResourceReceiver) int {
	rr.mu.Lock()
	defer rr.mu.Unlock()
	n := 0
	for _, p := range rr.parts {
		n += len(p)
	}
	return n
}

// A legitimate part is one SDU-sized slice of the encrypted body (SPEC
// §10.2 step 6). A larger one is malformed or hostile, and must be
// refused before it is buffered — ParseResourceAdv bounds how MANY
// parts a transfer may have, so without this the per-part size is the
// one term in the memory budget nothing checks.
func TestPlacePartRejectsAnOversizePart(t *testing.T) {
	good := bytes.Repeat([]byte{0x01}, ResourceSDU)
	rr := makeBoundedReceiver(t, [][]byte{good}, ResourceSDU)

	oversize := bytes.Repeat([]byte{0x02}, ResourceSDU+1)
	err := rr.placePart(oversize)
	if !errors.Is(err, errResourcePartOversize) {
		t.Fatalf("placePart(%d bytes) = %v, want errResourcePartOversize", len(oversize), err)
	}
	if got := buffered(rr); got != 0 {
		t.Errorf("%d bytes buffered after rejecting an oversize part", got)
	}
}

// assemble() already rejects a transfer whose total does not match the
// advertisement, but only once every part is buffered. A sender that
// keeps feeding parts is otherwise paid for in memory first and
// rejected second.
func TestPlacePartRejectsPartsPastTheAdvertisedSize(t *testing.T) {
	partA := bytes.Repeat([]byte{0x0A}, 100)
	partB := bytes.Repeat([]byte{0x0B}, 100)
	// The ADV promised room for one of them, not both.
	rr := makeBoundedReceiver(t, [][]byte{partA, partB}, 100)

	if err := rr.placePart(partA); err != nil {
		t.Fatalf("first part rejected: %v", err)
	}
	err := rr.placePart(partB)
	if !errors.Is(err, errResourceOverAdvertisedSize) {
		t.Fatalf("second part = %v, want errResourceOverAdvertisedSize", err)
	}
	if got, want := buffered(rr), 100; got != want {
		t.Errorf("%d bytes buffered, want %d — the over-cap part was kept", got, want)
	}
}

// The bound must not reject a transfer that exactly fills what it
// advertised, which is the ordinary case.
func TestPlacePartAcceptsATransferThatExactlyFits(t *testing.T) {
	partA := bytes.Repeat([]byte{0x0A}, 100)
	partB := bytes.Repeat([]byte{0x0B}, 60)
	rr := makeBoundedReceiver(t, [][]byte{partA, partB}, 160)

	if err := rr.placePart(partA); err != nil {
		t.Fatalf("first part: %v", err)
	}
	if err := rr.placePart(partB); err != nil {
		t.Fatalf("second part: %v", err)
	}
	if got, want := buffered(rr), 160; got != want {
		t.Errorf("buffered %d bytes, want %d", got, want)
	}
}

// A retransmit must not be counted twice — otherwise a lossy link,
// where retransmits are routine, would trip the cumulative bound on a
// perfectly good transfer.
func TestADuplicatePartDoesNotConsumeTheBudget(t *testing.T) {
	partA := bytes.Repeat([]byte{0x0A}, 100)
	partB := bytes.Repeat([]byte{0x0B}, 60)
	rr := makeBoundedReceiver(t, [][]byte{partA, partB}, 160)

	if err := rr.placePart(partA); err != nil {
		t.Fatalf("first part: %v", err)
	}
	if err := rr.placePart(partA); !errors.Is(err, errResourceDuplicatePart) {
		t.Fatalf("retransmit = %v, want errResourceDuplicatePart", err)
	}
	if err := rr.placePart(partB); err != nil {
		t.Errorf("a retransmit consumed budget the real part needed: %v", err)
	}
}
