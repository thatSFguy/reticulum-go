package rns

import (
	"bytes"
	"testing"
	"time"
)

func segAdv(t *testing.T, original []byte, index, total int) *ResourceAdvertisement {
	t.Helper()
	return &ResourceAdvertisement{
		OriginalHash:  original,
		SegmentIndex:  index,
		TotalSegments: total,
	}
}

// Segments are held until the last one lands. Handing up a segment on
// its own would give the application a truncated body it cannot tell
// apart from a complete one.
func TestSegmentAssemblyWaitsForEverySegment(t *testing.T) {
	s := newSegmentAssembler()
	link := bytes.Repeat([]byte{0x01}, IdentityHashLen)
	orig := bytes.Repeat([]byte{0xAA}, 32)
	now := time.Now()

	whole, err := s.add(link, segAdv(t, orig, 1, 3), []byte("aaa"), now)
	if err != nil || whole != nil {
		t.Fatalf("segment 1 = (%q, %v), want (nil, nil)", whole, err)
	}
	whole, err = s.add(link, segAdv(t, orig, 2, 3), []byte("bbb"), now)
	if err != nil || whole != nil {
		t.Fatalf("segment 2 = (%q, %v), want (nil, nil)", whole, err)
	}
	whole, err = s.add(link, segAdv(t, orig, 3, 3), []byte("ccc"), now)
	if err != nil {
		t.Fatalf("segment 3: %v", err)
	}
	if string(whole) != "aaabbbccc" {
		t.Errorf("assembled %q, want aaabbbccc", whole)
	}
	if s.pending() != 0 {
		t.Error("the completed assembly was not released")
	}
}

// Upstream sends segments in order, but trusting that would turn a
// reordering peer into silent corruption. Order is by `i`, not arrival.
func TestSegmentAssemblyOrdersByIndexNotArrival(t *testing.T) {
	s := newSegmentAssembler()
	link := bytes.Repeat([]byte{0x02}, IdentityHashLen)
	orig := bytes.Repeat([]byte{0xBB}, 32)
	now := time.Now()

	if _, err := s.add(link, segAdv(t, orig, 3, 3), []byte("ccc"), now); err != nil {
		t.Fatal(err)
	}
	if _, err := s.add(link, segAdv(t, orig, 1, 3), []byte("aaa"), now); err != nil {
		t.Fatal(err)
	}
	whole, err := s.add(link, segAdv(t, orig, 2, 3), []byte("bbb"), now)
	if err != nil {
		t.Fatal(err)
	}
	if string(whole) != "aaabbbccc" {
		t.Errorf("assembled %q in arrival order, want index order", whole)
	}
}

func TestSegmentAssemblyRejects(t *testing.T) {
	link := bytes.Repeat([]byte{0x03}, IdentityHashLen)
	orig := bytes.Repeat([]byte{0xCC}, 32)
	now := time.Now()

	t.Run("index out of range", func(t *testing.T) {
		s := newSegmentAssembler()
		if _, err := s.add(link, segAdv(t, orig, 4, 3), []byte("x"), now); err == nil {
			t.Error("accepted segment 4 of 3")
		}
		if _, err := s.add(link, segAdv(t, orig, 0, 3), []byte("x"), now); err == nil {
			t.Error("accepted segment 0 (indices are 1-based)")
		}
	})
	t.Run("too many segments", func(t *testing.T) {
		s := newSegmentAssembler()
		n := MaxAcceptedResourceSegments + 1
		if _, err := s.add(link, segAdv(t, orig, 1, n), []byte("x"), now); err == nil {
			t.Errorf("accepted a %d-segment transfer, cap is %d", n, MaxAcceptedResourceSegments)
		}
	})
	t.Run("no original_hash", func(t *testing.T) {
		s := newSegmentAssembler()
		if _, err := s.add(link, segAdv(t, nil, 1, 2), []byte("x"), now); err == nil {
			t.Error("accepted a multi-segment ADV with no `o` to correlate on")
		}
	})
	// A sender that changes `l` mid-transfer is broken or trying to grow
	// the allocation past what the first advertisement bought.
	t.Run("total changes mid-transfer", func(t *testing.T) {
		s := newSegmentAssembler()
		if _, err := s.add(link, segAdv(t, orig, 1, 2), []byte("a"), now); err != nil {
			t.Fatal(err)
		}
		if _, err := s.add(link, segAdv(t, orig, 2, 5), []byte("b"), now); err == nil {
			t.Error("accepted a changed total_segments")
		}
		if s.pending() != 0 {
			t.Error("the inconsistent assembly was not discarded")
		}
	})
}

// A retransmitted segment must not be counted twice, or the assembly
// completes early on a lossy link and concatenates a gap.
func TestSegmentAssemblyIgnoresDuplicates(t *testing.T) {
	s := newSegmentAssembler()
	link := bytes.Repeat([]byte{0x04}, IdentityHashLen)
	orig := bytes.Repeat([]byte{0xDD}, 32)
	now := time.Now()

	if _, err := s.add(link, segAdv(t, orig, 1, 2), []byte("aaa"), now); err != nil {
		t.Fatal(err)
	}
	whole, err := s.add(link, segAdv(t, orig, 1, 2), []byte("aaa"), now)
	if err != nil || whole != nil {
		t.Fatalf("duplicate segment = (%q, %v), want (nil, nil)", whole, err)
	}
	whole, err = s.add(link, segAdv(t, orig, 2, 2), []byte("bbb"), now)
	if err != nil {
		t.Fatal(err)
	}
	if string(whole) != "aaabbb" {
		t.Errorf("assembled %q", whole)
	}
}

// The sender builds segment N+1 only after N is proved, so a stalled
// sender would otherwise pin every completed segment indefinitely.
func TestSegmentAssemblyExpires(t *testing.T) {
	s := newSegmentAssembler()
	link := bytes.Repeat([]byte{0x05}, IdentityHashLen)
	orig := bytes.Repeat([]byte{0xEE}, 32)
	now := time.Now()

	if _, err := s.add(link, segAdv(t, orig, 1, 2), []byte("a"), now); err != nil {
		t.Fatal(err)
	}
	if s.pending() != 1 {
		t.Fatal("segment was not retained")
	}
	// Any later add sweeps expired assemblies.
	other := bytes.Repeat([]byte{0xFF}, 32)
	if _, err := s.add(link, segAdv(t, other, 1, 2), []byte("z"), now.Add(SegmentAssemblyTimeout+time.Minute)); err != nil {
		t.Fatal(err)
	}
	if s.pending() != 1 {
		t.Errorf("%d assemblies pending, want only the fresh one", s.pending())
	}
}

// Two transfers on the same link must not blend, and the same
// original_hash on different links must stay separate.
func TestSegmentAssemblyKeysOnLinkAndOriginalHash(t *testing.T) {
	s := newSegmentAssembler()
	linkA := bytes.Repeat([]byte{0x06}, IdentityHashLen)
	linkB := bytes.Repeat([]byte{0x07}, IdentityHashLen)
	orig := bytes.Repeat([]byte{0x11}, 32)
	now := time.Now()

	if _, err := s.add(linkA, segAdv(t, orig, 1, 2), []byte("A1"), now); err != nil {
		t.Fatal(err)
	}
	if _, err := s.add(linkB, segAdv(t, orig, 1, 2), []byte("B1"), now); err != nil {
		t.Fatal(err)
	}
	whole, err := s.add(linkA, segAdv(t, orig, 2, 2), []byte("A2"), now)
	if err != nil {
		t.Fatal(err)
	}
	if string(whole) != "A1A2" {
		t.Errorf("link A assembled %q; the two links' transfers blended", whole)
	}
	if s.pending() != 1 {
		t.Error("link B's partial transfer was disturbed")
	}
}

// The ADV parser must now accept l>1 — it used to reject outright — but
// still bound the segment count, since the per-advertisement caps bound
// only ONE segment.
func TestResourceAdvAcceptsMultiSegmentWithinCap(t *testing.T) {
	build := func(total int) []byte {
		adv := &ResourceAdvertisement{
			TransferSize: 100, DataSize: 100, NumParts: 1,
			Hash:         bytes.Repeat([]byte{0x01}, 32),
			RandomHash:   bytes.Repeat([]byte{0x02}, ResourceRandomHashSize),
			OriginalHash: bytes.Repeat([]byte{0x01}, 32),
			SegmentIndex: 1, TotalSegments: total,
			Flags:   int(ResourceFlagEncrypted | ResourceFlagSplit),
			Hashmap: bytes.Repeat([]byte{0x03}, ResourceMapHashLen),
		}
		packed, err := PackResourceAdv(adv)
		if err != nil {
			t.Fatal(err)
		}
		return packed
	}
	if _, err := ParseResourceAdv(build(3)); err != nil {
		t.Errorf("rejected a 3-segment advertisement: %v", err)
	}
	if _, err := ParseResourceAdv(build(MaxAcceptedResourceSegments + 1)); err == nil {
		t.Error("accepted a segment count past the cap")
	}
}
