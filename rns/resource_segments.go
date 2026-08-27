package rns

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"
)

// SPEC §10.11 — multi-segment resources.
//
// A payload larger than MaxEfficientSize is split at that boundary, and
// each segment is its OWN Resource with its own advertisement, hashmap,
// random_hash and encryption. Only three advertisement fields tie them
// together: `i` (1-based segment index), `l` (total segments), and `o`
// (the first segment's `h`, carried by every segment as the transfer's
// stable identity — `h` itself differs per segment).
//
// Because each segment is separately encrypted and hashed, reassembly at
// this layer is a plain concatenation of the per-segment plaintexts. The
// interesting part is the bookkeeping: segments arrive as independent
// transfers and must not be handed up until the last one lands, or the
// application sees a truncated body it has no way to recognise as
// partial.

// MaxAcceptedResourceSegments bounds a multi-segment transfer.
//
// The per-advertisement caps do not bound the whole: a peer can offer
// 1 MiB per segment and simply claim a large `l`. This ceiling times
// MaxAcceptedResourceSize is the real memory exposure of one transfer,
// and it is reachable pre-authorisation by anyone with a link.
const MaxAcceptedResourceSegments = 16

// SegmentAssemblyTimeout bounds how long a partial multi-segment
// transfer is retained. The sender builds segment N+1 only after N is
// proved (§10.11), so a stalled sender otherwise pins every completed
// segment indefinitely.
const SegmentAssemblyTimeout = 10 * time.Minute

type segmentAssembly struct {
	originalHash []byte
	total        int
	parts        map[int][]byte
	bytes        int
	started      time.Time
}

// segmentAssembler accumulates the segments of multi-segment transfers,
// keyed by hex(link_id || original_hash).
type segmentAssembler struct {
	mu  sync.Mutex
	all map[string]*segmentAssembly
}

func newSegmentAssembler() *segmentAssembler {
	return &segmentAssembler{all: map[string]*segmentAssembly{}}
}

func segmentKey(linkID, originalHash []byte) string {
	return hex.EncodeToString(linkID) + ":" + hex.EncodeToString(originalHash)
}

// add records one assembled segment and returns the full body once the
// final segment has landed. Returns nil when more are outstanding.
//
// Segments may arrive out of order in principle, so they are indexed
// rather than appended; upstream sends them strictly in order, but
// trusting that would turn a reordering peer into silent corruption
// instead of a detectable error.
func (s *segmentAssembler) add(linkID []byte, adv *ResourceAdvertisement, body []byte, now time.Time) ([]byte, error) {
	if adv.SegmentIndex < 1 || adv.SegmentIndex > adv.TotalSegments {
		return nil, fmt.Errorf("segment_index %d outside 1..%d", adv.SegmentIndex, adv.TotalSegments)
	}
	if adv.TotalSegments > MaxAcceptedResourceSegments {
		return nil, fmt.Errorf("%w: %d segments, cap is %d", ErrResourceTooLarge, adv.TotalSegments, MaxAcceptedResourceSegments)
	}
	if len(adv.OriginalHash) == 0 {
		return nil, fmt.Errorf("multi-segment advertisement carries no original_hash (`o`)")
	}

	key := segmentKey(linkID, adv.OriginalHash)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expireLocked(now)

	a, ok := s.all[key]
	if !ok {
		a = &segmentAssembly{
			originalHash: append([]byte(nil), adv.OriginalHash...),
			total:        adv.TotalSegments,
			parts:        map[int][]byte{},
			started:      now,
		}
		s.all[key] = a
	}
	if a.total != adv.TotalSegments {
		// A sender that changes `l` mid-transfer is either broken or
		// trying to grow the allocation past what the first
		// advertisement bought.
		delete(s.all, key)
		return nil, fmt.Errorf("total_segments changed mid-transfer: %d then %d", a.total, adv.TotalSegments)
	}
	if _, dup := a.parts[adv.SegmentIndex]; dup {
		return nil, nil // retransmitted segment; already held
	}

	a.parts[adv.SegmentIndex] = append([]byte(nil), body...)
	a.bytes += len(body)

	if len(a.parts) < a.total {
		return nil, nil
	}

	out := make([]byte, 0, a.bytes)
	for i := 1; i <= a.total; i++ {
		seg, ok := a.parts[i]
		if !ok {
			// Cannot happen while len(parts) == total, but concatenating
			// a gap would hand up a silently corrupt body.
			delete(s.all, key)
			return nil, fmt.Errorf("segment %d missing at completion", i)
		}
		out = append(out, seg...)
	}
	delete(s.all, key)
	return out, nil
}

func (s *segmentAssembler) expireLocked(now time.Time) {
	for k, a := range s.all {
		if now.Sub(a.started) > SegmentAssemblyTimeout {
			delete(s.all, k)
		}
	}
}

// pending reports how many partial transfers are held, for tests and
// observability.
func (s *segmentAssembler) pending() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.all)
}

// SendSegmentedResourceOverLink transfers a body larger than
// MaxEfficientSize as a §10.11 multi-segment resource, and falls through
// to a single Resource when it fits.
//
// Segments go out strictly in sequence, each waiting for the previous to
// conclude. Upstream builds segment N+1 only after N is proved
// (Resource.py:770-783) for the same reason: a 100 MiB transfer must not
// materialise 100 segments' worth of parts, hashmaps and ciphertext at
// once. Doing them concurrently would also give the receiver no way to
// bound what it is holding.
func (t *Transport) SendSegmentedResourceOverLink(ctx context.Context, link *Link, body, transportID []byte) error {
	if link == nil {
		return errors.New("SendSegmentedResourceOverLink: nil link")
	}
	if len(body) == 0 {
		return errors.New("SendSegmentedResourceOverLink: empty body")
	}
	if len(body) <= MaxEfficientSize {
		return t.SendResourceOverLink(ctx, link, body, transportID)
	}

	total := (len(body) + MaxEfficientSize - 1) / MaxEfficientSize
	if total > MaxAcceptedResourceSegments {
		// Refuse rather than emit a transfer a conformant receiver with
		// our own limits would reject partway through, after both sides
		// have paid for the segments already sent.
		return fmt.Errorf("%w: body needs %d segments, cap is %d",
			ErrResourceTooLarge, total, MaxAcceptedResourceSegments)
	}

	var originalHash []byte
	for i := 0; i < total; i++ {
		start := i * MaxEfficientSize
		end := start + MaxEfficientSize
		if end > len(body) {
			end = len(body)
		}
		rs, err := newSegmentSender(t, link, body[start:end], transportID, i+1, total, originalHash)
		if err != nil {
			return fmt.Errorf("segment %d/%d: %w", i+1, total, err)
		}
		if i == 0 {
			// Every later segment carries the FIRST segment's hash as
			// `o`; that is the only field tying the transfer together,
			// since `h` differs per segment.
			originalHash = rs.ResourceHash()
		}
		if err := t.linkManager.registerResourceSender(link.ID, rs.ResourceHash(), rs); err != nil {
			return fmt.Errorf("segment %d/%d: %w", i+1, total, err)
		}
		if err := rs.Run(ctx); err != nil {
			return fmt.Errorf("segment %d/%d: %w", i+1, total, err)
		}
		t.logger.Printf("resource segment %d/%d delivered on link %x", i+1, total, link.ID[:4])
	}
	return nil
}
