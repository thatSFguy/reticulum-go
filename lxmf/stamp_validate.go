package lxmf

import (
	"bytes"
	"errors"
	"fmt"
	"time"
)

// SPEC §5.7.2 step 3 / §5.7.4 — inbound stamp validation.
//
// Outbound stamps make us deliverable to a recipient who enforces them.
// This is the other side: checking a stamp somebody sent US, and scoring
// how much work they actually did.
//
// §5.7.4 defines the three-way behaviour we mirror:
//
//	stamp_cost unset            -> no stamp required, accept anything
//	stamp_cost set, no valid stamp, enforcing     -> DROP
//	stamp_cost set, no valid stamp, not enforcing -> accept, but tell
//	                                                 the application
//
// Not enforcing is upstream's default (_enforce_stamps), and it is ours.

// ErrStampInvalid is returned when a message carries no stamp, or one
// that does not clear the required cost.
var ErrStampInvalid = errors.New("inbound stamp missing or below required cost")

// MaxConcurrentStampValidations bounds how many inbound stamps are
// verified at once.
//
// This matters more than the outbound cap. Each validation builds a
// 768 KiB workblock, and unlike grinding — which we choose to do — this
// is work an ATTACKER triggers by sending us a message. Unbounded, a
// flood of stamped messages turns into a flood of 768 KiB allocations
// and HKDF rounds. Past the ceiling a message is delivered unvalidated
// (StampChecked stays false) rather than queued, so the pressure shows
// up as unscored messages instead of memory.
const MaxConcurrentStampValidations = 4

var stampValidationSlots = make(chan struct{}, MaxConcurrentStampValidations)

// ValidateStamp checks this message's §5.7.1 stamp against `cost` and
// reports the achieved value.
//
// The workblock material is the message_id over the FOUR-element payload
// (SPEC §5.5), which MessageID already returns for a stamped message —
// hashing the 5-element wire form would derive a workblock the sender
// never used and reject every genuine stamp.
//
// value is the actual leading-zero count, which can exceed cost:
// §5.7.2 step 3 exposes that surplus so an application can prioritise
// senders who spent more than the minimum.
func (m *Message) ValidateStamp(cost int) (value int, err error) {
	if cost <= 0 {
		return 0, nil
	}
	if len(m.Stamp) != StampSize {
		return 0, fmt.Errorf("%w: stamp is %d bytes, want %d", ErrStampInvalid, len(m.Stamp), StampSize)
	}
	wb, err := stampWorkblock(m.MessageID(), workblockExpandRounds)
	if err != nil {
		return 0, fmt.Errorf("stamp workblock: %w", err)
	}
	value = stampValue(wb, m.Stamp)
	if value < cost {
		return value, fmt.Errorf("%w: cleared %d bits, needed %d", ErrStampInvalid, value, cost)
	}
	return value, nil
}

// validateInboundStamp applies the §5.7.4 policy to one inbound message
// and records the outcome on it. Returns false when the message must be
// dropped, which happens only under EnforceStamps.
func (d *Delivery) validateInboundStamp(m *Message) bool {
	cost := d.InboundStampCost
	if cost <= 0 {
		// We ask for nothing, so there is nothing to check and nothing
		// to report — §5.7.4's first row.
		return true
	}

	// Bounded: see MaxConcurrentStampValidations. A message that cannot
	// get a slot is delivered unchecked rather than delayed, because
	// blocking here blocks the inbound dispatcher.
	select {
	case stampValidationSlots <- struct{}{}:
		defer func() { <-stampValidationSlots }()
	default:
		d.errorf("stamp validation skipped: %d concurrent validations already running", MaxConcurrentStampValidations)
		return true
	}

	// §5.7.3 first: a stamp matching any ticket we issued this sender is
	// valid regardless of cost, and scores the COST_TICKET sentinel
	// rather than a real leading-zero count. Upstream checks tickets
	// before proof-of-work (LXMessage.py:273-283); checking PoW first
	// would spend a 768 KiB workblock on a message we were going to
	// accept for free anyway.
	if d.Tickets != nil && len(m.Stamp) == TicketStampSize {
		for _, ticket := range d.Tickets.Issued(m.SourceHash, time.Now()) {
			want, err := TicketStamp(ticket, m.MessageID())
			if err != nil {
				continue
			}
			if bytes.Equal(want, m.Stamp) {
				m.StampChecked = true
				m.StampValid = true
				m.StampValue = CostTicket
				return true
			}
		}
	}

	value, err := m.ValidateStamp(cost)
	m.StampChecked = true
	m.StampValue = value
	m.StampValid = err == nil
	if err != nil {
		if d.EnforceStamps {
			d.errorf("dropping message from %x: %w", m.SourceHash[:4], err)
			return false
		}
		d.errorf("accepting unstamped/underpaid message from %x: %w", m.SourceHash[:4], err)
	}
	return true
}

// stampValue returns the leading-zero bit count of
// SHA256(workblock || stamp) — upstream's stamp_value (§5.7.2 step 3).
func stampValue(workblock, stamp []byte) int {
	digest := stampDigest(workblock, stamp)
	return leadingZeroBits(digest)
}
