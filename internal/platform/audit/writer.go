package audit

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qali-project/qali/internal/platform/audit/auditdb"
	"github.com/qali-project/qali/internal/platform/clock"
)

// Context is the attribution the caller's unit of work supplies.
type Context struct {
	WorkspaceID *uuid.UUID
	Actor       Actor
	RequestID   string
	SourceIP    netip.Addr
}

// Writer appends events inside the caller's transaction, so an event commits
// or rolls back together with the change it describes.
type Writer struct {
	clock clock.Clock
	newID func() (uuid.UUID, error)
}

// NewWriter returns a writer using c for timestamps and newID for event IDs.
func NewWriter(c clock.Clock, newID func() (uuid.UUID, error)) *Writer {
	return &Writer{clock: c, newID: newID}
}

// Append validates, redacts, chains, and inserts one event.
func (w *Writer) Append(ctx context.Context, tx auditdb.DBTX, c Context, e Entry) (Event, error) {
	if err := e.Validate(); err != nil {
		return Event{}, err
	}
	if err := c.Actor.Validate(); err != nil {
		return Event{}, err
	}
	metadata, err := Redact(e.Metadata)
	if err != nil {
		return Event{}, err
	}
	id, err := w.newID()
	if err != nil {
		return Event{}, err
	}
	ev := Event{
		ID:          id,
		Chain:       SystemChain,
		WorkspaceID: c.WorkspaceID,
		OccurredAt:  w.clock.Now().UTC().Truncate(time.Microsecond),
		Actor:       c.Actor,
		Action:      e.Action,
		TargetType:  e.TargetType,
		TargetID:    e.TargetID,
		Outcome:     e.Outcome,
		RequestID:   c.RequestID,
		SourceIP:    c.SourceIP,
		Metadata:    metadata,
	}
	if c.WorkspaceID != nil {
		ev.Chain = c.WorkspaceID.String()
	}

	q := auditdb.New(tx)
	if err := q.LockChain(ctx, ev.Chain); err != nil {
		return Event{}, fmt.Errorf("audit: lock chain: %w", err)
	}
	prev, err := q.LastHash(ctx, ev.Chain)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return Event{}, fmt.Errorf("audit: read chain head: %w", err)
	}
	ev.PrevHash = prev
	ev.Hash = ComputeHash(ev)

	err = q.InsertEvent(ctx, auditdb.InsertEventParams{
		ID:          ev.ID,
		Chain:       ev.Chain,
		WorkspaceID: ev.WorkspaceID,
		OccurredAt:  ev.OccurredAt,
		ActorType:   string(ev.Actor.Type),
		ActorID:     optional(ev.Actor.ID),
		Action:      ev.Action,
		TargetType:  optional(ev.TargetType),
		TargetID:    optional(ev.TargetID),
		Outcome:     string(ev.Outcome),
		RequestID:   optional(ev.RequestID),
		SourceIp:    optionalAddr(ev.SourceIP),
		Metadata:    ev.Metadata,
		PrevHash:    ev.PrevHash,
		Hash:        ev.Hash,
	})
	if err != nil {
		return Event{}, fmt.Errorf("audit: insert event: %w", err)
	}
	return ev, nil
}

// LoadChain returns a chain's events in append order for verification.
func LoadChain(ctx context.Context, tx auditdb.DBTX, chain string) ([]Event, error) {
	rows, err := auditdb.New(tx).ChainEvents(ctx, chain)
	if err != nil {
		return nil, fmt.Errorf("audit: load chain: %w", err)
	}
	events := make([]Event, 0, len(rows))
	for _, r := range rows {
		ev := Event{
			ID:          r.ID,
			Chain:       r.Chain,
			WorkspaceID: r.WorkspaceID,
			OccurredAt:  r.OccurredAt,
			Actor:       Actor{Type: ActorType(r.ActorType), ID: deref(r.ActorID)},
			Action:      r.Action,
			TargetType:  deref(r.TargetType),
			TargetID:    deref(r.TargetID),
			Outcome:     Outcome(r.Outcome),
			RequestID:   deref(r.RequestID),
			Metadata:    bytes.Clone(r.Metadata),
			PrevHash:    r.PrevHash,
			Hash:        r.Hash,
		}
		if r.SourceIp != nil {
			ev.SourceIP = *r.SourceIp
		}
		events = append(events, ev)
	}
	return events, nil
}

func optional(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func optionalAddr(a netip.Addr) *netip.Addr {
	if !a.IsValid() {
		return nil
	}
	return &a
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
