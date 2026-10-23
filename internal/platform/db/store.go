package db

import (
	"context"
	"errors"
	"fmt"
	"net/netip"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qali-project/qali/internal/platform/audit"
	"github.com/qali-project/qali/internal/platform/clock"
	"github.com/qali-project/qali/internal/platform/secret"
)

// Querier is the statement interface repositories receive. It matches the
// sqlc-generated DBTX, so generated queries run inside a scoped transaction.
type Querier interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// RequestInfo carries request attribution into audit events.
type RequestInfo struct {
	RequestID string
	SourceIP  netip.Addr
}

// Scope is the tenancy and attribution context of a unit of work. A
// workspace scope sees only that workspace's rows in isolated tables; the
// system scope sees none of them.
type Scope struct {
	workspace uuid.UUID
	actor     audit.Actor
	request   RequestInfo
}

// WorkspaceScope returns a scope for one workspace. Callers construct it only
// after authorization has resolved the workspace (application layer).
func WorkspaceScope(workspace uuid.UUID, actor audit.Actor, req RequestInfo) (Scope, error) {
	if workspace == uuid.Nil {
		return Scope{}, errors.New("db: workspace scope requires a workspace")
	}
	if err := actor.Validate(); err != nil {
		return Scope{}, err
	}
	return Scope{workspace: workspace, actor: actor, request: req}, nil
}

// SystemScope returns a scope without a workspace, for platform tables such as
// jobs. Workspace-isolated tables are invisible in it.
func SystemScope(actor audit.Actor, req RequestInfo) (Scope, error) {
	if err := actor.Validate(); err != nil {
		return Scope{}, err
	}
	return Scope{actor: actor, request: req}, nil
}

// Workspace returns the scope's workspace, or uuid.Nil for the system scope.
func (s Scope) Workspace() uuid.UUID { return s.workspace }

func (s Scope) auditContext() audit.Context {
	c := audit.Context{Actor: s.actor, RequestID: s.request.RequestID, SourceIP: s.request.SourceIP}
	if s.workspace != uuid.Nil {
		ws := s.workspace
		c.WorkspaceID = &ws
	}
	return c
}

// Options configures Open. Zero values select defaults.
type Options struct {
	MaxConns int32
	Clock    clock.Clock
	NewID    func() (uuid.UUID, error)
}

// Store runs scoped units of work against the runtime role's pool.
type Store struct {
	pool  *pgxpool.Pool
	audit *audit.Writer
}

// Open connects with the runtime role. It refuses superusers, roles that
// bypass row-level security, and the schema owner, because each of them would
// silently disable tenant isolation.
func Open(ctx context.Context, dsn secret.Value, opts Options) (*Store, error) {
	cfg, err := pgxpool.ParseConfig(string(dsn.Expose()))
	if err != nil {
		return nil, redactParseError(err)
	}
	if opts.MaxConns > 0 {
		cfg.MaxConns = opts.MaxConns
	}
	if opts.Clock == nil {
		opts.Clock = clock.System{}
	}
	if opts.NewID == nil {
		opts.NewID = uuid.NewV7
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("db: connect: %w", MapError(err))
	}
	var privileged bool
	err = pool.QueryRow(ctx, `
		SELECT r.rolsuper OR r.rolbypassrls
		       OR EXISTS (SELECT 1 FROM pg_namespace n WHERE n.nspname = 'qali' AND n.nspowner = r.oid)
		FROM pg_roles r WHERE r.rolname = current_user`).Scan(&privileged)
	if err != nil {
		pool.Close()
		return nil, fmt.Errorf("db: verify runtime role: %w", MapError(err))
	}
	if privileged {
		pool.Close()
		return nil, errors.New("db: the runtime connection must use the unprivileged application role (qali_app)")
	}
	return &Store{pool: pool, audit: audit.NewWriter(opts.Clock, opts.NewID)}, nil
}

// Close releases all connections.
func (s *Store) Close() { s.pool.Close() }

// Ping checks connectivity.
func (s *Store) Ping(ctx context.Context) error { return MapError(s.pool.Ping(ctx)) }

// Read runs fn in a read-only transaction bound to scope.
func (s *Store) Read(ctx context.Context, scope Scope, fn func(context.Context, Querier) error) error {
	return s.run(ctx, scope, pgx.ReadOnly, func(ctx context.Context, tx pgx.Tx) error {
		return fn(ctx, tx)
	})
}

// WriteTx is a read-write unit of work. It must record at least one audit
// event before it can commit.
type WriteTx struct {
	tx      pgx.Tx
	scope   Scope
	writer  *audit.Writer
	audited int
}

func (w *WriteTx) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	return w.tx.Exec(ctx, sql, args...)
}

func (w *WriteTx) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	return w.tx.Query(ctx, sql, args...)
}

func (w *WriteTx) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	return w.tx.QueryRow(ctx, sql, args...)
}

// Scope returns the unit of work's scope.
func (w *WriteTx) Scope() Scope { return w.scope }

// Audit records an event attributed to the scope, in this transaction.
func (w *WriteTx) Audit(ctx context.Context, e audit.Entry) error {
	if _, err := w.writer.Append(ctx, w.tx, w.scope.auditContext(), e); err != nil {
		return err
	}
	w.audited++
	return nil
}

// Write runs fn in a read-write transaction bound to scope and commits only
// if fn succeeds and recorded an audit event.
func (s *Store) Write(ctx context.Context, scope Scope, fn func(context.Context, *WriteTx) error) error {
	return s.run(ctx, scope, pgx.ReadWrite, func(ctx context.Context, tx pgx.Tx) error {
		w := &WriteTx{tx: tx, scope: scope, writer: s.audit}
		if err := fn(ctx, w); err != nil {
			return err
		}
		if w.audited == 0 {
			return &Error{kind: ErrUnaudited}
		}
		return nil
	})
}

// PlatformWrite runs fn in a read-write system-scope transaction without the
// audit requirement. It exists for platform bookkeeping such as job leases,
// is invisible to workspace-isolated tables, and lint forbids calling it
// outside internal/platform.
func (s *Store) PlatformWrite(ctx context.Context, fn func(context.Context, Querier) error) error {
	return s.run(ctx, Scope{}, pgx.ReadWrite, func(ctx context.Context, tx pgx.Tx) error {
		return fn(ctx, tx)
	})
}

func (s *Store) run(ctx context.Context, scope Scope, mode pgx.TxAccessMode, fn func(context.Context, pgx.Tx) error) (err error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{AccessMode: mode})
	if err != nil {
		return MapError(err)
	}
	defer func() {
		if p := recover(); p != nil {
			_ = tx.Rollback(context.WithoutCancel(ctx))
			panic(p)
		}
		if err != nil {
			_ = tx.Rollback(context.WithoutCancel(ctx))
		}
	}()
	workspace := ""
	if scope.workspace != uuid.Nil {
		workspace = scope.workspace.String()
	}
	// A user actor's ID enables the member_self policies (a user sees their
	// own memberships). The application layer builds actors only from
	// authenticated sessions.
	user := ""
	if scope.actor.Type == audit.ActorUser {
		if id, err := uuid.Parse(scope.actor.ID); err == nil {
			user = id.String()
		}
	}
	// is_local = true: the settings end with the transaction and never leak
	// to the next user of the pooled connection.
	if _, err := tx.Exec(ctx, "SELECT set_config('qali.workspace_id', $1, true), set_config('qali.user_id', $2, true)", workspace, user); err != nil {
		return MapError(err)
	}
	if err := fn(ctx, tx); err != nil {
		return err
	}
	return MapError(tx.Commit(ctx))
}

// Readiness failures.
var (
	ErrDatabaseUnavailable = errors.New("database unavailable")
	ErrMigrationsPending   = errors.New("database schema is older than this release; run migrations")
	ErrSchemaNewer         = errors.New("database schema is newer than this release")
)

// Ready reports whether the database is reachable and its schema version
// equals the newest migration embedded in this binary.
func (s *Store) Ready(ctx context.Context) error {
	var version int64
	err := s.pool.QueryRow(ctx,
		"SELECT COALESCE(max(version_id), 0) FROM goose_db_version WHERE is_applied").Scan(&version)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "42P01" {
			return fmt.Errorf("%w (no migrations applied)", ErrMigrationsPending)
		}
		return fmt.Errorf("%w: %w", ErrDatabaseUnavailable, MapError(err))
	}
	switch latest := LatestMigration(); {
	case version < latest:
		return fmt.Errorf("%w (at %d, need %d)", ErrMigrationsPending, version, latest)
	case version > latest:
		return fmt.Errorf("%w (at %d, release knows %d)", ErrSchemaNewer, version, latest)
	}
	return nil
}
