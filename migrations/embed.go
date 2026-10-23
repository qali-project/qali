// Package migrations embeds the append-only PostgreSQL migrations. Never edit
// an applied migration; add a new file (AGENTS.md).
package migrations

import "embed"

// FS holds the goose SQL migrations.
//
//go:embed *.sql
var FS embed.FS
