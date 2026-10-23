//go:build integration

package integration_test

import (
	"encoding/hex"
	"net/http"
	"strings"
	"testing"
)

// TestNoAuthenticationSecretReachesStorageOrLogs proves MVP-04.AC-11: after
// a full journey, no password, recovery code, TOTP secret, session cookie,
// CSRF token, or reset token appears in any table or log line.
func TestNoAuthenticationSecretReachesStorageOrLogs(t *testing.T) {
	s := newAuthServer(t)
	owner, secretB32, codes := s.enrolledOwner()
	sensitive := []string{ownerPassword, secretB32, owner.cookie(), owner.csrf}
	raw, err := decodeBase32(secretB32)
	if err != nil {
		t.Fatal(err)
	}
	sensitive = append(sensitive, hex.EncodeToString(raw), string(raw))
	for _, c := range codes {
		sensitive = append(sensitive, c, strings.ReplaceAll(c, "-", ""), strings.ReplaceAll(c, "-", "")[4:])
	}

	expect(t, s.client().do(http.MethodPost, "/api/v1/auth/recovery", map[string]any{"email": "owner@example.org", "recoveryCode": codes[0], "newPassword": "recovered passphrase one"}), http.StatusNoContent)
	reset, _, err := s.svc.IssuePasswordReset(t.Context(), "owner@example.org", "ops")
	if err != nil {
		t.Fatal(err)
	}
	expect(t, s.client().do(http.MethodPost, "/api/v1/auth/password-reset", map[string]any{"token": string(reset.Expose()), "newPassword": "operator reset passphrase"}), http.StatusNoContent)
	again := s.login("owner@example.org", "operator reset passphrase", secretB32)
	sensitive = append(sensitive, "recovered passphrase one", "operator reset passphrase", string(reset.Expose()), again.cookie(), again.csrf)

	dump := dumpDatabase(t, s.db)
	logs := s.logText()
	for _, value := range sensitive {
		if value == "" {
			t.Fatal("a sensitive value was empty; the test would prove nothing")
		}
		if strings.Contains(dump, value) {
			t.Fatalf("database contains a secret (%d chars)", len(value))
		}
		if strings.Contains(logs, value) {
			t.Fatalf("logs contain a secret (%d chars)", len(value))
		}
	}
	if !strings.Contains(dump, "owner@example.org") {
		t.Fatal("the dump is empty; the test would prove nothing")
	}
}

// dumpDatabase renders every row of every Qali table as JSON text.
func dumpDatabase(t *testing.T, d testDatabase) string {
	t.Helper()
	admin := connect(t, d.admin)
	rows, err := admin.Query(t.Context(), "SELECT tablename FROM pg_tables WHERE schemaname = 'qali'")
	if err != nil {
		t.Fatal(err)
	}
	var tables []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatal(err)
		}
		tables = append(tables, name)
	}
	rows.Close()
	var b strings.Builder
	for _, table := range tables {
		data, err := admin.Query(t.Context(), "SELECT row_to_json(x)::text FROM qali."+table+" x")
		if err != nil {
			t.Fatal(err)
		}
		for data.Next() {
			var line string
			if err := data.Scan(&line); err != nil {
				t.Fatal(err)
			}
			b.WriteString(line)
			b.WriteByte('\n')
		}
		data.Close()
	}
	return b.String()
}
