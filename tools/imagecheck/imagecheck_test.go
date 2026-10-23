package main

import (
	"archive/tar"
	"bytes"
	"strings"
	"testing"
)

type entry struct {
	name     string
	body     string
	typeflag byte
}

func tarOf(t *testing.T, entries ...entry) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		hdr := &tar.Header{Name: e.name, Mode: 0o755, Size: int64(len(e.body)), Typeflag: e.typeflag}
		if e.typeflag == 0 {
			hdr.Typeflag = tar.TypeReg
		}
		if hdr.Typeflag == tar.TypeDir || hdr.Typeflag == tar.TypeSymlink {
			hdr.Size = 0
			hdr.Linkname = e.body
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if hdr.Typeflag == tar.TypeReg {
			if _, err := tw.Write([]byte(e.body)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return &buf
}

// Key markers are split so scanners do not treat fixtures as leaked keys.
const (
	beginPrivateKey   = "-----BEGIN " + "PRIVATE KEY-----"
	endPrivateKey     = "-----END " + "PRIVATE KEY-----"
	beginECPrivateKey = "-----BEGIN EC " + "PRIVATE KEY-----"
)

var cleanImage = []entry{
	{name: "etc/", typeflag: tar.TypeDir},
	{name: "etc/passwd", body: "root:x:0:0:root:/root:/sbin/nologin\nnonroot:x:65532:65532::/home/nonroot:/sbin/nologin\n"},
	{name: "etc/ssl/certs/ca-certificates.crt", body: "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"},
	{name: "var/lib/dpkg/status.d/base", body: "Package: base-files\n"},
	{name: "usr/local/bin/qali", body: "\x7fELF binary"},
}

func TestCleanFilesystemHasNoFindings(t *testing.T) {
	findings, err := CheckFilesystem(tarOf(t, cleanImage...))
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("want no findings, got %v", findings)
	}
}

func TestForbiddenFilesAreReported(t *testing.T) {
	cases := []struct {
		name  string
		entry entry
		want  string
	}{
		{"shell", entry{name: "bin/sh", body: "x"}, "bin/sh"},
		{"busybox symlink", entry{name: "bin/ash", body: "/bin/busybox", typeflag: tar.TypeSymlink}, "bin/ash"},
		{"go compiler", entry{name: "usr/local/go/bin/go", body: "x"}, "usr/local/go/bin/go"},
		{"c compiler", entry{name: "usr/bin/gcc", body: "x"}, "usr/bin/gcc"},
		{"node", entry{name: "usr/local/bin/node", body: "x"}, "usr/local/bin/node"},
		{"npm", entry{name: "usr/local/bin/npm", body: "x"}, "usr/local/bin/npm"},
		{"apk", entry{name: "sbin/apk", body: "x"}, "sbin/apk"},
		{"apt-get", entry{name: "usr/bin/apt-get", body: "x"}, "usr/bin/apt-get"},
		{"dpkg", entry{name: "usr/bin/dpkg", body: "x"}, "usr/bin/dpkg"},
		{"dotenv", entry{name: "app/.env", body: "QALI_X=1"}, "app/.env"},
		{"dotenv variant", entry{name: "app/.env.local", body: "QALI_X=1"}, "app/.env.local"},
		{"key file", entry{name: "app/test.key", body: "x"}, "app/test.key"},
		{"embedded private key", entry{name: "app/cert.pem", body: beginPrivateKey + "\nabc\n" + endPrivateKey + "\n"}, "app/cert.pem"},
		{"ec private key", entry{name: "app/x.txt", body: beginECPrivateKey + "\n"}, "app/x.txt"},
		{"go source", entry{name: "src/main.go", body: "package main"}, "src/main.go"},
		{"testdata", entry{name: "app/testdata/fixture.json", body: "{}"}, "app/testdata/fixture.json"},
		{"node_modules", entry{name: "app/node_modules/x/index.js", body: ""}, "app/node_modules/x/index.js"},
		{"package.json", entry{name: "app/package.json", body: "{}"}, "app/package.json"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			findings, err := CheckFilesystem(tarOf(t, append(append([]entry{}, cleanImage...), tc.entry)...))
			if err != nil {
				t.Fatal(err)
			}
			if len(findings) != 1 || !strings.Contains(findings[0], tc.want) {
				t.Fatalf("want one finding naming %q, got %v", tc.want, findings)
			}
		})
	}
}

func TestMalformedArchiveIsAnError(t *testing.T) {
	if _, err := CheckFilesystem(strings.NewReader("not a tar archive at all, definitely not 512 bytes")); err == nil {
		t.Fatal("want an error for a malformed archive")
	}
}

func TestConfigUser(t *testing.T) {
	cases := []struct {
		user string
		ok   bool
	}{
		{"65532:65532", true},
		{"65532", true},
		{"nonroot", true},
		{"nonroot:nonroot", true},
		{"", false},
		{"root", false},
		{"0", false},
		{"0:0", false},
		{"0:65532", false},
		{"root:root", false},
		{"65532:0", false},
	}
	for _, tc := range cases {
		t.Run("user="+tc.user, func(t *testing.T) {
			findings := CheckConfig(ImageConfig{User: tc.user})
			if tc.ok && len(findings) != 0 {
				t.Fatalf("want no findings, got %v", findings)
			}
			if !tc.ok && len(findings) == 0 {
				t.Fatal("want a finding for a root or missing user")
			}
		})
	}
}
