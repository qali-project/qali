// Command imagecheck inspects a built container image against the runtime
// hardening rules in docs/SECURITY_ARCHITECTURE.md section 10: non-root user,
// no shell, compiler, or package manager, no source `.env`, private keys, test
// data, or source code.
//
// Usage: go run ./tools/imagecheck <image>
package main

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"strings"
)

// ImageConfig is the subset of the OCI image configuration that is checked.
type ImageConfig struct {
	User string `json:"User"`
}

var forbiddenExecutables = map[string]bool{
	"sh": true, "bash": true, "ash": true, "dash": true, "zsh": true, "busybox": true,
	"go": true, "gofmt": true, "gcc": true, "cc": true, "g++": true, "clang": true, "make": true,
	"node": true, "npm": true, "npx": true, "yarn": true, "pnpm": true, "corepack": true,
	"apk": true, "apt": true, "apt-get": true, "dpkg": true, "rpm": true, "yum": true, "dnf": true, "microdnf": true,
	"pip": true, "pip3": true, "python": true, "python3": true,
	"curl": true, "wget": true,
}

const maxScannedFile = 1 << 20

// CheckFilesystem reads a filesystem tar stream (docker export) and returns
// one finding per forbidden entry.
func CheckFilesystem(r io.Reader) ([]string, error) {
	var findings []string
	tr := tar.NewReader(r)
	entries := 0
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read image filesystem: %w", err)
		}
		entries++
		name := strings.TrimPrefix(path.Clean("/"+hdr.Name), "/")
		if hdr.Typeflag == tar.TypeDir {
			continue
		}
		if reason := forbiddenPath(name); reason != "" {
			findings = append(findings, fmt.Sprintf("%s: %s", name, reason))
			continue
		}
		if hdr.Typeflag == tar.TypeReg && hdr.Size <= maxScannedFile {
			body, err := io.ReadAll(tr)
			if err != nil {
				return nil, fmt.Errorf("read %s: %w", name, err)
			}
			if bytes.Contains(body, []byte("PRIVATE KEY-----")) {
				findings = append(findings, fmt.Sprintf("%s: contains a private key", name))
			}
		}
	}
	if entries == 0 {
		return nil, errors.New("image filesystem is empty")
	}
	return findings, nil
}

func forbiddenPath(name string) string {
	base := path.Base(name)
	segments := strings.Split(name, "/")
	for _, s := range segments[:len(segments)-1] {
		switch s {
		case "testdata":
			return "test data in image"
		case "node_modules":
			return "node_modules in image"
		}
	}
	switch {
	case forbiddenExecutables[base]:
		return "shell, compiler, package manager, or network tool in image"
	case base == ".env" || strings.HasPrefix(base, ".env.") || strings.HasSuffix(base, ".env"):
		return "environment file in image"
	case strings.HasSuffix(base, ".key"):
		return "key file in image"
	case strings.HasSuffix(base, ".go"):
		return "Go source in image"
	case base == "package.json":
		return "package manifest in image"
	}
	return ""
}

// CheckConfig rejects images that run as root or do not declare a user.
func CheckConfig(cfg ImageConfig) []string {
	user := strings.TrimSpace(cfg.User)
	if user == "" {
		return []string{"image does not declare a non-root USER"}
	}
	for part := range strings.SplitSeq(user, ":") {
		if part == "root" || part == "0" {
			return []string{fmt.Sprintf("image runs as root (USER %q)", user)}
		}
	}
	return nil
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: imagecheck <image>")
		os.Exit(2)
	}
	findings, err := inspect(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, "imagecheck:", err)
		os.Exit(2)
	}
	for _, f := range findings {
		fmt.Fprintln(os.Stderr, f)
	}
	if len(findings) > 0 {
		fmt.Fprintf(os.Stderr, "imagecheck: %d finding(s) in %s\n", len(findings), os.Args[1])
		os.Exit(1)
	}
	fmt.Printf("imagecheck: %s OK\n", os.Args[1])
}

// docker runs the docker CLI directly, without a shell. Arguments are an
// image reference from the operator's command line or IDs returned by docker.
func docker(ctx context.Context, args ...string) *exec.Cmd {
	return exec.CommandContext(ctx, "docker", args...) //nolint:gosec // G204: see doc comment
}

func inspect(image string) ([]string, error) {
	ctx := context.Background()
	out, err := docker(ctx, "image", "inspect", "--format", "{{json .Config}}", image).Output()
	if err != nil {
		return nil, fmt.Errorf("docker image inspect: %w", err)
	}
	var cfg ImageConfig
	if err := json.Unmarshal(out, &cfg); err != nil {
		return nil, fmt.Errorf("decode image config: %w", err)
	}
	findings := CheckConfig(cfg)

	id, err := docker(ctx, "create", image).Output()
	if err != nil {
		return nil, fmt.Errorf("docker create: %w", err)
	}
	container := strings.TrimSpace(string(id))
	defer func() { _ = docker(ctx, "rm", container).Run() }()

	export := docker(ctx, "export", container)
	stdout, err := export.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := export.Start(); err != nil {
		return nil, fmt.Errorf("docker export: %w", err)
	}
	fsFindings, scanErr := CheckFilesystem(stdout)
	_, _ = io.Copy(io.Discard, stdout)
	if err := export.Wait(); err != nil {
		return nil, fmt.Errorf("docker export: %w", err)
	}
	if scanErr != nil {
		return nil, scanErr
	}
	return append(findings, fsFindings...), nil
}
