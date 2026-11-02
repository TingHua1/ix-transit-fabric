package main

import (
	"archive/zip"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func writeArtifact(t *testing.T, name string, data []byte) string {
	t.Helper()
	if err := os.WriteFile(name, data, 0600); err != nil {
		t.Fatal(err)
	}
	return name
}

func requireRootArtifactInstall(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("local artifact installation is intentionally unsupported on Windows")
	}
	if os.Geteuid() != 0 {
		t.Skip("strict installed-binary verification requires a root-owned Unix file")
	}
}

func artifactHash(data []byte) string {
	sum := sha256.Sum256(data)
	return fmt.Sprintf("%x", sum[:])
}

func TestInstallLocalArtifactBinaryAndMetadata(t *testing.T) {
	requireRootArtifactInstall(t)
	dir := t.TempDir()
	data := []byte("locally-reviewed-easytier")
	source := writeArtifact(t, filepath.Join(dir, "source"), data)
	target := filepath.Join(dir, "easytier-core")
	metadata := filepath.Join(dir, "easytier-core.json")
	got, err := installLocalArtifact(source, artifactHash(data), target, metadata)
	if err != nil {
		t.Fatal(err)
	}
	installed, err := os.ReadFile(target)
	if err != nil || string(installed) != string(data) {
		t.Fatalf("wrong installed binary %q, %v", installed, err)
	}
	if got.SourceKind != "binary" || got.SHA256 != artifactHash(data) {
		t.Fatalf("unexpected metadata: %+v", got)
	}
	meta, err := os.ReadFile(metadata)
	if err != nil || strings.Contains(string(meta), "secret") || !strings.Contains(string(meta), got.SHA256) {
		t.Fatalf("bad metadata %q, %v", meta, err)
	}
}

func TestInstallNodeNetworkArtifactRejectsUntrustedConfig(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("local artifact installation is intentionally unsupported on Windows")
	}
	cfg := validNodeNetworkConfig()
	cfg.SchemaVersion = 2
	if _, err := InstallNodeNetworkArtifact(cfg, "/tmp/source", strings.Repeat("0", 64)); err == nil {
		t.Fatal("invalid install configuration accepted")
	}
	cfg = validNodeNetworkConfig()
	cfg.BinaryPath = "/tmp/untrusted/easytier-core"
	if _, err := InstallNodeNetworkArtifact(cfg, "/tmp/source", strings.Repeat("0", 64)); err == nil {
		t.Fatal("untrusted install configuration accepted")
	}
}

func TestInstallLocalArtifactHashFailureDoesNotOverwrite(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("local artifact installation is intentionally unsupported on Windows")
	}
	dir := t.TempDir()
	source := writeArtifact(t, filepath.Join(dir, "source"), []byte("new"))
	target := writeArtifact(t, filepath.Join(dir, "easytier-core"), []byte("old"))
	_, err := installLocalArtifact(source, strings.Repeat("0", 64), target, filepath.Join(dir, "metadata"))
	if err == nil {
		t.Fatal("bad hash accepted")
	}
	got, readErr := os.ReadFile(target)
	if readErr != nil || string(got) != "old" {
		t.Fatalf("target overwritten after hash failure: %q, %v", got, readErr)
	}
}

func TestInstallLocalArtifactZipSafetyAndInstall(t *testing.T) {
	requireRootArtifactInstall(t)
	dir := t.TempDir()
	makeZip := func(name, entry string, data []byte) string {
		t.Helper()
		f, err := os.Create(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		zw := zip.NewWriter(f)
		w, err := zw.Create(entry)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(data); err != nil {
			t.Fatal(err)
		}
		if err := zw.Close(); err != nil {
			t.Fatal(err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
		return f.Name()
	}
	good := makeZip("good.zip", easyTierCoreEntry, []byte("unzipped"))
	hash, err := sha256File(good)
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "easytier-core")
	if _, err := installLocalArtifact(good, hash, target, filepath.Join(dir, "metadata")); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(target)
	if string(got) != "unzipped" {
		t.Fatalf("zip did not install expected content: %q", got)
	}

	unsafe := makeZip("unsafe.zip", "../easytier-core", []byte("bad"))
	unsafeHash, err := sha256File(unsafe)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := installLocalArtifact(unsafe, unsafeHash, target, filepath.Join(dir, "metadata")); err == nil {
		t.Fatal("zip-slip entry accepted")
	}
	got, _ = os.ReadFile(target)
	if string(got) != "unzipped" {
		t.Fatal("unsafe zip overwrote target")
	}
}

func TestInstallLocalArtifactStagesOpenedSourceBeforePathReplacement(t *testing.T) {
	requireRootArtifactInstall(t)
	dir := t.TempDir()
	old := []byte("reviewed bytes")
	new := []byte("replacement bytes")
	source := writeArtifact(t, filepath.Join(dir, "source"), old)
	stageAndHashArtifactHook = func() { _ = os.WriteFile(source, new, 0600) }
	t.Cleanup(func() { stageAndHashArtifactHook = nil })
	if _, err := installLocalArtifact(source, artifactHash(old), filepath.Join(dir, "easytier-core"), filepath.Join(dir, "metadata")); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(dir, "easytier-core"))
	if err != nil || string(got) != string(old) {
		t.Fatalf("installed bytes did not come from opened source: %q, %v", got, err)
	}
}

func TestInstallLocalArtifactRejectsSymlinkSource(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("local artifact installation is intentionally unsupported on Windows")
	}
	dir := t.TempDir()
	realSource := writeArtifact(t, filepath.Join(dir, "real-source"), []byte("reviewed bytes"))
	link := filepath.Join(dir, "source-link")
	if err := os.Symlink(realSource, link); err != nil {
		t.Fatal(err)
	}
	if _, err := installLocalArtifact(link, artifactHash([]byte("reviewed bytes")), filepath.Join(dir, "easytier-core"), filepath.Join(dir, "metadata")); err == nil {
		t.Fatal("symlink source accepted")
	}
}

func TestInstallLocalArtifactMetadataFailureRollsBackBinaryAndMetadata(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("local artifact installation is intentionally unsupported on Windows")
	}
	dir := t.TempDir()
	source := writeArtifact(t, filepath.Join(dir, "source"), []byte("new binary"))
	target := writeArtifact(t, filepath.Join(dir, "easytier-core"), []byte("old binary"))
	metadata := writeArtifact(t, filepath.Join(dir, "metadata"), []byte("old metadata"))
	originalRename := artifactRename
	artifactRename = func(oldpath, newpath string) error {
		if newpath == metadata && strings.Contains(filepath.Base(oldpath), ".ix-control-easytier-metadata-") {
			return fmt.Errorf("injected metadata replacement failure")
		}
		return originalRename(oldpath, newpath)
	}
	t.Cleanup(func() { artifactRename = originalRename })
	_, err := installLocalArtifact(source, artifactHash([]byte("new binary")), target, metadata)
	if err == nil {
		t.Fatal("metadata replacement failure accepted")
	}
	var installErr *ArtifactInstallError
	if !errors.As(err, &installErr) || installErr.Installed {
		t.Fatalf("unexpected transaction error: %v", err)
	}
	gotBinary, _ := os.ReadFile(target)
	gotMetadata, _ := os.ReadFile(metadata)
	if string(gotBinary) != "old binary" || string(gotMetadata) != "old metadata" {
		t.Fatalf("rollback failed: binary=%q metadata=%q", gotBinary, gotMetadata)
	}
}

func TestRecoverArtifactTransactionRestoresOldPairAfterInterruptedMetadataReplacement(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("local artifact installation is intentionally unsupported on Windows")
	}
	dir := t.TempDir()
	target := writeArtifact(t, filepath.Join(dir, "easytier-core"), []byte("new binary"))
	metadata := writeArtifact(t, filepath.Join(dir, "metadata"), []byte("new metadata"))
	binaryBackup := writeArtifact(t, target+".ix-control-backup", []byte("old binary"))
	metadataBackup := writeArtifact(t, metadata+".ix-control-backup", []byte("old metadata"))
	if err := writeArtifactTransaction(artifactTransactionPath(metadata), artifactTransaction{
		BinaryTarget: target, MetadataTarget: metadata, BinaryBackup: binaryBackup, MetadataBackup: metadataBackup,
		BinaryOriginalPresent: true, MetadataOriginalPresent: true, Phase: "replacing",
	}); err != nil {
		t.Fatal(err)
	}
	if err := recoverArtifactTransaction(target, metadata); err != nil {
		t.Fatal(err)
	}
	gotBinary, _ := os.ReadFile(target)
	gotMetadata, _ := os.ReadFile(metadata)
	if string(gotBinary) != "old binary" || string(gotMetadata) != "old metadata" {
		t.Fatalf("recovery did not restore old pair: binary=%q metadata=%q", gotBinary, gotMetadata)
	}
	if _, err := os.Lstat(artifactTransactionPath(metadata)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("journal was not removed: %v", err)
	}
}

func TestNextInstallRecoversAfterCrashFollowingFirstBackup(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("local artifact installation is intentionally unsupported on Windows")
	}
	dir := t.TempDir()
	source := writeArtifact(t, filepath.Join(dir, "source"), []byte("new binary"))
	target := writeArtifact(t, filepath.Join(dir, "easytier-core"), []byte("old binary"))
	metadata := writeArtifact(t, filepath.Join(dir, "metadata"), []byte("old metadata"))
	originalRename := artifactRename
	backupCount := 0
	artifactRename = func(oldpath, newpath string) error {
		if strings.HasSuffix(newpath, ".ix-control-backup") {
			backupCount++
			if backupCount == 2 {
				return errors.New("simulated crash after first backup")
			}
		}
		return originalRename(oldpath, newpath)
	}
	if _, err := installLocalArtifact(source, artifactHash([]byte("new binary")), target, metadata); err == nil {
		t.Fatal("simulated crash accepted")
	}
	artifactRename = originalRename
	t.Cleanup(func() { artifactRename = originalRename })
	// A subsequent installer invocation performs recovery before it validates
	// the supplied artifact hash, so no new pair is committed in this test.
	if _, err := installLocalArtifact(source, strings.Repeat("0", 64), target, metadata); err == nil {
		t.Fatal("bad hash accepted")
	}
	gotBinary, _ := os.ReadFile(target)
	gotMetadata, _ := os.ReadFile(metadata)
	if string(gotBinary) != "old binary" || string(gotMetadata) != "old metadata" {
		t.Fatalf("next install did not recover old pair: binary=%q metadata=%q", gotBinary, gotMetadata)
	}
}
