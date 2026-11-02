package main

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const easyTierCoreEntry = "easytier-core"
const maxEasyTierZipEntrySize int64 = 512 << 20

// localArtifactInstallInput only describes files already present on this
// machine. It is deliberately private: arbitrary local targets are not a
// supported installation API.
type localArtifactInstallInput struct {
	SourcePath     string
	ExpectedSHA256 string
	TargetPath     string
	MetadataPath   string
}

// LocalArtifactMetadata is persisted next to an installed executable. It has
// supply-chain facts only and never contains network credentials.
type LocalArtifactMetadata struct {
	SHA256      string    `json:"sha256"`
	InstalledAt time.Time `json:"installed_at"`
	Platform    string    `json:"platform"`
	SourceKind  string    `json:"source_kind"`
}

// ArtifactInstallError distinguishes a failed, rolled-back transaction from a
// completed install whose backup cleanup needs operator attention.
type ArtifactInstallError struct {
	Installed bool
	Err       error
}

func (e *ArtifactInstallError) Error() string {
	if e.Installed {
		return "artifact installed but backup cleanup failed: " + e.Err.Error()
	}
	return "artifact was not installed: " + e.Err.Error()
}
func (e *ArtifactInstallError) Unwrap() error { return e.Err }

// artifactRename is a narrow fault-injection seam for transaction tests.
var artifactRename = os.Rename
var stageAndHashArtifactHook func()

type artifactTransaction struct {
	BinaryTarget            string `json:"binary_target"`
	MetadataTarget          string `json:"metadata_target"`
	BinaryBackup            string `json:"binary_backup"`
	MetadataBackup          string `json:"metadata_backup"`
	BinaryOriginalPresent   bool   `json:"binary_original_present"`
	MetadataOriginalPresent bool   `json:"metadata_original_present"`
	Phase                   string `json:"phase"`
	Committed               bool   `json:"committed"`
}

// InstallNodeNetworkArtifact installs a reviewed local artifact at the binary
// location declared by the node-network configuration. It only copies a local
// file after hash and archive checks; it never executes that artifact.
func InstallNodeNetworkArtifact(config NodeNetworkConfig, sourcePath, expectedSHA256 string) (LocalArtifactMetadata, error) {
	if err := requireNodeNetworkSupported(); err != nil {
		return LocalArtifactMetadata{}, err
	}
	if err := validateNodeNetworkConfigForInstall(config, OSNodeNetworkFileInspector{}); err != nil {
		return LocalArtifactMetadata{}, err
	}
	return installLocalArtifactInput(localArtifactInstallInput{
		SourcePath: sourcePath, ExpectedSHA256: expectedSHA256,
		TargetPath: config.BinaryPath, MetadataPath: config.BinaryPath + ".metadata.json",
	})
}

func installLocalArtifact(sourcePath, expectedSHA256, targetPath, metadataPath string) (LocalArtifactMetadata, error) {
	return installLocalArtifactInput(localArtifactInstallInput{sourcePath, expectedSHA256, targetPath, metadataPath})
}

func installLocalArtifactInput(input localArtifactInstallInput) (LocalArtifactMetadata, error) {
	if err := requireNodeNetworkSupported(); err != nil {
		return LocalArtifactMetadata{}, err
	}
	if !validArtifactSHA256(input.ExpectedSHA256) {
		return LocalArtifactMetadata{}, errors.New("expected SHA256 must be lowercase hexadecimal")
	}
	if err := validateArtifactTarget("artifact target", input.TargetPath); err != nil {
		return LocalArtifactMetadata{}, err
	}
	if input.MetadataPath == "" {
		input.MetadataPath = input.TargetPath + ".metadata.json"
	}
	if err := validateArtifactTarget("artifact metadata", input.MetadataPath); err != nil {
		return LocalArtifactMetadata{}, err
	}
	if filepath.Dir(input.TargetPath) != filepath.Dir(input.MetadataPath) {
		return LocalArtifactMetadata{}, errors.New("artifact and metadata must share a directory")
	}
	if err := recoverArtifactTransaction(input.TargetPath, input.MetadataPath); err != nil {
		return LocalArtifactMetadata{}, err
	}
	if err := rejectUnsafeExistingTarget(input.TargetPath); err != nil {
		return LocalArtifactMetadata{}, err
	}
	if err := rejectUnsafeExistingTarget(input.MetadataPath); err != nil {
		return LocalArtifactMetadata{}, err
	}

	// Hash and initial staging intentionally consume one already-open descriptor.
	// The source pathname is never reopened, so replacement after validation
	// cannot make the hash refer to different bytes than the installed artifact.
	sourceStage, sourceHash, err := stageAndHashArtifact(input.SourcePath, filepath.Dir(input.TargetPath))
	if err != nil {
		return LocalArtifactMetadata{}, err
	}
	defer os.Remove(sourceStage)
	if sourceHash != input.ExpectedSHA256 {
		return LocalArtifactMetadata{}, errors.New("local artifact SHA256 does not match expected SHA256")
	}

	stagedBinary, sourceKind, err := stageArtifactBinary(sourceStage, filepath.Dir(input.TargetPath))
	if err != nil {
		return LocalArtifactMetadata{}, err
	}
	defer os.Remove(stagedBinary)
	metadata := LocalArtifactMetadata{SHA256: sourceHash, InstalledAt: time.Now().UTC(), Platform: runtime.GOOS + "/" + runtime.GOARCH, SourceKind: sourceKind}
	stagedMetadata, err := stageArtifactMetadata(metadata, filepath.Dir(input.MetadataPath))
	if err != nil {
		return LocalArtifactMetadata{}, err
	}
	defer os.Remove(stagedMetadata)

	if err := replaceArtifactPair(stagedBinary, input.TargetPath, stagedMetadata, input.MetadataPath); err != nil {
		return LocalArtifactMetadata{}, err
	}
	if err := requireInstalledArtifactBinary(input.TargetPath); err != nil {
		return LocalArtifactMetadata{}, &ArtifactInstallError{Installed: true, Err: fmt.Errorf("installed binary failed final validation: %w", err)}
	}
	return metadata, nil
}

func validArtifactSHA256(value string) bool {
	if len(value) != sha256.Size*2 || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func validateArtifactTarget(label, name string) error {
	if name == "" || !filepath.IsAbs(name) || filepath.Clean(name) != name || filepath.Base(name) == "." {
		return fmt.Errorf("%s must be an absolute clean file path", label)
	}
	info, err := os.Lstat(filepath.Dir(name))
	if err != nil || !info.IsDir() || info.Mode()&fs.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 {
		return fmt.Errorf("%s directory must be an existing non-symlink directory that is not group- or world-writable", label)
	}
	return nil
}

func rejectUnsafeExistingTarget(name string) error {
	info, err := os.Lstat(name)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode()&fs.ModeSymlink != 0 {
		return fmt.Errorf("target %s must be a regular non-symlink file", name)
	}
	return nil
}

func stageAndHashArtifact(source, directory string) (string, string, error) {
	if source == "" {
		return "", "", errors.New("artifact source path is required")
	}
	f, err := openArtifactSourceNoFollow(source)
	if err != nil {
		return "", "", err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return "", "", errors.New("local artifact must remain a regular file")
	}
	if stageAndHashArtifactHook != nil {
		stageAndHashArtifactHook()
	}
	tmp, err := os.CreateTemp(directory, ".ix-control-artifact-source-*")
	if err != nil {
		return "", "", err
	}
	name := tmp.Name()
	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(tmp, h), f); err != nil {
		tmp.Close()
		os.Remove(name)
		return "", "", err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		os.Remove(name)
		return "", "", err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(name)
		return "", "", err
	}
	return name, hex.EncodeToString(h.Sum(nil)), nil
}

func requireInstalledArtifactBinary(name string) error {
	info, err := os.Lstat(name)
	if err != nil {
		return fmt.Errorf("inspect installed binary: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&fs.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 || info.Mode().Perm()&0111 == 0 {
		return errors.New("installed artifact must be a regular non-symlink executable that is not group- or world-writable")
	}
	return nil
}

func sha256File(name string) (string, error) {
	f, err := os.Open(name)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func stageArtifactBinary(source, directory string) (string, string, error) {
	f, err := os.Open(source)
	if err != nil {
		return "", "", err
	}
	var magic [4]byte
	n, readErr := io.ReadFull(f, magic[:])
	if readErr != nil && !errors.Is(readErr, io.ErrUnexpectedEOF) {
		f.Close()
		return "", "", readErr
	}
	f.Close()
	if n == 4 && string(magic[:]) == "PK\x03\x04" {
		return stageEasyTierZip(source, directory)
	}
	f, err = os.Open(source)
	if err != nil {
		return "", "", err
	}
	defer f.Close()
	name, err := stageArtifactReader(f, directory)
	return name, "binary", err
}

func stageArtifactReader(reader io.Reader, directory string) (string, error) {
	tmp, err := os.CreateTemp(directory, ".ix-control-easytier-*")
	if err != nil {
		return "", err
	}
	name := tmp.Name()
	if _, err := io.Copy(tmp, reader); err != nil {
		tmp.Close()
		os.Remove(name)
		return "", err
	}
	if err := tmp.Chmod(0755); err != nil {
		tmp.Close()
		os.Remove(name)
		return "", err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		os.Remove(name)
		return "", err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(name)
		return "", err
	}
	return name, nil
}

func stageEasyTierZip(source, directory string) (string, string, error) {
	zr, err := zip.OpenReader(source)
	if err != nil {
		return "", "", err
	}
	defer zr.Close()
	if len(zr.File) != 1 {
		return "", "", errors.New("zip must contain exactly one easytier-core entry")
	}
	entry := zr.File[0]
	if entry.Name != easyTierCoreEntry || strings.Contains(entry.Name, "\\") || filepath.IsAbs(entry.Name) || strings.Contains(entry.Name, "..") {
		return "", "", errors.New("zip entry is not a safe easytier-core file")
	}
	if entry.FileInfo().Mode()&fs.ModeSymlink != 0 || entry.FileInfo().IsDir() {
		return "", "", errors.New("zip easytier-core entry must be a regular file")
	}
	reader, err := entry.Open()
	if err != nil {
		return "", "", err
	}
	defer reader.Close()
	tmp, err := os.CreateTemp(directory, ".ix-control-easytier-*")
	if err != nil {
		return "", "", err
	}
	name := tmp.Name()
	written, err := io.Copy(tmp, io.LimitReader(reader, maxEasyTierZipEntrySize+1))
	if err != nil || written > maxEasyTierZipEntrySize {
		tmp.Close()
		os.Remove(name)
		if err != nil {
			return "", "", err
		}
		return "", "", errors.New("zip easytier-core entry exceeds size limit")
	}
	if err := tmp.Chmod(0755); err != nil {
		tmp.Close()
		os.Remove(name)
		return "", "", err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		os.Remove(name)
		return "", "", err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(name)
		return "", "", err
	}
	return name, "zip", nil
}

func stageArtifactMetadata(metadata LocalArtifactMetadata, directory string) (string, error) {
	b, err := json.Marshal(metadata)
	if err != nil {
		return "", err
	}
	tmp, err := os.CreateTemp(directory, ".ix-control-easytier-metadata-*")
	if err != nil {
		return "", err
	}
	name := tmp.Name()
	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		os.Remove(name)
		return "", err
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		os.Remove(name)
		return "", err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		os.Remove(name)
		return "", err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(name)
		return "", err
	}
	return name, nil
}

// replaceArtifactPair is a recoverable persistent transaction, not an atomic
// pair replacement.  A durable journal records the old pair before either
// target changes.  Until the committed marker is durable, a subsequent install
// restores the old pair; after it is durable, recovery only completes cleanup.
func replaceArtifactPair(binaryStage, binaryTarget, metadataStage, metadataTarget string) error {
	transactionPath := artifactTransactionPath(metadataTarget)
	if err := rejectUnsafeExistingTarget(transactionPath); err != nil {
		return &ArtifactInstallError{Err: err}
	}
	if _, err := os.Lstat(transactionPath); !errors.Is(err, fs.ErrNotExist) {
		return &ArtifactInstallError{Err: errors.New("artifact transaction journal already exists")}
	}
	binaryPresent, err := artifactTargetPresent(binaryTarget)
	if err != nil {
		return &ArtifactInstallError{Err: err}
	}
	metadataPresent, err := artifactTargetPresent(metadataTarget)
	if err != nil {
		return &ArtifactInstallError{Err: err}
	}
	tx := artifactTransaction{
		BinaryTarget: binaryTarget, MetadataTarget: metadataTarget,
		BinaryBackup: binaryTarget + ".ix-control-backup", MetadataBackup: metadataTarget + ".ix-control-backup",
		BinaryOriginalPresent: binaryPresent, MetadataOriginalPresent: metadataPresent,
		Phase: "intention",
	}
	if err := writeArtifactTransaction(transactionPath, tx); err != nil {
		return &ArtifactInstallError{Err: fmt.Errorf("write transaction intention journal failed: %w", err)}
	}
	if err := backupArtifactTarget(binaryTarget, tx.BinaryBackup, tx.BinaryOriginalPresent); err != nil {
		return &ArtifactInstallError{Err: fmt.Errorf("backup binary failed; recovery journal retained: %w", err)}
	}
	tx.Phase = "binary_backed_up"
	if err := writeArtifactTransaction(transactionPath, tx); err != nil {
		return &ArtifactInstallError{Err: fmt.Errorf("record binary backup failed; recovery journal retained: %w", err)}
	}
	if err := backupArtifactTarget(metadataTarget, tx.MetadataBackup, tx.MetadataOriginalPresent); err != nil {
		return &ArtifactInstallError{Err: fmt.Errorf("backup metadata failed; recovery journal retained: %w", err)}
	}
	tx.Phase = "metadata_backed_up"
	if err := writeArtifactTransaction(transactionPath, tx); err != nil {
		return &ArtifactInstallError{Err: fmt.Errorf("record metadata backup failed; recovery journal retained: %w", err)}
	}
	tx.Phase = "replacing"
	if err := writeArtifactTransaction(transactionPath, tx); err != nil {
		return &ArtifactInstallError{Err: fmt.Errorf("record replacement phase failed; recovery journal retained: %w", err)}
	}
	rollback := func(cause error) error {
		_ = os.Remove(binaryTarget)
		_ = os.Remove(metadataTarget)
		binaryRestoreErr := restoreArtifactTarget(binaryTarget, tx.BinaryBackup)
		metadataRestoreErr := restoreArtifactTarget(metadataTarget, tx.MetadataBackup)
		if binaryRestoreErr != nil || metadataRestoreErr != nil {
			return &ArtifactInstallError{Err: fmt.Errorf("transaction incomplete after %w; recovery journal retained; restore status: binary=%v metadata=%v", cause, binaryRestoreErr, metadataRestoreErr)}
		}
		journalErr := os.Remove(transactionPath)
		return &ArtifactInstallError{Err: fmt.Errorf("transaction rolled back after %w; journal removal status: %v", cause, journalErr)}
	}
	if err := artifactRename(binaryStage, binaryTarget); err != nil {
		return rollback(err)
	}
	if err := artifactRename(metadataStage, metadataTarget); err != nil {
		return rollback(err)
	}
	if err := syncArtifactDirectory(filepath.Dir(binaryTarget)); err != nil {
		return &ArtifactInstallError{Err: fmt.Errorf("transaction incomplete before commit marker: %w", err)}
	}
	tx.Committed = true
	tx.Phase = "committed"
	if err := writeArtifactTransaction(transactionPath, tx); err != nil {
		return &ArtifactInstallError{Err: fmt.Errorf("new pair written but commit marker failed; old pair will be restored on recovery: %w", err)}
	}
	if err := removeArtifactBackup(tx.BinaryBackup); err != nil {
		return &ArtifactInstallError{Installed: true, Err: fmt.Errorf("commit marker durable; binary backup cleanup failed: %w", err)}
	}
	if err := removeArtifactBackup(tx.MetadataBackup); err != nil {
		return &ArtifactInstallError{Installed: true, Err: fmt.Errorf("commit marker durable; metadata backup cleanup failed: %w", err)}
	}
	if err := syncArtifactDirectory(filepath.Dir(binaryTarget)); err != nil {
		return &ArtifactInstallError{Installed: true, Err: fmt.Errorf("commit marker durable; directory sync failed: %w", err)}
	}
	if err := os.Remove(transactionPath); err != nil {
		return &ArtifactInstallError{Installed: true, Err: fmt.Errorf("commit marker durable; transaction journal cleanup failed: %w", err)}
	}
	if err := syncArtifactDirectory(filepath.Dir(binaryTarget)); err != nil {
		return &ArtifactInstallError{Installed: true, Err: fmt.Errorf("commit marker durable; journal cleanup sync failed: %w", err)}
	}
	return nil
}

func artifactTransactionPath(metadataTarget string) string {
	return metadataTarget + ".ix-control-transaction.json"
}

func writeArtifactTransaction(name string, tx artifactTransaction) error {
	b, err := json.Marshal(tx)
	if err != nil {
		return err
	}
	directory := filepath.Dir(name)
	tmp, err := os.CreateTemp(directory, ".ix-control-artifact-transaction-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := artifactRename(tmpName, name); err != nil {
		return err
	}
	return syncArtifactDirectory(directory)
}

func recoverArtifactTransaction(binaryTarget, metadataTarget string) error {
	journal := artifactTransactionPath(metadataTarget)
	info, err := os.Lstat(journal)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode()&fs.ModeSymlink != 0 {
		return fmt.Errorf("artifact transaction journal is unsafe or unreadable: %w", err)
	}
	b, err := os.ReadFile(journal)
	if err != nil {
		return fmt.Errorf("read artifact transaction journal: %w", err)
	}
	var tx artifactTransaction
	if err := json.Unmarshal(b, &tx); err != nil || tx.BinaryTarget != binaryTarget || tx.MetadataTarget != metadataTarget || tx.BinaryBackup != binaryTarget+".ix-control-backup" || tx.MetadataBackup != metadataTarget+".ix-control-backup" || !validArtifactTransactionPhase(tx.Phase, tx.Committed) {
		return errors.New("artifact transaction journal is invalid for requested targets")
	}
	var problems []string
	if tx.Committed {
		if err := removeArtifactBackup(tx.BinaryBackup); err != nil {
			problems = append(problems, "binary backup="+err.Error())
		}
		if err := removeArtifactBackup(tx.MetadataBackup); err != nil {
			problems = append(problems, "metadata backup="+err.Error())
		}
	} else {
		if err := recoverArtifactTarget(binaryTarget, tx.BinaryBackup, tx.BinaryOriginalPresent); err != nil {
			problems = append(problems, "restore binary="+err.Error())
		}
		if err := recoverArtifactTarget(metadataTarget, tx.MetadataBackup, tx.MetadataOriginalPresent); err != nil {
			problems = append(problems, "restore metadata="+err.Error())
		}
	}
	if len(problems) != 0 {
		return &ArtifactInstallError{Installed: tx.Committed, Err: fmt.Errorf("transaction recovery incomplete (committed=%t): %s", tx.Committed, strings.Join(problems, "; "))}
	}
	if err := os.Remove(journal); err != nil {
		return &ArtifactInstallError{Installed: tx.Committed, Err: fmt.Errorf("transaction recovery completed pair handling but journal removal failed: %w", err)}
	}
	if err := syncArtifactDirectory(filepath.Dir(binaryTarget)); err != nil {
		return &ArtifactInstallError{Installed: tx.Committed, Err: fmt.Errorf("transaction recovery completed but directory sync failed: %w", err)}
	}
	return nil
}

func validArtifactTransactionPhase(phase string, committed bool) bool {
	if committed {
		return phase == "committed"
	}
	switch phase {
	case "intention", "binary_backed_up", "metadata_backed_up", "replacing":
		return true
	default:
		return false
	}
}

// recoverArtifactTarget restores only a backup that exists. In the intentional
// crash window after the first backup, the untouched second target is retained.
func recoverArtifactTarget(target, backup string, originalPresent bool) error {
	_, err := os.Lstat(backup)
	if errors.Is(err, fs.ErrNotExist) {
		if !originalPresent {
			if err := os.Remove(target); err != nil && !errors.Is(err, fs.ErrNotExist) {
				return err
			}
		}
		return nil
	}
	if err != nil {
		return err
	}
	if err := os.Remove(target); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return restoreArtifactTarget(target, backup)
}

func artifactTargetPresent(target string) (bool, error) {
	_, err := os.Lstat(target)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	return err == nil, err
}

func backupArtifactTarget(target, backup string, present bool) error {
	if !present {
		return nil
	}
	info, err := os.Lstat(target)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode()&fs.ModeSymlink != 0 {
		return fmt.Errorf("target %s must be a regular non-symlink file", target)
	}
	if err := rejectUnsafeExistingTarget(backup); err != nil {
		return err
	}
	if _, err := os.Lstat(backup); !errors.Is(err, fs.ErrNotExist) {
		return errors.New("artifact backup already exists")
	}
	if err := artifactRename(target, backup); err != nil {
		return err
	}
	return nil
}

func restoreArtifactTarget(target, backup string) error {
	if backup == "" {
		return nil
	}
	return artifactRename(backup, target)
}
func removeArtifactBackup(backup string) error {
	if backup == "" {
		return nil
	}
	return os.Remove(backup)
}
func syncArtifactDirectory(directory string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	d, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
