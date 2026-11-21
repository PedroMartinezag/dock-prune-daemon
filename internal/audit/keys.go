// Package audit implements an Ed25519-signed SHA-256 Merkle JSONL audit ledger
// and replay-protected HMAC-SHA256 webhook notifications for SOC2/ISO27001 compliance.
package audit

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

const (
	pemTypePrivateKey = "PRIVATE KEY"
	pemTypePublicKey  = "PUBLIC KEY"
)

// KeyPair holds an Ed25519 signing keypair and its deterministic key identifier.
type KeyPair struct {
	PrivateKey ed25519.PrivateKey
	PublicKey  ed25519.PublicKey
	KeyID      string
}

// KeyIDFromPublic computes a deterministic fingerprint ("ed25519:<16-hex>") from
// a 32-byte Ed25519 public key so rotated keys remain verifiable in historical ledgers.
func KeyIDFromPublic(pub ed25519.PublicKey) string {
	if len(pub) != ed25519.PublicKeySize {
		return "ed25519:invalid"
	}
	sum := sha256.Sum256(pub)
	return "ed25519:" + hex.EncodeToString(sum[:8])
}

// GenerateKeyPair creates a fresh cryptographically random Ed25519 keypair in memory.
func GenerateKeyPair() (KeyPair, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return KeyPair{}, fmt.Errorf("generate ed25519 keypair: %w", err)
	}
	return KeyPair{
		PrivateKey: priv,
		PublicKey:  pub,
		KeyID:      KeyIDFromPublic(pub),
	}, nil
}

// LoadOrGenerateKeyPair loads an existing PKCS#8 Ed25519 keypair from disk (verifying
// public/private key mathematical correspondence) or atomically generates and persists
// a new keypair with strict 0600 permissions on the private key.
func LoadOrGenerateKeyPair(privPath, pubPath string) (KeyPair, error) {
	cleanPriv := strings.TrimSpace(privPath)
	cleanPub := strings.TrimSpace(pubPath)
	if cleanPriv == "" || cleanPub == "" {
		return KeyPair{}, errors.New("audit private_key_path and public_key_path cannot be empty")
	}

	privRaw, err := os.ReadFile(cleanPriv)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return KeyPair{}, fmt.Errorf("read ed25519 private key %q: %w", cleanPriv, err)
		}
		kp, genErr := GenerateKeyPair()
		if genErr != nil {
			return KeyPair{}, genErr
		}
		if writeErr := writePrivateKeyPEM(cleanPriv, kp.PrivateKey); writeErr != nil {
			return KeyPair{}, writeErr
		}
		if writeErr := writePublicKeyPEM(cleanPub, kp.PublicKey); writeErr != nil {
			return KeyPair{}, writeErr
		}
		return kp, nil
	}

	// Enforce 0600 mode on existing private key files on Unix platforms.
	if runtime.GOOS != "windows" {
		if info, statErr := os.Stat(cleanPriv); statErr == nil && info.Mode().Perm()&0o077 != 0 {
			_ = os.Chmod(cleanPriv, 0o600)
		}
	}

	privKey, err := parsePrivateKeyBytes(privRaw)
	if err != nil {
		return KeyPair{}, fmt.Errorf("parse ed25519 private key %q: %w", cleanPriv, err)
	}
	derivedPub, ok := privKey.Public().(ed25519.PublicKey)
	if !ok || len(derivedPub) != ed25519.PublicKeySize {
		return KeyPair{}, errors.New("failed to derive valid ed25519 public key")
	}

	if pubRaw, pubErr := os.ReadFile(cleanPub); pubErr == nil {
		diskPub, parseErr := parsePublicKeyBytes(pubRaw)
		if parseErr != nil {
			return KeyPair{}, fmt.Errorf("parse ed25519 public key %q: %w", cleanPub, parseErr)
		}
		if !bytes.Equal(derivedPub, diskPub) {
			return KeyPair{}, fmt.Errorf("ed25519 public key %q does not match private key %q", cleanPub, cleanPriv)
		}
	} else if errors.Is(pubErr, os.ErrNotExist) {
		if writeErr := writePublicKeyPEM(cleanPub, derivedPub); writeErr != nil {
			return KeyPair{}, writeErr
		}
	} else {
		return KeyPair{}, fmt.Errorf("read ed25519 public key %q: %w", cleanPub, pubErr)
	}

	return KeyPair{
		PrivateKey: privKey,
		PublicKey:  derivedPub,
		KeyID:      KeyIDFromPublic(derivedPub),
	}, nil
}

// LoadPublicKey reads an Ed25519 public key from PKIX PEM or 64-char hex format
// for offline audit verification without requiring access to the private key.
func LoadPublicKey(pubPath string) (ed25519.PublicKey, string, error) {
	cleanPub := strings.TrimSpace(pubPath)
	if cleanPub == "" {
		return nil, "", errors.New("public key path cannot be empty")
	}
	raw, err := os.ReadFile(cleanPub)
	if err != nil {
		return nil, "", fmt.Errorf("read public key %q: %w", cleanPub, err)
	}
	pub, err := parsePublicKeyBytes(raw)
	if err != nil {
		return nil, "", fmt.Errorf("parse public key %q: %w", cleanPub, err)
	}
	return pub, KeyIDFromPublic(pub), nil
}

func parsePrivateKeyBytes(raw []byte) (ed25519.PrivateKey, error) {
	trimmed := bytes.TrimSpace(raw)
	if block, _ := pem.Decode(trimmed); block != nil {
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse PKCS#8 private key: %w", err)
		}
		edPriv, ok := parsed.(ed25519.PrivateKey)
		if !ok || len(edPriv) != ed25519.PrivateKeySize {
			return nil, errors.New("PKCS#8 key is not an Ed25519 private key")
		}
		return edPriv, nil
	}

	decodedHex, err := hex.DecodeString(string(trimmed))
	if err == nil {
		switch len(decodedHex) {
		case ed25519.SeedSize:
			return ed25519.NewKeyFromSeed(decodedHex), nil
		case ed25519.PrivateKeySize:
			return ed25519.PrivateKey(decodedHex), nil
		}
	}
	return nil, errors.New("unsupported private key encoding (expected PKCS#8 PEM or hex seed)")
}

func parsePublicKeyBytes(raw []byte) (ed25519.PublicKey, error) {
	trimmed := bytes.TrimSpace(raw)
	if block, _ := pem.Decode(trimmed); block != nil {
		parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse PKIX public key: %w", err)
		}
		edPub, ok := parsed.(ed25519.PublicKey)
		if !ok || len(edPub) != ed25519.PublicKeySize {
			return nil, errors.New("PKIX key is not an Ed25519 public key")
		}
		return edPub, nil
	}

	decodedHex, err := hex.DecodeString(string(trimmed))
	if err == nil && len(decodedHex) == ed25519.PublicKeySize {
		return ed25519.PublicKey(decodedHex), nil
	}
	return nil, errors.New("unsupported public key encoding (expected PKIX PEM or 64-char hex)")
}

func writePrivateKeyPEM(path string, priv ed25519.PrivateKey) error {
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return fmt.Errorf("marshal PKCS#8 private key: %w", err)
	}
	encoded := pem.EncodeToMemory(&pem.Block{
		Type:  pemTypePrivateKey,
		Bytes: der,
	})
	return writeFileAtomic(path, encoded, 0o600, 0o700)
}

func writePublicKeyPEM(path string, pub ed25519.PublicKey) error {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return fmt.Errorf("marshal PKIX public key: %w", err)
	}
	encoded := pem.EncodeToMemory(&pem.Block{
		Type:  pemTypePublicKey,
		Bytes: der,
	})
	return writeFileAtomic(path, encoded, 0o644, 0o755)
}

func writeFileAtomic(targetPath string, content []byte, filePerm, dirPerm os.FileMode) error {
	dir := filepath.Dir(targetPath)
	if err := os.MkdirAll(dir, dirPerm); err != nil {
		return fmt.Errorf("create directory %q: %w", dir, err)
	}

	tmpFile, err := os.CreateTemp(dir, ".dpd-tmp-*")
	if err != nil {
		return fmt.Errorf("create temp file in %q: %w", dir, err)
	}
	tmpName := tmpFile.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()

	if err := tmpFile.Chmod(filePerm); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("chmod temp file %q: %w", tmpName, err)
	}
	if _, err := tmpFile.Write(content); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("write temp file %q: %w", tmpName, err)
	}
	if err := tmpFile.Sync(); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("fsync temp file %q: %w", tmpName, err)
	}
	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("close temp file %q: %w", tmpName, err)
	}
	if err := os.Rename(tmpName, targetPath); err != nil {
		return fmt.Errorf("atomic rename %q -> %q: %w", tmpName, targetPath, err)
	}
	cleanup = false
	return nil
}
