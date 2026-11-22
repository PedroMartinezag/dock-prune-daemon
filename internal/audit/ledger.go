package audit

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/PedroMartinezag/dock-prune-daemon/internal/config"
	"github.com/PedroMartinezag/dock-prune-daemon/internal/disk"
	"github.com/PedroMartinezag/dock-prune-daemon/internal/engine"
)

// GenesisPrevHash anchors Sequence 1 of a newly initialized Merkle audit ledger.
const GenesisPrevHash = "0000000000000000000000000000000000000000000000000000000000000000"

const (
	auditSchemaVersion = "dpd-audit-v1"
	signDomainPrefix   = "dock-prune-daemon:audit:v1:"
	maxLedgerLineBytes = 4 << 20 // 4 MiB max single JSONL audit entry
)

// CycleSummary captures immutable compliance fields hashed inside an audit Record.
type CycleSummary struct {
	CycleID                  string      `json:"cycle_id"`
	Trigger                  string      `json:"trigger"`
	DryRun                   bool        `json:"dry_run"`
	InitialRegime            disk.Regime `json:"initial_regime"`
	FinalRegime              disk.Regime `json:"final_regime"`
	StartedAt                time.Time   `json:"started_at"`
	CompletedAt              time.Time   `json:"completed_at"`
	DurationMs               int64       `json:"duration_ms"`
	BeforeUsedPercent        float64     `json:"before_used_percent"`
	AfterUsedPercent         float64     `json:"after_used_percent"`
	ReportedReclaimedBytes   uint64      `json:"reported_reclaimed_bytes"`
	ActualDiskReclaimedBytes uint64      `json:"actual_disk_reclaimed_bytes"`
	TargetSatisfied          bool        `json:"target_satisfied"`
	BuildCachePreserved      bool        `json:"build_cache_preserved"`
	ENOSPCAverted            bool        `json:"enospc_averted"`
	StagesExecuted           []string    `json:"stages_executed,omitempty"`
	TruncatedLogs            int         `json:"truncated_logs"`
	ForensicLogDigests       []string    `json:"forensic_log_digests,omitempty"`
}

// SummarizeCycle projects an engine.CycleReport into a deterministic CycleSummary.
func SummarizeCycle(rep engine.CycleReport) CycleSummary {
	stages := make([]string, 0, len(rep.Stages))
	for _, st := range rep.Stages {
		if st.Executed {
			stages = append(stages, string(st.Stage))
		}
	}
	var digests []string
	for _, entry := range rep.LogEntries {
		if entry.ForensicSHA256 != "" {
			digests = append(digests, entry.ContainerID+":"+entry.ForensicSHA256)
		}
	}
	return CycleSummary{
		CycleID:                  rep.CycleID,
		Trigger:                  rep.Trigger,
		DryRun:                   rep.DryRun,
		InitialRegime:            rep.InitialRegime,
		FinalRegime:              rep.FinalRegime,
		StartedAt:                rep.StartedAt.UTC(),
		CompletedAt:              rep.CompletedAt.UTC(),
		DurationMs:               rep.Duration.Milliseconds(),
		BeforeUsedPercent:        rep.BeforeDisk.UsedPercent,
		AfterUsedPercent:         rep.AfterDisk.UsedPercent,
		ReportedReclaimedBytes:   rep.ReportedReclaimedBytes,
		ActualDiskReclaimedBytes: rep.ActualDiskReclaimedBytes,
		TargetSatisfied:          rep.TargetSatisfied,
		BuildCachePreserved:      rep.BuildCachePreserved,
		ENOSPCAverted:            rep.ENOSPCAverted,
		StagesExecuted:           stages,
		TruncatedLogs:            len(rep.LogEntries),
		ForensicLogDigests:       digests,
	}
}

// Record is a single line in audit.jsonl bound by a SHA-256 Merkle link and Ed25519 signature.
type Record struct {
	Schema      string       `json:"schema"`
	Sequence    uint64       `json:"sequence"`
	RecordedAt  time.Time    `json:"recorded_at"`
	ChainAnchor bool         `json:"chain_anchor,omitempty"`
	PrevHash    string       `json:"prev_hash"`
	PayloadHash string       `json:"payload_hash"`
	RecordHash  string       `json:"record_hash"`
	KeyID       string       `json:"key_id"`
	Signature   string       `json:"signature"`
	Summary     CycleSummary `json:"summary"`
}

// VerifyResult reports cryptographic verification metrics for an audit.jsonl file.
type VerifyResult struct {
	LedgerPath    string `json:"ledger_path"`
	VerifiedCount int    `json:"verified_count"`
	FirstSequence uint64 `json:"first_sequence"`
	LastSequence  uint64 `json:"last_sequence"`
	HeadHash      string `json:"head_hash"`
	KeyID         string `json:"key_id"`
	AnchoredStart bool   `json:"anchored_start"`
}

// Ledger manages append-only, fsynced, Ed25519-signed Merkle audit logs with size rotation.
type Ledger struct {
	mu         sync.Mutex
	enabled    bool
	ledgerPath string
	maxBytes   int64
	keys       KeyPair
	nowFn      func() time.Time
	seq        uint64
	lastHash   string
	nextAnchor bool
}

// NewLedger initializes or resumes an Ed25519-signed Merkle ledger on disk,
// verifying any pre-existing ledger chain before appending new records.
func NewLedger(cfg config.AuditConfig) (*Ledger, error) {
	if !cfg.Enabled {
		return &Ledger{enabled: false, nowFn: time.Now}, nil
	}

	ledgerPath := strings.TrimSpace(cfg.LedgerPath)
	if ledgerPath == "" {
		return nil, errors.New("audit.ledger_path cannot be empty when audit is enabled")
	}

	keys, err := LoadOrGenerateKeyPair(cfg.PrivateKeyPath, cfg.PublicKeyPath)
	if err != nil {
		return nil, err
	}

	if err := os.MkdirAll(filepath.Dir(ledgerPath), 0o750); err != nil {
		return nil, fmt.Errorf("create ledger directory: %w", err)
	}

	maxBytes := cfg.MaxLedgerBytes.Bytes()
	if maxBytes < (1 * config.MiB).Bytes() {
		maxBytes = (50 * config.MiB).Bytes()
	}

	l := &Ledger{
		enabled:    true,
		ledgerPath: ledgerPath,
		maxBytes:   maxBytes,
		keys:       keys,
		nowFn:      time.Now,
		seq:        0,
		lastHash:   GenesisPrevHash,
	}

	if _, statErr := os.Stat(ledgerPath); statErr == nil {
		vres, vErr := VerifyFile(ledgerPath, keys.PublicKey)
		if vErr != nil {
			return nil, fmt.Errorf("existing audit ledger failed integrity verification: %w", vErr)
		}
		if vres.VerifiedCount > 0 {
			l.seq = vres.LastSequence
			l.lastHash = vres.HeadHash
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return nil, fmt.Errorf("stat audit ledger %q: %w", ledgerPath, statErr)
	}

	return l, nil
}

// KeyID returns the deterministic public key fingerprint active on this ledger.
func (l *Ledger) KeyID() string {
	if l == nil {
		return ""
	}
	return l.keys.KeyID
}

// Append signs and appends a new reclamation cycle record to the Merkle ledger.
func (l *Ledger) Append(report engine.CycleReport) (Record, error) {
	if l == nil || !l.enabled {
		return Record{}, nil
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	if err := l.rotateIfNeededLocked(); err != nil {
		return Record{}, err
	}

	now := l.nowFn().UTC()
	nextSeq := l.seq + 1
	isAnchor := l.nextAnchor

	rec := Record{
		Schema:      auditSchemaVersion,
		Sequence:    nextSeq,
		RecordedAt:  now,
		ChainAnchor: isAnchor,
		PrevHash:    l.lastHash,
		KeyID:       l.keys.KeyID,
		Summary:     SummarizeCycle(report),
	}

	payloadHash, recordHash, err := computeHashes(rec)
	if err != nil {
		return Record{}, err
	}
	rec.PayloadHash = payloadHash
	rec.RecordHash = recordHash

	sig := ed25519.Sign(l.keys.PrivateKey, []byte(signDomainPrefix+recordHash))
	rec.Signature = hex.EncodeToString(sig)

	encoded, err := json.Marshal(rec)
	if err != nil {
		return Record{}, fmt.Errorf("marshal audit record: %w", err)
	}
	encoded = append(encoded, '\n')

	f, err := os.OpenFile(l.ledgerPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
	if err != nil {
		return Record{}, fmt.Errorf("open audit ledger %q: %w", l.ledgerPath, err)
	}
	_, writeErr := f.Write(encoded)
	syncErr := f.Sync()
	closeErr := f.Close()

	if writeErr != nil {
		return Record{}, fmt.Errorf("append audit ledger: %w", writeErr)
	}
	if syncErr != nil {
		return Record{}, fmt.Errorf("fsync audit ledger: %w", syncErr)
	}
	if closeErr != nil {
		return Record{}, fmt.Errorf("close audit ledger: %w", closeErr)
	}

	l.seq = nextSeq
	l.lastHash = recordHash
	l.nextAnchor = false
	return rec, nil
}

func (l *Ledger) rotateIfNeededLocked() error {
	info, err := os.Stat(l.ledgerPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("stat ledger before rotation: %w", err)
	}
	if info.Size() < l.maxBytes {
		return nil
	}

	stamp := l.nowFn().UTC().Format("20060102T150405.000000000Z")
	archivePath := fmt.Sprintf("%s.%s", l.ledgerPath, stamp)
	if err := os.Rename(l.ledgerPath, archivePath); err != nil {
		return fmt.Errorf("rotate audit ledger %q -> %q: %w", l.ledgerPath, archivePath, err)
	}
	// Mark the first entry of the newly rotated segment with a signed ChainAnchor
	// so offline verifiers distinguish legitimate rotation from head-truncation tampering.
	if l.seq > 0 {
		l.nextAnchor = true
	}
	return nil
}

// VerifyFile validates every line in a JSONL ledger against both the SHA-256 Merkle
// hash chain and the domain-separated Ed25519 public key signature.
func VerifyFile(ledgerPath string, pubKey ed25519.PublicKey) (VerifyResult, error) {
	if len(pubKey) != ed25519.PublicKeySize {
		return VerifyResult{}, errors.New("invalid ed25519 public key length")
	}
	f, err := os.Open(ledgerPath)
	if err != nil {
		return VerifyResult{}, fmt.Errorf("open ledger %q: %w", ledgerPath, err)
	}
	defer f.Close()

	expectedKeyID := KeyIDFromPublic(pubKey)
	res := VerifyResult{
		LedgerPath: ledgerPath,
		HeadHash:   GenesisPrevHash,
		KeyID:      expectedKeyID,
	}

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), maxLedgerLineBytes)

	var lineNum int
	var prevSeq uint64
	var expectedPrevHash string

	for scanner.Scan() {
		lineNum++
		raw := bytes.TrimSpace(scanner.Bytes())
		if len(raw) == 0 {
			continue
		}

		var rec Record
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&rec); err != nil {
			return res, fmt.Errorf("line %d: malformed JSON record: %w", lineNum, err)
		}

		if rec.Schema != auditSchemaVersion {
			return res, fmt.Errorf("line %d: unsupported schema %q", lineNum, rec.Schema)
		}
		if rec.KeyID != expectedKeyID {
			return res, fmt.Errorf("line %d: key_id mismatch (record=%q, verifier=%q)", lineNum, rec.KeyID, expectedKeyID)
		}

		if res.VerifiedCount == 0 {
			if rec.Sequence == 1 {
				if rec.PrevHash != GenesisPrevHash {
					return res, fmt.Errorf("line %d: genesis record has invalid prev_hash %q", lineNum, rec.PrevHash)
				}
			} else if rec.Sequence > 1 && rec.ChainAnchor {
				if len(rec.PrevHash) != 64 {
					return res, fmt.Errorf("line %d: anchored rotated record has malformed prev_hash", lineNum)
				}
				res.AnchoredStart = true
			} else {
				return res, fmt.Errorf("line %d: head-truncation detected (sequence=%d without signed chain_anchor)", lineNum, rec.Sequence)
			}
			res.FirstSequence = rec.Sequence
		} else {
			if rec.Sequence != prevSeq+1 {
				return res, fmt.Errorf("line %d: sequence discontinuity (got %d, expected %d)", lineNum, rec.Sequence, prevSeq+1)
			}
			if rec.PrevHash != expectedPrevHash {
				return res, fmt.Errorf("line %d: Merkle chain broken (prev_hash=%s, expected=%s)", lineNum, rec.PrevHash, expectedPrevHash)
			}
		}

		wantPayloadHash, wantRecordHash, err := computeHashes(rec)
		if err != nil {
			return res, fmt.Errorf("line %d: compute canonical hashes: %w", lineNum, err)
		}
		if rec.PayloadHash != wantPayloadHash {
			return res, fmt.Errorf("line %d: payload_hash tampered (got %s, want %s)", lineNum, rec.PayloadHash, wantPayloadHash)
		}
		if rec.RecordHash != wantRecordHash {
			return res, fmt.Errorf("line %d: record_hash tampered (got %s, want %s)", lineNum, rec.RecordHash, wantRecordHash)
		}

		sigBytes, err := hex.DecodeString(rec.Signature)
		if err != nil || len(sigBytes) != ed25519.SignatureSize {
			return res, fmt.Errorf("line %d: malformed ed25519 signature encoding", lineNum)
		}
		if !ed25519.Verify(pubKey, []byte(signDomainPrefix+rec.RecordHash), sigBytes) {
			return res, fmt.Errorf("line %d: invalid ed25519 cryptographic signature", lineNum)
		}

		prevSeq = rec.Sequence
		expectedPrevHash = rec.RecordHash
		res.VerifiedCount++
		res.LastSequence = rec.Sequence
		res.HeadHash = rec.RecordHash
	}

	if err := scanner.Err(); err != nil {
		return res, fmt.Errorf("scan ledger %q: %w", ledgerPath, err)
	}
	return res, nil
}

func computeHashes(rec Record) (payloadHash string, recordHash string, err error) {
	canonicalSummary, err := json.Marshal(rec.Summary)
	if err != nil {
		return "", "", fmt.Errorf("marshal canonical summary: %w", err)
	}
	pSum := sha256.Sum256(canonicalSummary)
	payloadHash = hex.EncodeToString(pSum[:])

	envelope := fmt.Sprintf(
		"%s|seq=%d|ts=%s|anchor=%t|prev=%s|key=%s|payload=%s",
		rec.Schema,
		rec.Sequence,
		rec.RecordedAt.UTC().Format(time.RFC3339Nano),
		rec.ChainAnchor,
		rec.PrevHash,
		rec.KeyID,
		payloadHash,
	)
	rSum := sha256.Sum256([]byte(envelope))
	recordHash = hex.EncodeToString(rSum[:])
	return payloadHash, recordHash, nil
}
