package audit

import (
	"bufio"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PedroMartinezag/dock-prune-daemon/internal/config"
	"github.com/PedroMartinezag/dock-prune-daemon/internal/disk"
	"github.com/PedroMartinezag/dock-prune-daemon/internal/engine"
)

func TestKeyPair_GenerateReload_Permissions_AndMismatchDetection(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	privPath := filepath.Join(dir, "ed25519.key")
	pubPath := filepath.Join(dir, "ed25519.pub")

	kp1, err := LoadOrGenerateKeyPair(privPath, pubPath)
	if err != nil {
		t.Fatalf("LoadOrGenerateKeyPair initial error: %v", err)
	}
	if !strings.HasPrefix(kp1.KeyID, "ed25519:") {
		t.Fatalf("unexpected KeyID format: %s", kp1.KeyID)
	}

	if runtime.GOOS != "windows" {
		st, err := os.Stat(privPath)
		if err != nil {
			t.Fatalf("stat private key: %v", err)
		}
		if st.Mode().Perm() != 0o600 {
			t.Fatalf("private key mode = %o, want 0600", st.Mode().Perm())
		}
	}

	// Reloading existing files must return the exact same keypair
	kp2, err := LoadOrGenerateKeyPair(privPath, pubPath)
	if err != nil {
		t.Fatalf("LoadOrGenerateKeyPair reload error: %v", err)
	}
	if kp2.KeyID != kp1.KeyID {
		t.Fatalf("reloaded KeyID %s != initial %s", kp2.KeyID, kp1.KeyID)
	}

	// Overwriting pubPath with an unrelated public key must be caught immediately!
	otherKP, _ := GenerateKeyPair()
	if err := writePublicKeyPEM(pubPath, otherKP.PublicKey); err != nil {
		t.Fatalf("overwrite pubPath: %v", err)
	}
	if _, err := LoadOrGenerateKeyPair(privPath, pubPath); err == nil {
		t.Fatal("expected error when public key on disk does not match private key")
	}
}

func TestLedger_MerkleChain_TamperDetection_HeadTruncation_AndRotationAnchor(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	auditCfg := config.AuditConfig{
		Enabled:        true,
		LedgerPath:     filepath.Join(dir, "audit.jsonl"),
		PrivateKeyPath: filepath.Join(dir, "ed25519.key"),
		PublicKeyPath:  filepath.Join(dir, "ed25519.pub"),
		MaxLedgerBytes: 50 * config.MiB,
	}

	ledger, err := NewLedger(auditCfg)
	if err != nil {
		t.Fatalf("NewLedger: %v", err)
	}

	t0 := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	for i := 1; i <= 3; i++ {
		rep := engine.CycleReport{
			CycleID:                  "cyc-0" + string(rune('0'+i)),
			Trigger:                  "periodic",
			StartedAt:                t0.Add(time.Duration(i) * time.Minute),
			CompletedAt:              t0.Add(time.Duration(i)*time.Minute + 2*time.Second),
			Duration:                 2 * time.Second,
			InitialRegime:            disk.RegimeElevated,
			FinalRegime:              disk.RegimeNominal,
			ActualDiskReclaimedBytes: uint64(i) * 1024 * 1024 * 1024,
			TargetSatisfied:          true,
		}
		if _, err := ledger.Append(rep); err != nil {
			t.Fatalf("Append(%d) error: %v", i, err)
		}
	}

	pubKey, _, err := LoadPublicKey(auditCfg.PublicKeyPath)
	if err != nil {
		t.Fatalf("LoadPublicKey: %v", err)
	}

	vres, err := VerifyFile(auditCfg.LedgerPath, pubKey)
	if err != nil {
		t.Fatalf("VerifyFile failed on valid ledger: %v", err)
	}
	if vres.VerifiedCount != 3 || vres.FirstSequence != 1 || vres.LastSequence != 3 {
		t.Fatalf("unexpected VerifyResult: %+v", vres)
	}

	// Reopening ledger across daemon restart must resume cleanly at sequence 4
	reopened, err := NewLedger(auditCfg)
	if err != nil {
		t.Fatalf("reopen NewLedger: %v", err)
	}
	rec4, err := reopened.Append(engine.CycleReport{
		CycleID:       "cyc-04",
		Trigger:       "manual",
		StartedAt:     t0.Add(10 * time.Minute),
		CompletedAt:   t0.Add(10*time.Minute + time.Second),
		InitialRegime: disk.RegimeCritical,
		FinalRegime:   disk.RegimeNominal,
	})
	if err != nil || rec4.Sequence != 4 {
		t.Fatalf("expected resumed Sequence=4, got seq=%d err=%v", rec4.Sequence, err)
	}

	rawLines := readLines(t, auditCfg.LedgerPath)
	if len(rawLines) != 4 {
		t.Fatalf("expected 4 JSONL lines, got %d", len(rawLines))
	}

	// Attack 1: Wrong Ed25519 public key rejected
	wrongKP, _ := GenerateKeyPair()
	if _, err := VerifyFile(auditCfg.LedgerPath, wrongKP.PublicKey); err == nil {
		t.Fatal("expected signature verification failure with wrong Ed25519 public key")
	}

	// Attack 2: Modify payload field inside line 2 -> caught!
	tamperedPayloadPath := filepath.Join(dir, "tampered_payload.jsonl")
	mutatedLine2 := strings.Replace(rawLines[1], `"periodic"`, `"forged"`, 1)
	writeLines(t, tamperedPayloadPath, []string{rawLines[0], mutatedLine2, rawLines[2], rawLines[3]})
	if _, err := VerifyFile(tamperedPayloadPath, pubKey); err == nil {
		t.Fatal("expected tamper error on modified payload field")
	}

	// Attack 3: Delete middle record (line 2) -> caught!
	deletedMidPath := filepath.Join(dir, "deleted_mid.jsonl")
	writeLines(t, deletedMidPath, []string{rawLines[0], rawLines[2], rawLines[3]})
	if _, err := VerifyFile(deletedMidPath, pubKey); err == nil {
		t.Fatal("expected chain/sequence break error when middle record is deleted")
	}

	// Attack 4: Head-truncation attack (delete line 1 so unanchored seq=2 is at top) -> caught!
	headTruncPath := filepath.Join(dir, "head_trunc.jsonl")
	writeLines(t, headTruncPath, []string{rawLines[1], rawLines[2], rawLines[3]})
	if _, err := VerifyFile(headTruncPath, pubKey); err == nil {
		t.Fatal("expected head-truncation detection when genesis record is stripped without signed anchor")
	}

	// Legitimate size rotation sets signed ChainAnchor=true so post-rotation VerifyFile succeeds!
	reopened.maxBytes = 100 // Force rotation on next append
	rec5, err := reopened.Append(engine.CycleReport{
		CycleID:     "cyc-05-rotated",
		Trigger:     "periodic",
		StartedAt:   t0.Add(20 * time.Minute),
		CompletedAt: t0.Add(20*time.Minute + time.Second),
	})
	if err != nil {
		t.Fatalf("Append across rotation error: %v", err)
	}
	if !rec5.ChainAnchor || rec5.Sequence != 5 {
		t.Fatalf("expected ChainAnchor=true and Sequence=5 after rotation, got %+v", rec5)
	}
	rotRes, err := VerifyFile(auditCfg.LedgerPath, pubKey)
	if err != nil {
		t.Fatalf("VerifyFile failed on legitimately rotated ledger: %v", err)
	}
	if !rotRes.AnchoredStart || rotRes.FirstSequence != 5 || rotRes.VerifiedCount != 1 {
		t.Fatalf("unexpected rotated VerifyResult: %+v", rotRes)
	}
}

func TestWebhookNotifier_HMACSignature_Retry503_AndCleanDrain(t *testing.T) {
	t.Parallel()

	const secret = "b2b-enterprise-hmac-secret-2026"
	var attempts atomic.Int32
	var verifiedOK atomic.Bool

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := attempts.Add(1)
		body, _ := io.ReadAll(r.Body)
		ts := r.Header.Get(headerTimestamp)
		sig := r.Header.Get(headerSignature256)

		if !VerifyWebhookSignature(secret, ts, sig, body) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		// Simulate transient 503 failure on first 2 attempts, then 200 OK on 3rd!
		if n < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		verifiedOK.Store(true)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	notifier := NewNotifier(config.AuditConfig{
		WebhookURL:        srv.URL,
		WebhookHMACSecret: secret,
		WebhookTimeout:    config.Duration(2 * time.Second),
		WebhookMaxRetries: 3,
	})
	notifier.baseDelay = 10 * time.Millisecond

	queued := notifier.Enqueue(
		engine.CycleReport{CycleID: "cyc-webhook-1", Trigger: "periodic"},
		Record{Sequence: 7, RecordHash: strings.Repeat("b", 64)},
	)
	if !queued {
		t.Fatal("expected Enqueue to succeed")
	}

	drainCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := notifier.Close(drainCtx); err != nil {
		t.Fatalf("Close drain failed: %v", err)
	}

	if !verifiedOK.Load() || attempts.Load() != 3 {
		t.Fatalf("expected 3 attempts ending in verified 200 OK, got attempts=%d verified=%v",
			attempts.Load(), verifiedOK.Load())
	}
	delivered, failed, dropped := notifier.Stats()
	if delivered != 1 || failed != 0 || dropped != 0 {
		t.Fatalf("unexpected stats: delivered=%d failed=%d dropped=%d", delivered, failed, dropped)
	}

	// Tampered body must fail constant-time VerifyWebhookSignature
	sig := ComputeWebhookSignature(secret, "1700000000", []byte(`{"ok":true}`))
	if VerifyWebhookSignature(secret, "1700000000", sig, []byte(`{"ok":false}`)) {
		t.Fatal("VerifyWebhookSignature accepted modified payload")
	}
}

func readLines(t *testing.T, path string) []string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer f.Close()

	var lines []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	return lines
}

func writeLines(t *testing.T, path string, lines []string) {
	t.Helper()
	content := strings.Join(lines, "\n") + "\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
