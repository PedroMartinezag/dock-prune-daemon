// Command dock-prune-daemon is an autonomous, zero-dependency container storage
// control plane combining OCI Layer Reference DAG math, Linux PSI adaptive I/O
// pacing, Holt-Winters ENOSPC forecasting, and Ed25519-signed Merkle audit logs.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/PedroMartinezag/dock-prune-daemon/internal/audit"
	"github.com/PedroMartinezag/dock-prune-daemon/internal/buildinfo"
	"github.com/PedroMartinezag/dock-prune-daemon/internal/config"
	"github.com/PedroMartinezag/dock-prune-daemon/internal/daemon"
	"github.com/PedroMartinezag/dock-prune-daemon/internal/disk"
	"github.com/PedroMartinezag/dock-prune-daemon/internal/docker"
	"github.com/PedroMartinezag/dock-prune-daemon/internal/engine"
	"github.com/PedroMartinezag/dock-prune-daemon/internal/finops"
	"github.com/PedroMartinezag/dock-prune-daemon/internal/kernel"
	"github.com/PedroMartinezag/dock-prune-daemon/internal/ui"
)

const (
	exitOK       = 0
	exitFailure  = 1
	exitBadUsage = 2
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr))
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		printRootUsage(stdout)
		return exitOK
	}

	sub := strings.TrimSpace(args[0])
	rest := args[1:]

	switch sub {
	case "daemon":
		return cmdDaemon(ctx, rest, stderr)
	case "once":
		return cmdOnce(ctx, rest, stdout, stderr)
	case "explain":
		return cmdExplain(ctx, rest, stdout, stderr)
	case "top":
		return cmdTop(ctx, rest, stdout, stderr)
	case "doctor":
		return cmdDoctor(ctx, rest, stdout, stderr)
	case "roi":
		return cmdROI(rest, stdout, stderr)
	case "verify-audit":
		return cmdVerifyAudit(rest, stdout, stderr)
	case "version", "--version", "-v":
		return cmdVersion(rest, stdout, stderr)
	case "help", "--help", "-h":
		printRootUsage(stdout)
		return exitOK
	default:
		fmt.Fprintf(stderr, "unknown subcommand %q\n\n", sub)
		printRootUsage(stderr)
		return exitBadUsage
	}
}

func cmdDaemon(ctx context.Context, args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("daemon", flag.ContinueOnError)
	fs.SetOutput(stderr)
	overrides := config.BindFlags(fs)
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitBadUsage
	}

	cfg, err := config.Load("", os.LookupEnv, overrides)
	if err != nil {
		fmt.Fprintf(stderr, "configuration error: %v\n", err)
		return exitBadUsage
	}

	logger := buildLogger(cfg, stderr)
	cfgPath := overrides.ConfigPath(os.LookupEnv)
	store, err := config.NewStore(cfg, cfgPath, os.LookupEnv)
	if err != nil {
		logger.Error("init config store failed", "error", err)
		return exitFailure
	}

	eng, err := docker.NewClient(cfg.Docker)
	if err != nil {
		logger.Error("init docker engine client failed", "error", err)
		return exitFailure
	}
	defer eng.Close()

	coord, err := daemon.NewCoordinator(daemon.Options{
		ConfigStore: store,
		Engine:      eng,
		Logger:      logger,
	})
	if err != nil {
		logger.Error("init control-plane coordinator failed", "error", err)
		return exitFailure
	}

	// Wire OS SIGHUP (atomic hot-reload) and SIGUSR1 (immediate manual cycle trigger).
	if reloadSigs := daemon.ReloadSignals(); len(reloadSigs) > 0 {
		reloadCh := make(chan os.Signal, 1)
		signal.Notify(reloadCh, reloadSigs...)
		defer signal.Stop(reloadCh)
		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				case <-reloadCh:
					_, _ = coord.Reload()
				}
			}
		}()
	}

	if trigSigs := daemon.TriggerSignals(); len(trigSigs) > 0 {
		trigCh := make(chan os.Signal, 1)
		signal.Notify(trigCh, trigSigs...)
		defer signal.Stop(trigCh)
		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				case <-trigCh:
					cur := store.Current()
					_, _ = coord.TriggerNow(ctx, "sigusr1", cur.DryRun, true)
				}
			}
		}()
	}

	if err := coord.Run(ctx); err != nil {
		logger.Error("daemon exited with error", "error", err)
		return exitFailure
	}
	return exitOK
}

func cmdOnce(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("once", flag.ContinueOnError)
	fs.SetOutput(stderr)
	overrides := config.BindFlags(fs)
	forceFlag := fs.Bool("force", false, "Run waterfall down to target_percent even when below high_percent")
	jsonFlag := fs.Bool("json", false, "Emit machine-readable CycleReport JSON")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitBadUsage
	}

	cfg, err := config.Load("", os.LookupEnv, overrides)
	if err != nil {
		fmt.Fprintf(stderr, "configuration error: %v\n", err)
		return exitBadUsage
	}

	eng, err := docker.NewClient(cfg.Docker)
	if err != nil {
		fmt.Fprintf(stderr, "docker client error: %v\n", err)
		return exitFailure
	}
	defer eng.Close()

	pruner, err := engine.NewPruner(engine.Dependencies{Engine: eng})
	if err != nil {
		fmt.Fprintf(stderr, "init pruner error: %v\n", err)
		return exitFailure
	}

	rep, err := pruner.RunCycle(ctx, cfg, engine.RunOptions{
		Trigger: "cli-once",
		Force:   *forceFlag,
	})
	if err != nil {
		fmt.Fprintf(stderr, "reclamation cycle failed: %v\n", err)
		return exitFailure
	}

	// Best-effort FinOps & Ed25519 Merkle audit recording when state_dir is writable.
	if tracker, tErr := finops.LoadOrNew(cfg.StateDir); tErr == nil {
		_ = tracker.RecordCycle(rep)
	}
	if cfg.Audit.Enabled {
		if ledger, lErr := audit.NewLedger(cfg.Audit); lErr == nil {
			if rec, aErr := ledger.Append(rep); aErr == nil && cfg.Audit.WebhookURL != "" {
				notifier := audit.NewNotifier(cfg.Audit)
				notifier.Enqueue(rep, rec)
				drainCtx, cancel := context.WithTimeout(ctx, cfg.Audit.WebhookTimeout.Std())
				_ = notifier.Close(drainCtx)
				cancel()
			}
		}
	}

	if *jsonFlag {
		return writePrettyJSON(stdout, stderr, rep)
	}

	renderer := ui.AutoRenderer(os.LookupEnv)
	_, _ = io.WriteString(stdout, renderer.RenderCycle(rep))
	return exitOK
}

func cmdExplain(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("explain", flag.ContinueOnError)
	fs.SetOutput(stderr)
	overrides := config.BindFlags(fs)
	jsonFlag := fs.Bool("json", false, "Emit machine-readable ExplainReport JSON")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitBadUsage
	}

	cfg, err := config.Load("", os.LookupEnv, overrides)
	if err != nil {
		fmt.Fprintf(stderr, "configuration error: %v\n", err)
		return exitBadUsage
	}

	eng, err := docker.NewClient(cfg.Docker)
	if err != nil {
		fmt.Fprintf(stderr, "docker client error: %v\n", err)
		return exitFailure
	}
	defer eng.Close()

	pruner, err := engine.NewPruner(engine.Dependencies{Engine: eng})
	if err != nil {
		fmt.Fprintf(stderr, "init pruner error: %v\n", err)
		return exitFailure
	}

	exp, err := pruner.Explain(ctx, cfg)
	if err != nil {
		fmt.Fprintf(stderr, "OCI layer DAG inspection failed: %v\n", err)
		return exitFailure
	}

	if *jsonFlag {
		return writePrettyJSON(stdout, stderr, exp)
	}

	renderer := ui.AutoRenderer(os.LookupEnv)
	_, _ = io.WriteString(stdout, renderer.RenderExplain(exp))
	return exitOK
}

func cmdTop(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("top", flag.ContinueOnError)
	fs.SetOutput(stderr)
	overrides := config.BindFlags(fs)
	intervalStr := fs.String("interval", "2s", "Refresh interval (for example, 1s, 2s, 5s)")
	iterations := fs.Int("iterations", 0, "Stop after N frames (0 runs until Ctrl+C)")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitBadUsage
	}

	interval, err := time.ParseDuration(strings.TrimSpace(*intervalStr))
	if err != nil || interval < 250*time.Millisecond {
		fmt.Fprintf(stderr, "invalid --interval %q (must be >= 250ms)\n", *intervalStr)
		return exitBadUsage
	}

	cfg, err := config.Load("", os.LookupEnv, overrides)
	if err != nil {
		fmt.Fprintf(stderr, "configuration error: %v\n", err)
		return exitBadUsage
	}

	eng, err := docker.NewClient(cfg.Docker)
	if err != nil {
		fmt.Fprintf(stderr, "docker client error: %v\n", err)
		return exitFailure
	}
	defer eng.Close()

	probe := disk.NewOSProbe()
	fc := disk.NewForecaster(cfg.Forecast, cfg.Watermarks.PanicFreeBytes)
	gov := kernel.NewGovernor(cfg.Kernel)
	phantom := kernel.NewPhantomScanner(cfg.Kernel, cfg.Docker.ContainerRootDir)
	tracker, _ := finops.LoadOrNew(cfg.StateDir)
	renderer := ui.AutoRenderer(os.LookupEnv)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for step := 1; ; step++ {
		_, _ = eng.Ping(ctx)
		snap, mErr := probe.Measure(cfg.Docker.ContainerRootDir)
		if mErr != nil {
			fmt.Fprintf(stderr, "statfs error: %v\n", mErr)
			return exitFailure
		}
		fcRes := fc.Observe(snap)
		assess := disk.Evaluate(snap, fcRes, cfg.Watermarks, cfg.Forecast)
		psiSnap, _ := gov.ReadSnapshot()
		phRep, _ := phantom.Scan()

		var roiRep finops.Report
		if tracker != nil {
			roiRep = tracker.Snapshot(cfg.Telemetry)
		}

		frame := ui.TopFrame{
			CapturedAt: time.Now().UTC(),
			Iteration:  step,
			Regime:     assess.Regime,
			Disk:       snap,
			Forecast:   fcRes,
			PSI:        psiSnap,
			Breaker:    eng.BreakerStats(),
			Phantom:    phRep,
			FinOps:     roiRep,
		}
		_, _ = io.WriteString(stdout, renderer.RenderTopFrame(frame, *iterations != 1))

		if *iterations > 0 && step >= *iterations {
			return exitOK
		}

		select {
		case <-ctx.Done():
			return exitOK
		case <-ticker.C:
		}
	}
}

func cmdDoctor(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	fs.SetOutput(stderr)
	overrides := config.BindFlags(fs)
	jsonFlag := fs.Bool("json", false, "Emit machine-readable DoctorReport JSON")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitBadUsage
	}

	cfg, err := config.Load("", os.LookupEnv, overrides)
	if err != nil {
		fmt.Fprintf(stderr, "configuration error: %v\n", err)
		return exitBadUsage
	}

	rep := ui.DoctorReport{
		CheckedAt: time.Now().UTC(),
		Healthy:   true,
	}

	// Check 1: Docker Engine Socket & API Negotiation
	eng, err := docker.NewClient(cfg.Docker)
	if err != nil {
		rep.Healthy = false
		rep.Checks = append(rep.Checks, ui.DoctorCheck{
			Name:        "Docker Socket Endpoint",
			Status:      ui.CheckFail,
			Summary:     err.Error(),
			Remediation: "Verify --docker-host or DPD_DOCKER_HOST points to a valid unix:// or tcp:// socket.",
		})
	} else {
		defer eng.Close()
		ping, pErr := eng.Ping(ctx)
		if pErr != nil {
			rep.Healthy = false
			rep.Checks = append(rep.Checks, ui.DoctorCheck{
				Name:        "Docker Engine Connectivity",
				Status:      ui.CheckFail,
				Summary:     pErr.Error(),
				Remediation: "Ensure dockerd is running and current user/service has rw access to /var/run/docker.sock.",
			})
		} else {
			rep.APIVersion = ping.APIVersion
			if ver, vErr := eng.Version(ctx); vErr == nil {
				rep.DockerVersion = ver.Version
			}
			rep.Checks = append(rep.Checks, ui.DoctorCheck{
				Name:    "Docker Engine Connectivity",
				Status:  ui.CheckPass,
				Summary: fmt.Sprintf("Connected (Engine %s, Negotiated API v%s)", nonEmptyStr(rep.DockerVersion, "ok"), ping.APIVersion),
			})
		}
	}

	// Check 2 & 3: Backing Filesystem Blocks & Inode Table
	probe := disk.NewOSProbe()
	snap, sErr := probe.Measure(cfg.Docker.ContainerRootDir)
	if sErr != nil {
		rep.Healthy = false
		rep.Checks = append(rep.Checks, ui.DoctorCheck{
			Name:        "Container Root Statfs",
			Status:      ui.CheckFail,
			Summary:     sErr.Error(),
			Remediation: fmt.Sprintf("Verify directory %q exists and is mounted.", cfg.Docker.ContainerRootDir),
		})
	} else {
		rep.Disk = snap
		blockSt := ui.CheckPass
		blockRem := ""
		if snap.UsedPercent >= cfg.Watermarks.CriticalPercent {
			blockSt = ui.CheckWarn
			blockRem = "Run 'dock-prune-daemon once' to reclaim space down to target watermark."
		}
		rep.Checks = append(rep.Checks, ui.DoctorCheck{
			Name:        "Block Storage Capacity",
			Status:      blockSt,
			Summary:     fmt.Sprintf("%.1f%% used (%s free of %s)", snap.UsedPercent, ui.FormatUintBytes(snap.FreeBytes), ui.FormatUintBytes(snap.TotalBytes)),
			Remediation: blockRem,
		})

		if snap.TotalInodes > 0 {
			inodeSt := ui.CheckPass
			inodeRem := ""
			if snap.InodeUsedPercent >= cfg.Watermarks.InodeHighPercent {
				inodeSt = ui.CheckWarn
				inodeRem = "High inode saturation detected; prune dangling layers and small container artifacts."
			}
			rep.Checks = append(rep.Checks, ui.DoctorCheck{
				Name:        "Filesystem Inode Headroom",
				Status:      inodeSt,
				Summary:     fmt.Sprintf("%.1f%% used (%d free inodes)", snap.InodeUsedPercent, snap.FreeInodes),
				Remediation: inodeRem,
			})
		}
	}

	// Check 4: Linux Kernel Pressure Stall Information (PSI)
	gov := kernel.NewGovernor(cfg.Kernel)
	psiSnap, _ := gov.ReadSnapshot()
	rep.PSI = psiSnap
	if psiSnap.Supported {
		rep.Checks = append(rep.Checks, ui.DoctorCheck{
			Name:    "Linux Kernel PSI Pacing",
			Status:  ui.CheckPass,
			Summary: fmt.Sprintf("Active (/proc/pressure/io avg10=%.2f%%)", psiSnap.IOSome.Avg10),
		})
	} else {
		rep.Checks = append(rep.Checks, ui.DoctorCheck{
			Name:        "Linux Kernel PSI Pacing",
			Status:      ui.CheckWarn,
			Summary:     "Unavailable (using static base_stage_pause fallback)",
			Remediation: "Boot Linux kernel >= 4.20 with CONFIG_PSI=y for adaptive I/O throttling.",
		})
	}

	// Check 5: ProcFS Unlinked Open-FD Forensics (Phantom Space Leaks)
	scanner := kernel.NewPhantomScanner(cfg.Kernel, cfg.Docker.ContainerRootDir)
	phRep, _ := scanner.Scan()
	rep.Phantom = phRep
	if !phRep.Supported {
		rep.Checks = append(rep.Checks, ui.DoctorCheck{
			Name:    "Phantom Open-FD Forensics",
			Status:  ui.CheckPass,
			Summary: "ProcFS scan skipped on non-Linux platform",
		})
	} else if len(phRep.Findings) > 0 {
		rep.Checks = append(rep.Checks, ui.DoctorCheck{
			Name:        "Phantom Open-FD Forensics",
			Status:      ui.CheckWarn,
			Summary:     fmt.Sprintf("%s trapped in %d deleted open file(s) across %d container(s)", ui.FormatBytes(phRep.TotalLeakedBytes), len(phRep.Findings), phRep.AffectedContainers),
			Remediation: "Restart affected containers or configure log rotation instead of unlinking active logs.",
		})
	} else {
		rep.Checks = append(rep.Checks, ui.DoctorCheck{
			Name:    "Phantom Open-FD Forensics",
			Status:  ui.CheckPass,
			Summary: fmt.Sprintf("0 leaked open FDs across %d inspected PIDs", phRep.ScannedPIDs),
		})
	}

	// Check 6: Ed25519 Merkle Audit Ledger Integrity (when existing ledger is present)
	if cfg.Audit.Enabled {
		if _, err := os.Stat(cfg.Audit.LedgerPath); err == nil {
			pubKey, keyID, kErr := audit.LoadPublicKey(cfg.Audit.PublicKeyPath)
			if kErr != nil {
				rep.Healthy = false
				rep.Checks = append(rep.Checks, ui.DoctorCheck{
					Name:        "Ed25519 Audit Ledger",
					Status:      ui.CheckFail,
					Summary:     kErr.Error(),
					Remediation: "Verify audit.public_key_path matches the ledger signing key.",
				})
			} else if vres, vErr := audit.VerifyFile(cfg.Audit.LedgerPath, pubKey); vErr != nil {
				rep.Healthy = false
				rep.Checks = append(rep.Checks, ui.DoctorCheck{
					Name:        "Ed25519 Audit Ledger",
					Status:      ui.CheckFail,
					Summary:     vErr.Error(),
					Remediation: "Investigate audit.jsonl tampering before resuming daemon.",
				})
			} else {
				rep.Checks = append(rep.Checks, ui.DoctorCheck{
					Name:    "Ed25519 Audit Ledger",
					Status:  ui.CheckPass,
					Summary: fmt.Sprintf("Verified %d signed Merkle record(s) (%s)", vres.VerifiedCount, keyID),
				})
			}
		}
	}

	if *jsonFlag {
		code := writePrettyJSON(stdout, stderr, rep)
		if code != exitOK || !rep.Healthy {
			return exitFailure
		}
		return exitOK
	}

	renderer := ui.AutoRenderer(os.LookupEnv)
	_, _ = io.WriteString(stdout, renderer.RenderDoctor(rep))
	if !rep.Healthy {
		return exitFailure
	}
	return exitOK
}

func cmdROI(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("roi", flag.ContinueOnError)
	fs.SetOutput(stderr)
	overrides := config.BindFlags(fs)
	mdFlag := fs.Bool("markdown", false, "Emit copy-pasteable Markdown FinOps ROI report")
	jsonFlag := fs.Bool("json", false, "Emit machine-readable FinOps Report JSON")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitBadUsage
	}

	cfg, err := config.Load("", os.LookupEnv, overrides)
	if err != nil {
		fmt.Fprintf(stderr, "configuration error: %v\n", err)
		return exitBadUsage
	}

	tracker, err := finops.LoadOrNew(cfg.StateDir)
	if err != nil {
		fmt.Fprintf(stderr, "load finops state failed: %v\n", err)
		return exitFailure
	}
	rep := tracker.Snapshot(cfg.Telemetry)

	if *jsonFlag {
		return writePrettyJSON(stdout, stderr, rep)
	}
	if *mdFlag {
		_, _ = io.WriteString(stdout, finops.FormatMarkdown(rep))
		return exitOK
	}

	renderer := ui.AutoRenderer(os.LookupEnv)
	_, _ = io.WriteString(stdout, renderer.RenderROI(rep))
	return exitOK
}

func cmdVerifyAudit(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("verify-audit", flag.ContinueOnError)
	fs.SetOutput(stderr)
	overrides := config.BindFlags(fs)
	ledgerFlag := fs.String("ledger", "", "Explicit path to audit.jsonl (defaults to config audit.ledger_path)")
	pubKeyFlag := fs.String("pubkey", "", "Explicit path to Ed25519 public key PEM (defaults to config audit.public_key_path)")
	jsonFlag := fs.Bool("json", false, "Emit verification result as JSON")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitBadUsage
	}

	cfg, err := config.Load("", os.LookupEnv, overrides)
	if err != nil {
		fmt.Fprintf(stderr, "configuration error: %v\n", err)
		return exitBadUsage
	}

	ledgerPath := strings.TrimSpace(*ledgerFlag)
	if ledgerPath == "" {
		ledgerPath = cfg.Audit.LedgerPath
	}
	pubPath := strings.TrimSpace(*pubKeyFlag)
	if pubPath == "" {
		pubPath = cfg.Audit.PublicKeyPath
	}

	pubKey, _, err := audit.LoadPublicKey(pubPath)
	if err != nil {
		fmt.Fprintf(stderr, "load ed25519 public key failed: %v\n", err)
		return exitFailure
	}

	res, err := audit.VerifyFile(ledgerPath, pubKey)
	if err != nil {
		fmt.Fprintf(stderr, "AUDIT VERIFICATION FAILED: %v\n", err)
		return exitFailure
	}

	if *jsonFlag {
		return writePrettyJSON(stdout, stderr, res)
	}

	renderer := ui.AutoRenderer(os.LookupEnv)
	_, _ = io.WriteString(stdout, renderer.RenderVerifyAudit(res))
	return exitOK
}

func cmdVersion(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("version", flag.ContinueOnError)
	fs.SetOutput(stderr)
	jsonFlag := fs.Bool("json", false, "Emit build provenance as JSON")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitBadUsage
	}
	if *jsonFlag {
		return writePrettyJSON(stdout, stderr, buildinfo.Get())
	}
	fmt.Fprintln(stdout, buildinfo.Summary())
	return exitOK
}

func buildLogger(cfg config.Config, out io.Writer) *slog.Logger {
	var level slog.Level
	switch cfg.LogLevel {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}

	opts := &slog.HandlerOptions{Level: level}
	if cfg.LogFormat == "text" {
		return slog.New(slog.NewTextHandler(out, opts))
	}
	return slog.New(slog.NewJSONHandler(out, opts))
}

func writePrettyJSON(stdout, stderr io.Writer, v any) int {
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		fmt.Fprintf(stderr, "encode JSON output failed: %v\n", err)
		return exitFailure
	}
	return exitOK
}

func printRootUsage(w io.Writer) {
	fmt.Fprintf(w, `%s

Usage:
  dock-prune-daemon <subcommand> [flags]

Subcommands:
  daemon        Run the autonomous kernel-aware container storage control plane
  once          Execute a single deterministic 5-stage reclamation cycle (CI/CD friendly)
  explain       Build the OCI Layer Reference DAG & Orphan Clique plan without deleting data
  top           Stream live block/inode pressure, Holt-Winters TTE, and Linux PSI in terminal
  doctor        Audit Docker socket, backing filesystem, PSI, Ed25519 ledger & phantom open FDs
  roi           Quantify cumulative GiB reclaimed, ENOSPC outages averted & USD FinOps value
  verify-audit  Verify SHA-256 Merkle hash chains & Ed25519 signatures on audit.jsonl
  version       Print static binary build provenance and zero-dependency contract

Run 'dock-prune-daemon <subcommand> --help' for subcommand-specific flags.
Sustained via GitHub Sponsors: https://github.com/sponsors/PedroMartinezag
`, buildinfo.Summary())
}

func nonEmptyStr(s, fallback string) string {
	if strings.TrimSpace(s) == "" {
		return fallback
	}
	return s
}
