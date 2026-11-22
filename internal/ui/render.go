// Package ui renders deterministic ANSI and NO_COLOR terminal tables, pressure
// gauges, OCI Layer DAG explanations, host health diagnostics, live 'top' frames,
// and FinOps ROI reports with zero external TUI dependencies.
package ui

import (
	"fmt"
	"math"
	"os"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/PedroMartinezag/dock-prune-daemon/internal/audit"
	"github.com/PedroMartinezag/dock-prune-daemon/internal/config"
	"github.com/PedroMartinezag/dock-prune-daemon/internal/disk"
	"github.com/PedroMartinezag/dock-prune-daemon/internal/docker"
	"github.com/PedroMartinezag/dock-prune-daemon/internal/engine"
	"github.com/PedroMartinezag/dock-prune-daemon/internal/finops"
	"github.com/PedroMartinezag/dock-prune-daemon/internal/kernel"
)

const (
	ansiReset   = "\x1b[0m"
	ansiBold    = "\x1b[1m"
	ansiDim     = "\x1b[2m"
	ansiGreen   = "\x1b[32m"
	ansiYellow  = "\x1b[33m"
	ansiRed     = "\x1b[31m"
	ansiCyan    = "\x1b[36m"
	ansiMagenta = "\x1b[35m"
	ansiClear   = "\x1b[H\x1b[2J"
)

// CheckStatus classifies an individual diagnostic check inside 'dock-prune-daemon doctor'.
type CheckStatus string

const (
	CheckPass CheckStatus = "PASS"
	CheckWarn CheckStatus = "WARN"
	CheckFail CheckStatus = "FAIL"
)

// DoctorCheck represents a single subsystem health assertion and actionable remediation.
type DoctorCheck struct {
	Name        string      `json:"name"`
	Status      CheckStatus `json:"status"`
	Summary     string      `json:"summary"`
	Remediation string      `json:"remediation,omitempty"`
}

// DoctorReport aggregates complete host, kernel, socket, ledger, and phantom-FD diagnostics.
type DoctorReport struct {
	CheckedAt     time.Time            `json:"checked_at"`
	Healthy       bool                 `json:"healthy"`
	DockerVersion string               `json:"docker_version,omitempty"`
	APIVersion    string               `json:"api_version,omitempty"`
	Disk          disk.Snapshot        `json:"disk"`
	PSI           kernel.PSISnapshot   `json:"psi"`
	Phantom       kernel.PhantomReport `json:"phantom"`
	Checks        []DoctorCheck        `json:"checks"`
}

// TopFrame bundles real-time sensor telemetry rendered by 'dock-prune-daemon top'.
type TopFrame struct {
	CapturedAt time.Time            `json:"captured_at"`
	Iteration  int                  `json:"iteration"`
	Regime     disk.Regime          `json:"regime"`
	Disk       disk.Snapshot        `json:"disk"`
	Forecast   disk.ForecastResult  `json:"forecast"`
	PSI        kernel.PSISnapshot   `json:"psi"`
	Breaker    docker.BreakerStats  `json:"breaker"`
	Phantom    kernel.PhantomReport `json:"phantom"`
	FinOps     finops.Report        `json:"finops"`
	LastCycle  *engine.CycleReport  `json:"last_cycle,omitempty"`
}

// Renderer formats structured telemetry for interactive terminals and CI logs.
type Renderer struct {
	noColor bool
	width   int
}

// NewRenderer creates a terminal renderer with bounded column width.
func NewRenderer(noColor bool, width int) *Renderer {
	if width < 72 {
		width = 72
	}
	if width > 160 {
		width = 160
	}
	return &Renderer{
		noColor: noColor,
		width:   width,
	}
}

// AutoRenderer inspects NO_COLOR and TERM environment conventions (https://no-color.org/).
func AutoRenderer(lookup config.EnvLookupFunc) *Renderer {
	if lookup == nil {
		lookup = os.LookupEnv
	}
	_, hasNoColor := lookup("NO_COLOR")
	termVal, _ := lookup("TERM")
	dumbTerm := strings.EqualFold(strings.TrimSpace(termVal), "dumb")
	return NewRenderer(hasNoColor || dumbTerm, 108)
}

// FormatBytes formats signed byte counts using binary IEC units (GiB, MiB, KiB, B).
func FormatBytes(b int64) string {
	if b < 0 {
		if b == math.MinInt64 {
			return "-8.00 EiB"
		}
		return "-" + FormatUintBytes(uint64(-b))
	}
	return FormatUintBytes(uint64(b))
}

// FormatUintBytes formats unsigned byte counts into concise binary IEC strings.
func FormatUintBytes(b uint64) string {
	const (
		kib = 1024
		mib = 1024 * kib
		gib = 1024 * mib
		tib = 1024 * gib
	)
	switch {
	case b >= tib:
		return fmt.Sprintf("%.2f TiB", float64(b)/float64(tib))
	case b >= gib:
		return fmt.Sprintf("%.2f GiB", float64(b)/float64(gib))
	case b >= mib:
		return fmt.Sprintf("%.2f MiB", float64(b)/float64(mib))
	case b >= kib:
		return fmt.Sprintf("%.1f KiB", float64(b)/float64(kib))
	default:
		return fmt.Sprintf("%d B", b)
	}
}

// RenderBar draws a fixed-width Unicode block saturation bar colored by severity.
func (r *Renderer) RenderBar(pct float64, barWidth int) string {
	if barWidth < 8 {
		barWidth = 8
	}
	clamped := pct
	if math.IsNaN(clamped) || clamped < 0 {
		clamped = 0
	}
	if clamped > 100 {
		clamped = 100
	}

	filled := int(math.Round((clamped / 100.0) * float64(barWidth)))
	if filled > barWidth {
		filled = barWidth
	}
	barPlain := strings.Repeat("█", filled) + strings.Repeat("░", barWidth-filled)

	color := ansiGreen
	if clamped >= 90.0 {
		color = ansiRed
	} else if clamped >= 75.0 {
		color = ansiYellow
	}
	return "[" + r.paint(barPlain, color) + "]"
}

// RenderExplain formats the read-only OCI Layer Reference DAG & Orphan Clique analysis.
func (r *Renderer) RenderExplain(rep engine.ExplainReport) string {
	var b strings.Builder

	b.WriteString(r.paint("OCI LAYER REFERENCE DAG & SURGICAL RECLAMATION EXPLAIN", ansiBold))
	b.WriteByte('\n')
	b.WriteString(strings.Repeat("─", r.width))
	b.WriteByte('\n')

	fmt.Fprintf(&b, "Regime: %s  |  Root: %s  |  Breaker: %s\n",
		r.formatRegime(rep.Assessment.Regime),
		rep.Disk.Path,
		string(rep.Breaker.State),
	)
	fmt.Fprintf(&b, "Blocks: %s %5.1f%% (%s free / %s total)  |  Target Reclaim: %s\n",
		r.RenderBar(rep.Disk.UsedPercent, 20),
		rep.Disk.UsedPercent,
		FormatUintBytes(rep.Disk.FreeBytes),
		FormatUintBytes(rep.Disk.TotalBytes),
		FormatUintBytes(rep.Assessment.ReclaimTargetBytes),
	)
	fmt.Fprintf(&b, "Inodes: %s %5.1f%% (%d free / %d total)  |  TTE: %s\n",
		r.RenderBar(rep.Disk.InodeUsedPercent, 20),
		rep.Disk.InodeUsedPercent,
		rep.Disk.FreeInodes,
		rep.Disk.TotalInodes,
		formatTTE(rep.Forecast.BlockTTESeconds),
	)

	if rep.DAG != nil {
		b.WriteByte('\n')
		fmt.Fprintf(&b, "DAG Layer Topology: %d images -> %d unique OCI layers  |  Shared-Layer Illusion Ratio: %.2fx\n",
			len(rep.DAG.ImageOrder),
			len(rep.DAG.LayerOrder),
			rep.DAG.SharedBloatRatio,
		)
		fmt.Fprintf(&b, "Unique Layer Pool:  %s total  (%s pinned by containers/policy, %s unlockable)\n",
			FormatBytes(rep.DAG.TotalUniqueLayerBytes),
			FormatBytes(rep.DAG.PinnedLayerBytes),
			FormatBytes(rep.DAG.ReclaimableLayerBytes),
		)
	}

	if len(rep.Plan.OrphanCliques) > 0 {
		b.WriteByte('\n')
		b.WriteString(r.paint("Zero-Container Orphan Layer Cliques (Superlinear Shared Unlock):", ansiBold))
		b.WriteByte('\n')
		fmt.Fprintf(&b, "%s  %s  %s  %s  %s\n",
			padRight("CLIQUE", 10),
			padRight("IMAGES", 7),
			padRight("SHARED UNLOCK", 14),
			padRight("TOTAL RECLAIM", 14),
			"MEMBER TAGS",
		)
		for _, cl := range rep.Plan.OrphanCliques {
			fmt.Fprintf(&b, "%s  %s  %s  %s  %s\n",
				padRight(cl.ID, 10),
				padRight(fmt.Sprintf("%d", len(cl.ImageIDs)), 7),
				padRight(FormatBytes(cl.SharedUnlockBytes), 14),
				padRight(FormatBytes(cl.TotalReclaimBytes), 14),
				truncateRunes(strings.Join(cl.RepoTags, ", "), 52),
			)
		}
	}

	b.WriteByte('\n')
	b.WriteString(r.paint("Per-Image Shared-Layer Accounting:", ansiBold))
	b.WriteByte('\n')
	fmt.Fprintf(&b, "%s  %s  %s  %s  %s  %s\n",
		padRight("IMAGE TAG", 30),
		padRight("REPORTED", 11),
		padRight("EXCLUSIVE", 11),
		padRight("ILLUSION", 11),
		padRight("DISPOSITION", 22),
		"CLIQUE",
	)
	for _, ex := range rep.Plan.Explanations {
		cliqueLabel := ex.CliqueID
		if cliqueLabel == "" {
			cliqueLabel = "-"
		}
		fmt.Fprintf(&b, "%s  %s  %s  %s  %s  %s\n",
			padRight(ex.PrimaryTag, 30),
			padRight(FormatBytes(ex.ReportedSize), 11),
			padRight(FormatBytes(ex.ExclusiveBytes), 11),
			padRight(FormatBytes(ex.SharedIllusionBytes), 11),
			padRight(string(ex.Disposition), 22),
			cliqueLabel,
		)
	}

	b.WriteByte('\n')
	if len(rep.Plan.Steps) == 0 {
		b.WriteString(r.paint("Planned Stage 4 Eviction Schedule: No unreferenced unprotected images require eviction.", ansiDim))
		b.WriteByte('\n')
	} else {
		b.WriteString(r.paint("Planned Stage 4 Surgical Eviction Schedule:", ansiBold))
		b.WriteByte('\n')
		for _, st := range rep.Plan.Steps {
			fmt.Fprintf(&b, "  #%02d [%s] +%s (cum %s, %d layers) -> %s\n",
				st.Step,
				string(st.Kind),
				FormatBytes(st.MarginalBytes),
				FormatBytes(st.CumulativeBytes),
				st.UnlockedLayers,
				strings.Join(st.RepoTags, ", "),
			)
		}
	}

	return b.String()
}

// RenderDoctor formats host, kernel, socket, audit, and phantom open-FD diagnostics.
func (r *Renderer) RenderDoctor(rep DoctorReport) string {
	var b strings.Builder

	header := "HOST & KERNEL STORAGE CONTROL PLANE DIAGNOSTICS (DOCTOR)"
	b.WriteString(r.paint(header, ansiBold))
	b.WriteByte('\n')
	b.WriteString(strings.Repeat("─", r.width))
	b.WriteByte('\n')

	for _, chk := range rep.Checks {
		badge := r.formatCheckBadge(chk.Status)
		fmt.Fprintf(&b, "%s  %-28s %s\n", badge, chk.Name, chk.Summary)
		if chk.Remediation != "" && chk.Status != CheckPass {
			fmt.Fprintf(&b, "        %s %s\n", r.paint("Fix:", ansiCyan), chk.Remediation)
		}
	}

	if len(rep.Phantom.Findings) > 0 {
		b.WriteByte('\n')
		b.WriteString(r.paint("Unlinked Open-FD Forensics (Phantom Disk Leaks):", ansiBold))
		b.WriteByte('\n')
		fmt.Fprintf(&b, "%s  %s  %s  %s  %s  %s\n",
			padRight("PID", 8),
			padRight("FD", 5),
			padRight("PROCESS", 14),
			padRight("LEAKED SIZE", 12),
			padRight("CONTAINER", 14),
			"DELETED PATH",
		)
		for _, fd := range rep.Phantom.Findings {
			cid := fd.ContainerID
			if len(cid) > 12 {
				cid = cid[:12]
			}
			if cid == "" {
				cid = "host"
			}
			fmt.Fprintf(&b, "%s  %s  %s  %s  %s  %s\n",
				padRight(fmt.Sprintf("%d", fd.PID), 8),
				padRight(fmt.Sprintf("%d", fd.FD), 5),
				padRight(fd.Comm, 14),
				padRight(FormatBytes(fd.SizeBytes), 12),
				padRight(cid, 14),
				truncateRunes(fd.DeletedPath, 42),
			)
		}
	}

	b.WriteByte('\n')
	if rep.Healthy {
		b.WriteString(r.paint("VERDICT: HEALTHY — Ready for autonomous production operation.", ansiGreen))
	} else {
		b.WriteString(r.paint("VERDICT: ACTION REQUIRED — Review failed checks above before production rollout.", ansiRed))
	}
	b.WriteByte('\n')
	return b.String()
}

// RenderTopFrame renders a single refresh frame for 'dock-prune-daemon top'.
func (r *Renderer) RenderTopFrame(frame TopFrame, clearScreen bool) string {
	var b strings.Builder
	if clearScreen && !r.noColor {
		b.WriteString(ansiClear)
	}

	fmt.Fprintf(&b, "%s  |  Regime: %s  |  Breaker: %s  |  Sample #%d (%s)\n",
		r.paint(">_ dock-prune-daemon top", ansiBold),
		r.formatRegime(frame.Regime),
		string(frame.Breaker.State),
		frame.Iteration,
		frame.CapturedAt.UTC().Format("15:04:05 UTC"),
	)
	b.WriteString(strings.Repeat("─", r.width))
	b.WriteByte('\n')

	fmt.Fprintf(&b, "Blocks : %s %5.1f%%  (%s used / %s free / %s total)\n",
		r.RenderBar(frame.Disk.UsedPercent, 26),
		frame.Disk.UsedPercent,
		FormatUintBytes(frame.Disk.UsedBytes),
		FormatUintBytes(frame.Disk.FreeBytes),
		FormatUintBytes(frame.Disk.TotalBytes),
	)
	fmt.Fprintf(&b, "Inodes : %s %5.1f%%  (%d used / %d free)\n",
		r.RenderBar(frame.Disk.InodeUsedPercent, 26),
		frame.Disk.InodeUsedPercent,
		frame.Disk.UsedInodes,
		frame.Disk.FreeInodes,
	)

	fmt.Fprintf(&b, "Burn   : %s/s  (accel %s/s², Z=%.2f)  |  Predicted TTE: %s\n",
		FormatBytes(int64(math.Round(frame.Forecast.BlockVelocityBps))),
		FormatBytes(int64(math.Round(frame.Forecast.BlockAccelBps2))),
		frame.Forecast.BurnZScore,
		formatTTE(frame.Forecast.BlockTTESeconds),
	)

	psiStatus := "unsupported (non-Linux or CONFIG_PSI=n)"
	if frame.PSI.Supported {
		psiStatus = fmt.Sprintf("io.some=%.2f%%  io.full=%.2f%%  mem.full=%.2f%%  (eff=%.2f%%)",
			frame.PSI.IOSome.Avg10, frame.PSI.IOFull.Avg10, frame.PSI.MemFull.Avg10, frame.PSI.EffectiveIOStall())
	}
	fmt.Fprintf(&b, "Kernel : PSI %s\n", psiStatus)
	fmt.Fprintf(&b, "Leaks  : %s across %d unlinked open FD(s)  |  FinOps Saved: $%.2f (%.2f GiB freed)\n",
		FormatBytes(frame.Phantom.TotalLeakedBytes),
		len(frame.Phantom.Findings),
		frame.FinOps.EstimatedTotalSavingsUSD,
		frame.FinOps.TotalActualReclaimedGiB,
	)

	if frame.LastCycle != nil {
		b.WriteString(strings.Repeat("─", r.width))
		b.WriteByte('\n')
		fmt.Fprintf(&b, "Last Cycle [%s] trigger=%s dry_run=%t freed=%s (%s) in %s\n",
			frame.LastCycle.CycleID,
			frame.LastCycle.Trigger,
			frame.LastCycle.DryRun,
			FormatUintBytes(frame.LastCycle.ActualDiskReclaimedBytes),
			string(frame.LastCycle.FinalRegime),
			frame.LastCycle.Duration.Round(time.Millisecond),
		)
	}

	return b.String()
}

// RenderROI formats the FinOps & Infrastructure Reliability summary for terminal display.
func (r *Renderer) RenderROI(rep finops.Report) string {
	var b strings.Builder

	b.WriteString(r.paint("INFRASTRUCTURE RELIABILITY & FINOPS ROI REPORT", ansiBold))
	b.WriteByte('\n')
	b.WriteString(strings.Repeat("─", r.width))
	b.WriteByte('\n')

	fmt.Fprintf(&b, "Active Reclaim Cycles     : %d (total evaluations: %d, dry-runs: %d)\n",
		rep.State.ActiveReclaimCycles, rep.State.TotalCycles, rep.State.DryRunCycles)
	fmt.Fprintf(&b, "Cumulative Space Freed    : %.2f GiB (peak single rescue: %.2f GiB) -> $%.2f\n",
		rep.TotalActualReclaimedGiB, rep.PeakSingleReclaimGiB, rep.StorageSavingsUSD)
	fmt.Fprintf(&b, "Stage 0 Logs Truncated    : %s (zero-downtime O_APPEND truncations)\n",
		FormatUintBytes(rep.State.TotalLogTruncatedBytes))
	fmt.Fprintf(&b, "ENOSPC Outages Averted    : %d critical/panic rescues -> $%.2f\n",
		rep.State.ENOSPCAvertedCount, rep.IncidentAvoidanceUSD)
	fmt.Fprintf(&b, "Warm BuildKit Cache Kept  : %d cycles (~%.0f CI mins saved) -> $%.2f\n",
		rep.State.BuildCachePreservedCycles, rep.CIMinutesSavedEstimate, rep.WarmCacheSavingsUSD)

	b.WriteString(strings.Repeat("─", r.width))
	b.WriteByte('\n')
	fmt.Fprintf(&b, "ESTIMATED VALUE DELIVERED : %s (%.2fx return on $150/mo DevOps Team Sponsor tier)\n",
		r.paint(fmt.Sprintf("$%.2f USD", rep.EstimatedTotalSavingsUSD), ansiGreen),
		rep.TeamSponsorROIMultiple,
	)
	fmt.Fprintf(&b, "Back ongoing maintenance & 24h/48h B2B SLAs: %s\n",
		r.paint("https://github.com/sponsors/PedroMartinezag", ansiMagenta))
	return b.String()
}

// RenderCycle summarizes a single 'once' or manual reclamation cycle execution.
func (r *Renderer) RenderCycle(rep engine.CycleReport) string {
	var b strings.Builder

	mode := "LIVE EXECUTION"
	if rep.DryRun {
		mode = "DRY-RUN SIMULATION"
	}
	fmt.Fprintf(&b, "%s [%s]  Cycle=%s  Trigger=%s\n",
		r.paint("SURGICAL RECLAMATION SUMMARY", ansiBold),
		mode,
		rep.CycleID,
		rep.Trigger,
	)
	fmt.Fprintf(&b, "Regime: %s -> %s  |  Disk: %.1f%% -> %.1f%%  |  Duration: %s\n",
		r.formatRegime(rep.InitialRegime),
		r.formatRegime(rep.FinalRegime),
		rep.BeforeDisk.UsedPercent,
		rep.AfterDisk.UsedPercent,
		rep.Duration.Round(time.Millisecond),
	)
	fmt.Fprintf(&b, "Reclaimed: %s actual (%s stage-reported)  |  Target Satisfied: %t  |  Cache Preserved: %t\n",
		FormatUintBytes(rep.ActualDiskReclaimedBytes),
		FormatUintBytes(rep.ReportedReclaimedBytes),
		rep.TargetSatisfied,
		rep.BuildCachePreserved,
	)

	for _, st := range rep.Stages {
		earlyTag := ""
		if st.StoppedEarlyAfter {
			earlyTag = " [hysteresis target reached -> early stop]"
		}
		fmt.Fprintf(&b, "  - %-28s deleted=%-4d reported=%-10s delta=%-10s pause=%s%s\n",
			string(st.Stage),
			st.ItemsDeleted,
			FormatUintBytes(st.ReportedReclaimedBytes),
			FormatUintBytes(st.DiskDeltaBytes),
			st.PSIPauseApplied.Round(time.Millisecond),
			earlyTag,
		)
	}
	for _, w := range rep.Warnings {
		fmt.Fprintf(&b, "  ! warning: %s\n", r.paint(w, ansiYellow))
	}
	return b.String()
}

// RenderVerifyAudit formats cryptographic Ed25519 + SHA-256 Merkle verification output.
func (r *Renderer) RenderVerifyAudit(res audit.VerifyResult) string {
	var b strings.Builder
	b.WriteString(r.paint("AUDIT LEDGER CRYPTOGRAPHIC VERIFICATION PASSED", ansiGreen))
	b.WriteByte('\n')
	fmt.Fprintf(&b, "Ledger File    : %s\n", res.LedgerPath)
	fmt.Fprintf(&b, "Signing Key ID : %s\n", res.KeyID)
	fmt.Fprintf(&b, "Records Valid  : %d (sequence %d .. %d, rotated_anchor=%t)\n",
		res.VerifiedCount, res.FirstSequence, res.LastSequence, res.AnchoredStart)
	fmt.Fprintf(&b, "Merkle Head    : %s\n", res.HeadHash)
	return b.String()
}

func (r *Renderer) formatRegime(reg disk.Regime) string {
	switch reg {
	case disk.RegimeNominal:
		return r.paint(string(reg), ansiGreen)
	case disk.RegimePreemptive, disk.RegimeElevated:
		return r.paint(string(reg), ansiYellow)
	case disk.RegimeCritical, disk.RegimePanic, disk.RegimeDegraded:
		return r.paint(string(reg), ansiRed)
	default:
		return string(reg)
	}
}

func (r *Renderer) formatCheckBadge(st CheckStatus) string {
	label := fmt.Sprintf("[%-4s]", string(st))
	switch st {
	case CheckPass:
		return r.paint(label, ansiGreen)
	case CheckWarn:
		return r.paint(label, ansiYellow)
	default:
		return r.paint(label, ansiRed)
	}
}

func (r *Renderer) paint(text, code string) string {
	if r == nil || r.noColor || code == "" {
		return text
	}
	return code + text + ansiReset
}

func formatTTE(tteSeconds float64) string {
	if tteSeconds <= 0 || math.IsNaN(tteSeconds) || math.IsInf(tteSeconds, 0) {
		return "stable (non-increasing)"
	}
	d := time.Duration(tteSeconds * float64(time.Second)).Round(time.Second)
	return d.String()
}

func padRight(plain string, width int) string {
	if width <= 0 {
		return ""
	}
	trimmed := truncateRunes(plain, width)
	count := utf8.RuneCountInString(trimmed)
	if count >= width {
		return trimmed
	}
	return trimmed + strings.Repeat(" ", width-count)
}

func truncateRunes(s string, maxRunes int) string {
	if maxRunes <= 0 {
		return ""
	}
	if utf8.RuneCountInString(s) <= maxRunes {
		return s
	}
	runes := []rune(s)
	if maxRunes <= 1 {
		return string(runes[:maxRunes])
	}
	return string(runes[:maxRunes-1]) + "…"
}
