package disk

import (
	"math"
	"sync"

	"github.com/PedroMartinezag/dock-prune-daemon/internal/config"
)

const (
	minSampleDeltaSeconds = 0.1
	reclaimResetThreshold = 64 * 1024 * 1024 // 64 MiB sudden drop indicates an external or internal prune
	minBurstFloorBytesSec = 1024 * 1024      // 1 MiB/s minimum floor to trigger Z-score burst on flat disks
)

// ForecastResult contains kinematic burn-rate, acceleration, Z-score anomaly,
// and quadratic Time-To-Exhaustion (TTE) projections for blocks and inodes.
type ForecastResult struct {
	Samples          int     `json:"samples"`
	Ready            bool    `json:"ready"`
	BlockVelocityBps float64 `json:"block_velocity_bps"`
	BlockAccelBps2   float64 `json:"block_accel_bps2"`
	BlockTTESeconds  float64 `json:"block_tte_seconds"`
	InodeVelocityIps float64 `json:"inode_velocity_ips"`
	InodeAccelIps2   float64 `json:"inode_accel_ips2"`
	InodeTTESeconds  float64 `json:"inode_tte_seconds"`
	BurnZScore       float64 `json:"burn_z_score"`
	AnomalyTriggered bool    `json:"anomaly_triggered"`
}

// Forecaster implements thread-safe Holt-Winters double-exponential smoothing
// (level = velocity, trend = acceleration) paired with a rolling Z-score detector.
type Forecaster struct {
	mu              sync.Mutex
	alpha           float64
	beta            float64
	zScoreThreshold float64
	panicFreeFloor  uint64

	window     []float64
	windowHead int
	windowLen  int

	initialized bool
	samples     int
	prevSnap    Snapshot

	hasTrendState bool
	blockVel      float64
	blockAccel    float64
	inodeVel      float64
	inodeAccel    float64

	lastResult ForecastResult
}

// NewForecaster creates a stateful kinematic disk forecaster.
func NewForecaster(cfg config.ForecastConfig, panicFreeFloor config.ByteSize) *Forecaster {
	alpha := cfg.Alpha
	if alpha <= 0 || alpha >= 1 || math.IsNaN(alpha) {
		alpha = 0.35
	}
	beta := cfg.Beta
	if beta <= 0 || beta >= 1 || math.IsNaN(beta) {
		beta = 0.20
	}
	zThresh := cfg.ZScoreThreshold
	if zThresh < 1.0 || math.IsNaN(zThresh) {
		zThresh = 3.0
	}
	winSize := cfg.WindowSize
	if winSize < 8 {
		winSize = 32
	}
	var floor uint64
	if panicFreeFloor > 0 {
		floor = uint64(panicFreeFloor.Bytes())
	}

	return &Forecaster{
		alpha:           alpha,
		beta:            beta,
		zScoreThreshold: zThresh,
		panicFreeFloor:  floor,
		window:          make([]float64, winSize),
		lastResult: ForecastResult{
			BlockTTESeconds: -1,
			InodeTTESeconds: -1,
		},
	}
}

// ResetBaseline re-anchors the previous snapshot after a reclamation cycle so a
// large intentional drop in disk usage does not skew ongoing burn-rate tracking.
func (f *Forecaster) ResetBaseline(snap Snapshot) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.prevSnap = snap
	f.initialized = true
	if f.blockAccel < 0 {
		f.blockAccel = 0
	}
	if f.inodeAccel < 0 {
		f.inodeAccel = 0
	}
}

// Last returns the most recently computed ForecastResult snapshot.
func (f *Forecaster) Last() ForecastResult {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lastResult
}

// Observe ingests a new filesystem Snapshot and updates velocity, acceleration,
// Z-score burst detection, and quadratic Time-To-Exhaustion estimates.
func (f *Forecaster) Observe(snap Snapshot) ForecastResult {
	f.mu.Lock()
	defer f.mu.Unlock()

	if !f.initialized {
		f.prevSnap = snap
		f.initialized = true
		f.samples = 1
		f.lastResult = ForecastResult{
			Samples:         1,
			Ready:           false,
			BlockTTESeconds: -1,
			InodeTTESeconds: -1,
		}
		return f.lastResult
	}

	dt := snap.SampledAt.Sub(f.prevSnap.SampledAt).Seconds()
	if dt < minSampleDeltaSeconds {
		return f.lastResult
	}

	deltaBytes := float64(snap.UsedBytes) - float64(f.prevSnap.UsedBytes)
	deltaInodes := float64(snap.UsedInodes) - float64(f.prevSnap.UsedInodes)
	f.prevSnap = snap
	f.samples++

	// Guard against large negative cliffs from external or internal pruning so smoothed
	// velocity is never blinded to a continuing runaway writer.
	if deltaBytes <= -float64(reclaimResetThreshold) {
		if f.blockVel < 0 {
			f.blockVel = 0
		}
		f.blockAccel = 0
		f.lastResult.Samples = f.samples
		f.lastResult.BlockTTESeconds = solveQuadraticTTE(headroomBytes(snap.FreeBytes, f.panicFreeFloor), f.blockVel, f.blockAccel)
		return f.lastResult
	}

	instBlockVel := deltaBytes / dt
	instInodeVel := deltaInodes / dt

	// Evaluate Z-score against prior historical velocity window before inserting current sample.
	zScore, anomaly := f.computeZScore(instBlockVel)
	f.pushWindow(instBlockVel)

	if !f.hasTrendState {
		f.blockVel = instBlockVel
		f.blockAccel = 0
		f.inodeVel = instInodeVel
		f.inodeAccel = 0
		f.hasTrendState = true
	} else {
		prevBlockVel := f.blockVel
		// Holt-Winters double exponential update normalized per second:
		// s_t = alpha * v_t + (1 - alpha) * (s_{t-1} + b_{t-1} * dt)
		// b_t = beta * ((s_t - s_{t-1}) / dt) + (1 - beta) * b_{t-1}
		f.blockVel = f.alpha*instBlockVel + (1.0-f.alpha)*(prevBlockVel+f.blockAccel*dt)
		f.blockAccel = f.beta*((f.blockVel-prevBlockVel)/dt) + (1.0-f.beta)*f.blockAccel

		prevInodeVel := f.inodeVel
		f.inodeVel = f.alpha*instInodeVel + (1.0-f.alpha)*(prevInodeVel+f.inodeAccel*dt)
		f.inodeAccel = f.beta*((f.inodeVel-prevInodeVel)/dt) + (1.0-f.beta)*f.inodeAccel
	}

	remBytes := headroomBytes(snap.FreeBytes, f.panicFreeFloor)
	blockTTE := solveQuadraticTTE(remBytes, f.blockVel, f.blockAccel)

	inodeTTE := -1.0
	if snap.TotalInodes > 0 {
		inodeTTE = solveQuadraticTTE(float64(snap.FreeInodes), f.inodeVel, f.inodeAccel)
	}

	f.lastResult = ForecastResult{
		Samples:          f.samples,
		Ready:            f.samples >= 3,
		BlockVelocityBps: f.blockVel,
		BlockAccelBps2:   f.blockAccel,
		BlockTTESeconds:  blockTTE,
		InodeVelocityIps: f.inodeVel,
		InodeAccelIps2:   f.inodeAccel,
		InodeTTESeconds:  inodeTTE,
		BurnZScore:       zScore,
		AnomalyTriggered: anomaly,
	}
	return f.lastResult
}

func (f *Forecaster) pushWindow(v float64) {
	f.window[f.windowHead] = v
	f.windowHead = (f.windowHead + 1) % len(f.window)
	if f.windowLen < len(f.window) {
		f.windowLen++
	}
}

func (f *Forecaster) computeZScore(currentVel float64) (float64, bool) {
	// Require at least 5 baseline velocity observations and a meaningful positive write rate.
	if f.windowLen < 5 || currentVel < minBurstFloorBytesSec {
		return 0, false
	}

	var sum float64
	for i := 0; i < f.windowLen; i++ {
		sum += f.window[i]
	}
	mean := sum / float64(f.windowLen)
	if currentVel <= mean {
		return 0, false
	}

	var sqDiffSum float64
	for i := 0; i < f.windowLen; i++ {
		diff := f.window[i] - mean
		sqDiffSum += diff * diff
	}
	variance := sqDiffSum / float64(f.windowLen)
	// Enforce a small noise floor (64 KiB/s std dev) so perfectly idle disks produce bounded finite Z-scores.
	stdDev := math.Max(math.Sqrt(variance), 64*1024)
	z := (currentVel - mean) / stdDev
	if math.IsNaN(z) || math.IsInf(z, 0) {
		return 0, false
	}
	return z, z >= f.zScoreThreshold
}

func headroomBytes(freeBytes, panicFloor uint64) float64 {
	if freeBytes <= panicFloor {
		return 0
	}
	return float64(freeBytes - panicFloor)
}

// solveQuadraticTTE solves R = v*t + 0.5*max(0, a)*t^2 using the numerically stable
// rationalized root t = 2R / (v + sqrt(v^2 + 2*a*R)), avoiding catastrophic cancellation
// when acceleration 'a' approaches zero.
func solveQuadraticTTE(remaining, velocity, accel float64) float64 {
	if velocity <= 0 {
		return -1
	}
	if remaining <= 0 {
		return 0.001
	}
	posAccel := math.Max(0, accel)
	discriminant := velocity*velocity + 2.0*posAccel*remaining
	denom := velocity + math.Sqrt(discriminant)
	if denom <= 0 || math.IsNaN(denom) || math.IsInf(denom, 0) {
		return -1
	}
	tte := (2.0 * remaining) / denom
	if math.IsNaN(tte) || math.IsInf(tte, 0) || tte <= 0 {
		return -1
	}
	return tte
}
