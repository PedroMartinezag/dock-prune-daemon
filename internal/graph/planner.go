package graph

import (
	"cmp"
	"fmt"
	"math"
	"slices"
	"strings"
	"time"
)

const (
	defaultMaxCoalitionSize = 8
	scoreTieEpsilon         = 1e-9
)

// CandidateKind classifies whether a planned eviction step removes a standalone image,
// an intermediate shared-layer coalition, or a complete zero-container orphan clique.
type CandidateKind string

const (
	CandidateSingle         CandidateKind = "single"
	CandidateLayerCoalition CandidateKind = "layer_coalition"
	CandidateOrphanClique   CandidateKind = "orphan_clique"
)

// Disposition describes why an image was pinned, protected, or marked eligible in explain output.
type Disposition string

const (
	DispositionPinnedContainer Disposition = "PINNED_BY_CONTAINER"
	DispositionProtectedPolicy Disposition = "PROTECTED_BY_POLICY"
	DispositionEligibleSingle  Disposition = "ELIGIBLE_SINGLE"
	DispositionEligibleClique  Disposition = "ELIGIBLE_CLIQUE_MEMBER"
)

// OrphanClique represents a connected component of >=2 container-free, unprotected images
// coupled across unpinned shared OCI layers that unlock superlinearly when evicted together.
type OrphanClique struct {
	ID                string   `json:"id"`
	ImageIDs          []string `json:"image_ids"`
	RepoTags          []string `json:"repo_tags"`
	SharedLayerCount  int      `json:"shared_layer_count"`
	SharedUnlockBytes int64    `json:"shared_unlock_bytes"`
	TotalReclaimBytes int64    `json:"total_reclaim_bytes"`
	AvgAgeHours       float64  `json:"avg_age_hours"`
	DensityScore      float64  `json:"density_score"`
}

// EvictionStep represents a single surgical step in a Stage 4 reclamation plan.
type EvictionStep struct {
	Step            int           `json:"step"`
	Kind            CandidateKind `json:"kind"`
	ImageIDs        []string      `json:"image_ids"`
	RepoTags        []string      `json:"repo_tags"`
	MarginalBytes   int64         `json:"marginal_bytes"`
	CumulativeBytes int64         `json:"cumulative_bytes"`
	UnlockedLayers  int           `json:"unlocked_layers"`
	AvgAgeHours     float64       `json:"avg_age_hours"`
	Score           float64       `json:"score"`
	Reason          string        `json:"reason"`
}

// ImageExplanation provides full per-image storage transparency for 'explain' CLI and /v1/dag.
type ImageExplanation struct {
	ID                     string      `json:"id"`
	PrimaryTag             string      `json:"primary_tag"`
	ReportedSize           int64       `json:"reported_size"`
	ExclusiveBytes         int64       `json:"exclusive_bytes"`
	ReclaimableSharedBytes int64       `json:"reclaimable_shared_bytes"`
	PinnedSharedBytes      int64       `json:"pinned_shared_bytes"`
	SharedIllusionBytes    int64       `json:"shared_illusion_bytes"`
	ActiveContainers       int         `json:"active_containers"`
	StoppedContainers      int         `json:"stopped_containers"`
	Eligible               bool        `json:"eligible"`
	CliqueID               string      `json:"clique_id,omitempty"`
	Disposition            Disposition `json:"disposition"`
	Reason                 string      `json:"reason"`
	SingletonScore         float64     `json:"singleton_score"`
}

// PlanOptions parameterizes surgical Stage 4 OCI DAG reclamation planning.
type PlanOptions struct {
	// TargetBytes stops planning as soon as CumulativeBytes >= TargetBytes.
	// When TargetBytes <= 0, all positive-gain eligible steps are ranked for full explain inspection.
	TargetBytes int64
	// MaxCoalitionSize caps the number of images evicted in a single multi-image step (default 8).
	MaxCoalitionSize int
	// AllowZeroByte permits evicting 0-byte metadata-only images (default false).
	AllowZeroByte bool
}

// ReclamationPlan holds the complete ordered eviction schedule, discovered orphan cliques,
// and per-image diagnostic explanations.
type ReclamationPlan struct {
	TargetBytes         int64              `json:"target_bytes"`
	PlannedBytes        int64              `json:"planned_bytes"`
	TargetSatisfied     bool               `json:"target_satisfied"`
	TotalEligibleImages int                `json:"total_eligible_images"`
	SelectedImageCount  int                `json:"selected_image_count"`
	Steps               []EvictionStep     `json:"steps"`
	OrphanCliques       []OrphanClique     `json:"orphan_cliques"`
	Explanations        []ImageExplanation `json:"explanations"`
}

// OrderedImageIDs returns the flattened, deduplicated execution sequence of image IDs to remove.
func (p ReclamationPlan) OrderedImageIDs() []string {
	out := make([]string, 0, p.SelectedImageCount)
	seen := make(map[string]struct{}, p.SelectedImageCount)
	for _, step := range p.Steps {
		for _, id := range step.ImageIDs {
			if _, ok := seen[id]; !ok {
				seen[id] = struct{}{}
				out = append(out, id)
			}
		}
	}
	return out
}

// ScoreCandidate evaluates the marginal byte density objective function:
// Score(S | E) = [ ΔB(S | E) * (1 + ln(1 + AvgAgeHours(S)/24)) ] / |∪_{i ∈ S} L(i)|^0.25.
func ScoreCandidate(dag *DAG, imageIDs []string, marginalBytes int64) (score float64, avgAgeHours float64) {
	if dag == nil || len(imageIDs) == 0 || marginalBytes <= 0 {
		return 0, 0
	}

	var totalAge float64
	var validCount int
	for _, id := range imageIDs {
		node, ok := dag.Images[id]
		if !ok {
			continue
		}
		totalAge += node.AgeHours(dag.CapturedAt)
		validCount++
	}
	if validCount > 0 {
		avgAgeHours = totalAge / float64(validCount)
	}

	layerUnion := dag.UniqueLayerUnionCount(imageIDs)
	if layerUnion < 1 {
		layerUnion = 1
	}

	ageFactor := 1.0 + math.Log1p(avgAgeHours/24.0)
	layerPenalty := math.Pow(float64(layerUnion), 0.25)
	score = (float64(marginalBytes) * ageFactor) / layerPenalty
	if math.IsNaN(score) || math.IsInf(score, 0) || score < 0 {
		return 0, avgAgeHours
	}
	return score, avgAgeHours
}

// FindOrphanCliques discovers connected components of >=2 eligible images linked strictly
// through unpinned shared OCI layers (layers that genuinely unlock when the clique is evicted).
func FindOrphanCliques(dag *DAG) []OrphanClique {
	if dag == nil || len(dag.ImageOrder) == 0 {
		return nil
	}

	adj := make(map[string][]string)
	for _, digest := range dag.LayerOrder {
		ln := dag.Layers[digest]
		if ln.Pinned || len(ln.ImageIDs) < 2 {
			continue
		}
		// Because !ln.Pinned, every image referencing this layer is guaranteed eligible.
		first := ln.ImageIDs[0]
		for i := 1; i < len(ln.ImageIDs); i++ {
			peer := ln.ImageIDs[i]
			adj[first] = append(adj[first], peer)
			adj[peer] = append(adj[peer], first)
		}
	}

	visited := make(map[string]bool)
	var rawComponents [][]string

	for _, imgID := range dag.ImageOrder {
		if visited[imgID] {
			continue
		}
		neighbors := adj[imgID]
		if len(neighbors) == 0 {
			continue
		}

		// Deterministic BFS over unpinned shared-layer edges.
		var comp []string
		queue := []string{imgID}
		visited[imgID] = true

		for len(queue) > 0 {
			cur := queue[0]
			queue = queue[1:]
			comp = append(comp, cur)

			nexts := adj[cur]
			slices.Sort(nexts)
			for _, nb := range slices.Compact(nexts) {
				if !visited[nb] {
					visited[nb] = true
					queue = append(queue, nb)
				}
			}
		}

		if len(comp) >= 2 {
			slices.Sort(comp)
			rawComponents = append(rawComponents, comp)
		}
	}

	cliques := make([]OrphanClique, 0, len(rawComponents))
	for _, members := range rawComponents {
		memberSet := make(map[string]struct{}, len(members))
		var sumExclusive int64
		tags := make([]string, 0, len(members))

		for _, id := range members {
			memberSet[id] = struct{}{}
			if node := dag.Images[id]; node != nil {
				sumExclusive += node.ExclusiveBytes
				tags = append(tags, node.PrimaryTag())
			}
		}

		sharedLayers := 0
		for _, digest := range dag.LayerOrder {
			ln := dag.Layers[digest]
			if ln.Pinned || len(ln.ImageIDs) < 2 {
				continue
			}
			if _, ok := memberSet[ln.ImageIDs[0]]; ok {
				sharedLayers++
			}
		}

		totalBytes, _ := dag.MarginalGain(members, nil)
		sharedUnlock := totalBytes - sumExclusive
		if sharedUnlock < 0 {
			sharedUnlock = 0
		}
		score, avgAge := ScoreCandidate(dag, members, totalBytes)

		cliques = append(cliques, OrphanClique{
			ImageIDs:          members,
			RepoTags:          tags,
			SharedLayerCount:  sharedLayers,
			SharedUnlockBytes: sharedUnlock,
			TotalReclaimBytes: totalBytes,
			AvgAgeHours:       avgAge,
			DensityScore:      score,
		})
	}

	slices.SortFunc(cliques, func(a, b OrphanClique) int {
		if !scoresNearlyEqual(a.DensityScore, b.DensityScore) {
			return cmp.Compare(b.DensityScore, a.DensityScore)
		}
		if c := cmp.Compare(b.TotalReclaimBytes, a.TotalReclaimBytes); c != 0 {
			return c
		}
		return slices.Compare(a.ImageIDs, b.ImageIDs)
	})

	for i := range cliques {
		cliques[i].ID = fmt.Sprintf("clique-%02d", i+1)
	}
	return cliques
}

// ExplainImages generates a complete diagnostic table covering every image in the DAG.
func ExplainImages(dag *DAG, cliques []OrphanClique) []ImageExplanation {
	if dag == nil {
		return nil
	}

	imageToClique := make(map[string]string)
	for _, cl := range cliques {
		for _, id := range cl.ImageIDs {
			imageToClique[id] = cl.ID
		}
	}

	out := make([]ImageExplanation, 0, len(dag.ImageOrder))
	for _, id := range dag.ImageOrder {
		node := dag.Images[id]
		disp, reason := describeNodeDisposition(*node, imageToClique[id])
		var singleScore float64
		if node.IsEligible() {
			singleScore, _ = ScoreCandidate(dag, []string{id}, node.ExclusiveBytes)
		}

		out = append(out, ImageExplanation{
			ID:                     node.ID,
			PrimaryTag:             node.PrimaryTag(),
			ReportedSize:           node.ReportedSize,
			ExclusiveBytes:         node.ExclusiveBytes,
			ReclaimableSharedBytes: node.ReclaimableSharedBytes,
			PinnedSharedBytes:      node.PinnedSharedBytes,
			SharedIllusionBytes:    node.SharedIllusionBytes(),
			ActiveContainers:       node.ActiveContainers,
			StoppedContainers:      node.StoppedContainers,
			Eligible:               node.IsEligible(),
			CliqueID:               imageToClique[id],
			Disposition:            disp,
			Reason:                 reason,
			SingletonScore:         singleScore,
		})
	}
	return out
}

// PlanReclamation solves the iterative supermodular eviction schedule across singletons,
// intermediate unpinned-layer coalitions, and full zero-container orphan cliques.
func PlanReclamation(dag *DAG, opts PlanOptions) ReclamationPlan {
	if dag == nil {
		return ReclamationPlan{}
	}

	maxCoalition := opts.MaxCoalitionSize
	if maxCoalition < 1 {
		maxCoalition = defaultMaxCoalitionSize
	}

	cliques := FindOrphanCliques(dag)
	explanations := ExplainImages(dag, cliques)

	var totalEligible int
	for _, id := range dag.ImageOrder {
		if dag.Images[id].IsEligible() {
			totalEligible++
		}
	}

	cliqueKeyToID := make(map[string]string, len(cliques))
	for _, cl := range cliques {
		cliqueKeyToID[canonicalSetKey(cl.ImageIDs)] = cl.ID
	}

	evicted := make(map[string]bool, totalEligible)
	var steps []EvictionStep
	var cumulativeBytes int64
	var selectedImages int

	for selectedImages < totalEligible {
		if opts.TargetBytes > 0 && cumulativeBytes >= opts.TargetBytes {
			break
		}

		candidates := buildStepCandidates(dag, cliques, cliqueKeyToID, evicted, maxCoalition)
		if len(candidates) == 0 {
			break
		}

		var best *evaluatedCandidate
		for i := range candidates {
			cand := &candidates[i]
			marginalBytes, unlockedLayers := dag.MarginalGain(cand.imageIDs, evicted)
			if marginalBytes <= 0 && !opts.AllowZeroByte {
				continue
			}
			score, avgAge := ScoreCandidate(dag, cand.imageIDs, marginalBytes)
			cand.marginalBytes = marginalBytes
			cand.unlockedLayers = unlockedLayers
			cand.score = score
			cand.avgAgeHours = avgAge
			cand.earliestCreated = earliestCreatedAt(dag, cand.imageIDs)

			if best == nil || isBetterCandidate(cand, best) {
				best = cand
			}
		}

		if best == nil {
			break
		}

		for _, id := range best.imageIDs {
			if !evicted[id] {
				evicted[id] = true
				selectedImages++
			}
		}
		cumulativeBytes += best.marginalBytes

		tags := make([]string, 0, len(best.imageIDs))
		for _, id := range best.imageIDs {
			if n := dag.Images[id]; n != nil {
				tags = append(tags, n.PrimaryTag())
			}
		}

		steps = append(steps, EvictionStep{
			Step:            len(steps) + 1,
			Kind:            best.kind,
			ImageIDs:        best.imageIDs,
			RepoTags:        tags,
			MarginalBytes:   best.marginalBytes,
			CumulativeBytes: cumulativeBytes,
			UnlockedLayers:  best.unlockedLayers,
			AvgAgeHours:     best.avgAgeHours,
			Score:           best.score,
			Reason:          formatStepReason(best),
		})
	}

	targetSatisfied := opts.TargetBytes <= 0 || cumulativeBytes >= opts.TargetBytes
	return ReclamationPlan{
		TargetBytes:         opts.TargetBytes,
		PlannedBytes:        cumulativeBytes,
		TargetSatisfied:     targetSatisfied,
		TotalEligibleImages: totalEligible,
		SelectedImageCount:  selectedImages,
		Steps:               steps,
		OrphanCliques:       cliques,
		Explanations:        explanations,
	}
}

type evaluatedCandidate struct {
	kind            CandidateKind
	cliqueID        string
	imageIDs        []string
	marginalBytes   int64
	unlockedLayers  int
	score           float64
	avgAgeHours     float64
	earliestCreated time.Time
}

func buildStepCandidates(
	dag *DAG,
	cliques []OrphanClique,
	cliqueKeyToID map[string]string,
	evicted map[string]bool,
	maxCoalition int,
) []evaluatedCandidate {
	seenKeys := make(map[string]struct{})
	var out []evaluatedCandidate

	addCandidate := func(ids []string, preferredKind CandidateKind) {
		if len(ids) == 0 || len(ids) > maxCoalition {
			return
		}
		key := canonicalSetKey(ids)
		if _, exists := seenKeys[key]; exists {
			return
		}
		seenKeys[key] = struct{}{}

		kind := preferredKind
		cliqueID := cliqueKeyToID[key]
		if len(ids) == 1 {
			kind = CandidateSingle
		} else if cliqueID != "" {
			kind = CandidateOrphanClique
		}
		out = append(out, evaluatedCandidate{
			kind:     kind,
			cliqueID: cliqueID,
			imageIDs: ids,
		})
	}

	// 1. Singleton moves for every remaining eligible image.
	for _, id := range dag.ImageOrder {
		if evicted[id] || !dag.Images[id].IsEligible() {
			continue
		}
		addCandidate([]string{id}, CandidateSingle)
	}

	if maxCoalition < 2 {
		return out
	}

	// 2. Exact minimal layer-unlocking coalitions C_l = ImageIDs(l) \ E for unpinned shared layers.
	for _, digest := range dag.LayerOrder {
		ln := dag.Layers[digest]
		if ln.Pinned || len(ln.ImageIDs) < 2 {
			continue
		}
		rem := filterRemainingEligible(dag, ln.ImageIDs, evicted)
		if len(rem) >= 2 && len(rem) <= maxCoalition {
			addCandidate(rem, CandidateLayerCoalition)
		}
	}

	// 3. Full connected orphan cliques C_K = K \ E.
	for _, cl := range cliques {
		rem := filterRemainingEligible(dag, cl.ImageIDs, evicted)
		if len(rem) >= 2 && len(rem) <= maxCoalition {
			addCandidate(rem, CandidateOrphanClique)
		}
	}

	return out
}

func filterRemainingEligible(dag *DAG, ids []string, evicted map[string]bool) []string {
	var rem []string
	for _, id := range ids {
		if evicted[id] {
			continue
		}
		node := dag.Images[id]
		if node == nil || !node.IsEligible() {
			return nil
		}
		rem = append(rem, id)
	}
	slices.Sort(rem)
	return slices.Compact(rem)
}

func isBetterCandidate(a, b *evaluatedCandidate) bool {
	if !scoresNearlyEqual(a.score, b.score) {
		return a.score > b.score
	}
	if a.marginalBytes != b.marginalBytes {
		return a.marginalBytes > b.marginalBytes
	}
	if len(a.imageIDs) != len(b.imageIDs) {
		// Smaller image cardinality minimizes operational blast radius on exact score ties.
		return len(a.imageIDs) < len(b.imageIDs)
	}
	if !a.earliestCreated.Equal(b.earliestCreated) {
		if a.earliestCreated.IsZero() {
			return false
		}
		if b.earliestCreated.IsZero() {
			return true
		}
		return a.earliestCreated.Before(b.earliestCreated)
	}
	return slices.Compare(a.imageIDs, b.imageIDs) < 0
}

func earliestCreatedAt(dag *DAG, ids []string) time.Time {
	var earliest time.Time
	for _, id := range ids {
		node := dag.Images[id]
		if node == nil || node.CreatedAt.IsZero() {
			continue
		}
		if earliest.IsZero() || node.CreatedAt.Before(earliest) {
			earliest = node.CreatedAt
		}
	}
	return earliest
}

func describeNodeDisposition(node ImageNode, cliqueID string) (Disposition, string) {
	if node.IsPinnedByContainer() {
		firstName := node.Containers[0].Name
		if node.ActiveContainers > 0 {
			return DispositionPinnedContainer, fmt.Sprintf("pinned by %d running container(s) (e.g. %s)", node.ActiveContainers, firstName)
		}
		return DispositionPinnedContainer, fmt.Sprintf("pinned by %d retained stopped container(s) (e.g. %s)", node.StoppedContainers, firstName)
	}
	if node.Protected {
		if node.ProtectReason != "" {
			return DispositionProtectedPolicy, node.ProtectReason
		}
		return DispositionProtectedPolicy, "protected by immunity policy"
	}
	if cliqueID != "" {
		return DispositionEligibleClique, fmt.Sprintf("member of zero-container orphan %s (shared unpinned layers)", cliqueID)
	}
	return DispositionEligibleSingle, "unreferenced standalone image eligible for DAG eviction"
}

func formatStepReason(c *evaluatedCandidate) string {
	switch c.kind {
	case CandidateOrphanClique:
		if c.cliqueID != "" {
			return fmt.Sprintf("evict %d-image orphan %s unlocking %d OCI layer(s)", len(c.imageIDs), c.cliqueID, c.unlockedLayers)
		}
		return fmt.Sprintf("evict %d-image orphan clique unlocking %d OCI layer(s)", len(c.imageIDs), c.unlockedLayers)
	case CandidateLayerCoalition:
		return fmt.Sprintf("evict %d-image shared-layer coalition unlocking %d OCI layer(s)", len(c.imageIDs), c.unlockedLayers)
	default:
		return fmt.Sprintf("evict standalone unreferenced image unlocking %d exclusive/unpinned layer(s)", c.unlockedLayers)
	}
}

func canonicalSetKey(sortedIDs []string) string {
	return strings.Join(sortedIDs, ",")
}

func scoresNearlyEqual(a, b float64) bool {
	diff := math.Abs(a - b)
	scale := math.Max(1.0, math.Max(math.Abs(a), math.Abs(b)))
	return diff <= scoreTieEpsilon*scale
}
