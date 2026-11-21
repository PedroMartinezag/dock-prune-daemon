// Package graph constructs a deterministic bipartite OCI reference DAG
// (Containers -> Images -> SHA256 RootFS Layers) to compute exact supermodular
// byte reclamation and eliminate Docker's shared-layer size illusion.
package graph

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/PedroMartinezag/dock-prune-daemon/internal/docker"
)

const defaultInspectConcurrency = 4

// ProtectionCheckFunc evaluates whether an image is immune from eviction due to
// operator policy (protected labels, glob patterns, or minimum resource age).
type ProtectionCheckFunc func(img ImageNode) (protected bool, reason string)

// SnapshotOptions configures DAG construction and policy immunity propagation.
type SnapshotOptions struct {
	Now            time.Time
	ProtectCheck   ProtectionCheckFunc
	MaxConcurrency int
}

// RawImageInput bundles Docker Engine metadata for a single image so the DAG
// builder can run both against a live socket and in-memory deterministic tests.
type RawImageInput struct {
	Summary docker.ImageSummary
	Inspect docker.ImageInspect
	History []docker.ImageHistoryItem
}

// ContainerRef summarizes a container holding a hard reference to an image.
type ContainerRef struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	State   string `json:"state"`
	Running bool   `json:"running"`
}

// LayerNode represents a content-addressable OCI filesystem layer (diff_id) in the DAG.
type LayerNode struct {
	Digest    string   `json:"digest"`
	SizeBytes int64    `json:"size_bytes"`
	ImageIDs  []string `json:"image_ids"`
	Pinned    bool     `json:"pinned"`
}

// ImageNode represents an OCI image vertex along with its exact exclusive,
// unlockable shared, and pinned shared byte accounting.
type ImageNode struct {
	ID                     string            `json:"id"`
	RepoTags               []string          `json:"repo_tags"`
	RepoDigests            []string          `json:"repo_digests"`
	Labels                 map[string]string `json:"labels,omitempty"`
	CreatedAt              time.Time         `json:"created_at"`
	ReportedSize           int64             `json:"reported_size"`
	Layers                 []string          `json:"layers"`
	Containers             []ContainerRef    `json:"containers,omitempty"`
	ActiveContainers       int               `json:"active_containers"`
	StoppedContainers      int               `json:"stopped_containers"`
	Dangling               bool              `json:"dangling"`
	Protected              bool              `json:"protected"`
	ProtectReason          string            `json:"protect_reason,omitempty"`
	ExclusiveBytes         int64             `json:"exclusive_bytes"`
	SharedBytes            int64             `json:"shared_bytes"`
	ReclaimableSharedBytes int64             `json:"reclaimable_shared_bytes"`
	PinnedSharedBytes      int64             `json:"pinned_shared_bytes"`
}

// PrimaryTag returns the first human-readable repository tag or a short digest fallback.
func (n ImageNode) PrimaryTag() string {
	for _, t := range n.RepoTags {
		trimmed := strings.TrimSpace(t)
		if trimmed != "" && trimmed != "<none>:<none>" {
			return trimmed
		}
	}
	for _, d := range n.RepoDigests {
		trimmed := strings.TrimSpace(d)
		if trimmed != "" && trimmed != "<none>@<none>" {
			return trimmed
		}
	}
	short := strings.TrimPrefix(n.ID, "sha256:")
	if len(short) > 12 {
		short = short[:12]
	}
	return "<untagged:" + short + ">"
}

// IsPinnedByContainer reports whether any container (running or retained stopped)
// still references this image on the backing storage driver.
func (n ImageNode) IsPinnedByContainer() bool {
	return len(n.Containers) > 0
}

// IsEligible reports whether this image can legally participate in Stage 4 eviction.
func (n ImageNode) IsEligible() bool {
	return !n.Protected && !n.IsPinnedByContainer()
}

// SharedIllusionBytes returns the gap between Docker's naive reported image size
// and the actual bytes freed if this single image is removed alone.
func (n ImageNode) SharedIllusionBytes() int64 {
	if n.ReportedSize <= n.ExclusiveBytes {
		return 0
	}
	return n.ReportedSize - n.ExclusiveBytes
}

// AgeHours returns the non-negative age of the image in hours relative to now.
func (n ImageNode) AgeHours(now time.Time) float64 {
	if n.CreatedAt.IsZero() || now.Before(n.CreatedAt) {
		return 0
	}
	return now.Sub(n.CreatedAt).Hours()
}

// DAG holds the complete container-image-layer reference topology at a point in time.
type DAG struct {
	CapturedAt              time.Time             `json:"captured_at"`
	Images                  map[string]*ImageNode `json:"images"`
	ImageOrder              []string              `json:"image_order"`
	Layers                  map[string]*LayerNode `json:"layers"`
	LayerOrder              []string              `json:"layer_order"`
	TotalUniqueLayerBytes   int64                 `json:"total_unique_layer_bytes"`
	PinnedLayerBytes        int64                 `json:"pinned_layer_bytes"`
	ReclaimableLayerBytes   int64                 `json:"reclaimable_layer_bytes"`
	TotalReportedImageBytes int64                 `json:"total_reported_image_bytes"`
	SharedBloatRatio        float64               `json:"shared_bloat_ratio"`
}

// BuildFromEngine queries the Docker Engine over its socket with bounded concurrency,
// gracefully skipping ephemeral images removed mid-scan (HTTP 404 races).
func BuildFromEngine(ctx context.Context, eng docker.Engine, opts SnapshotOptions) (*DAG, error) {
	if eng == nil {
		return nil, errors.New("nil docker engine client")
	}
	if opts.Now.IsZero() {
		opts.Now = time.Now().UTC()
	}

	containers, err := eng.ListContainers(ctx, docker.ListContainersOptions{All: true})
	if err != nil {
		return nil, fmt.Errorf("list containers for DAG: %w", err)
	}

	summaries, err := eng.ListImages(ctx, docker.ListImagesOptions{
		All:        false,
		SharedSize: true,
	})
	if err != nil {
		return nil, fmt.Errorf("list images for DAG: %w", err)
	}

	workers := opts.MaxConcurrency
	if workers < 1 {
		workers = defaultInspectConcurrency
	}
	if workers > len(summaries) && len(summaries) > 0 {
		workers = len(summaries)
	}

	type fetchResult struct {
		input RawImageInput
		valid bool
		err   error
	}

	jobs := make(chan docker.ImageSummary, len(summaries))
	results := make(chan fetchResult, len(summaries))

	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for sum := range jobs {
				if ctx.Err() != nil {
					results <- fetchResult{err: ctx.Err()}
					continue
				}
				insp, inspErr := eng.InspectImage(ctx, sum.ID)
				if inspErr != nil {
					var apiErr *docker.APIError
					if errors.As(inspErr, &apiErr) && apiErr.IsNotFound() {
						// Image was deleted concurrently between ListImages and InspectImage.
						results <- fetchResult{valid: false}
						continue
					}
					results <- fetchResult{err: fmt.Errorf("inspect image %s: %w", sum.ID, inspErr)}
					continue
				}

				hist, histErr := eng.ImageHistory(ctx, sum.ID)
				if histErr != nil {
					var apiErr *docker.APIError
					if errors.As(histErr, &apiErr) && (apiErr.IsNotFound() || apiErr.IsNotImplemented()) {
						hist = nil
					} else {
						results <- fetchResult{err: fmt.Errorf("history image %s: %w", sum.ID, histErr)}
						continue
					}
				}

				results <- fetchResult{
					input: RawImageInput{
						Summary: sum,
						Inspect: insp,
						History: hist,
					},
					valid: true,
				}
			}
		}()
	}

	for _, sum := range summaries {
		jobs <- sum
	}
	close(jobs)
	wg.Wait()
	close(results)

	rawInputs := make([]RawImageInput, 0, len(summaries))
	for res := range results {
		if res.err != nil {
			return nil, res.err
		}
		if res.valid {
			rawInputs = append(rawInputs, res.input)
		}
	}

	return Build(rawInputs, containers, opts), nil
}

// Build constructs an exact OCI Layer Reference DAG in memory from raw engine metadata.
func Build(rawImages []RawImageInput, containers []docker.ContainerSummary, opts SnapshotOptions) *DAG {
	now := opts.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}

	dag := &DAG{
		CapturedAt: now.UTC(),
		Images:     make(map[string]*ImageNode, len(rawImages)),
		Layers:     make(map[string]*LayerNode),
	}

	// Track bijectively matched per-layer sizes across all images first so base layers
	// with exact history anchor derived or squashed images lacking history metadata.
	exactLayerSizes := make(map[string]int64)
	tagToImageID := make(map[string]string)

	for _, item := range rawImages {
		imgID := strings.TrimSpace(item.Inspect.ID)
		if imgID == "" {
			imgID = strings.TrimSpace(item.Summary.ID)
		}
		if imgID == "" {
			continue
		}

		tags := mergeUniqueStrings(item.Summary.RepoTags, item.Inspect.RepoTags)
		digests := mergeUniqueStrings(item.Summary.RepoDigests, item.Inspect.RepoDigests)
		labels := mergeLabels(item.Summary.Labels, item.Inspect.Config)
		createdAt := resolveCreatedAt(item.Summary, item.Inspect.Created)

		reportedSize := item.Inspect.Size
		if reportedSize <= 0 && item.Summary.Size > 0 {
			reportedSize = item.Summary.Size
		}
		if reportedSize < 0 {
			reportedSize = 0
		}

		rawLayers := item.Inspect.RootFS.Layers
		uniqueLayers := deduplicatePreservingOrder(rawLayers)
		if len(uniqueLayers) == 0 {
			// Synthesize a deterministic virtual self-layer for 0-layer manifest edge cases.
			uniqueLayers = []string{"virtual:" + imgID}
			exactLayerSizes["virtual:"+imgID] = reportedSize
		} else if mapped, ok := matchBijectiveHistorySizes(rawLayers, item.History); ok {
			for digest, sz := range mapped {
				if sz > exactLayerSizes[digest] {
					exactLayerSizes[digest] = sz
				}
			}
		}

		dangling := isDanglingTags(tags)
		node := &ImageNode{
			ID:           imgID,
			RepoTags:     tags,
			RepoDigests:  digests,
			Labels:       labels,
			CreatedAt:    createdAt,
			ReportedSize: reportedSize,
			Layers:       uniqueLayers,
			Dangling:     dangling,
		}
		dag.Images[imgID] = node

		for _, t := range tags {
			if t != "" && t != "<none>:<none>" {
				tagToImageID[t] = imgID
			}
		}
	}

	dag.ImageOrder = make([]string, 0, len(dag.Images))
	for id := range dag.Images {
		dag.ImageOrder = append(dag.ImageOrder, id)
	}
	slices.Sort(dag.ImageOrder)

	// Attach all active and retained stopped containers to their backing ImageNodes.
	sortedContainers := slices.Clone(containers)
	slices.SortFunc(sortedContainers, func(a, b docker.ContainerSummary) int {
		return cmp.Compare(a.ID, b.ID)
	})

	for _, ctr := range sortedContainers {
		targetNode := resolveContainerImage(ctr, dag.Images, dag.ImageOrder, tagToImageID)
		if targetNode == nil {
			continue
		}
		running := ctr.IsRunning()
		targetNode.Containers = append(targetNode.Containers, ContainerRef{
			ID:      ctr.ID,
			Name:    ctr.PrimaryName(),
			State:   ctr.State,
			Running: running,
		})
		if running {
			targetNode.ActiveContainers++
		} else {
			targetNode.StoppedContainers++
		}
	}

	// Evaluate policy protection rules in deterministic image order.
	for _, imgID := range dag.ImageOrder {
		node := dag.Images[imgID]
		if opts.ProtectCheck != nil {
			protected, reason := opts.ProtectCheck(*node)
			node.Protected = protected
			node.ProtectReason = strings.TrimSpace(reason)
		}
		dag.TotalReportedImageBytes += node.ReportedSize
	}

	// Reconcile any remaining unknown layer sizes via cross-image residual inference.
	inferredSizes := make(map[string]int64, len(exactLayerSizes))
	for k, v := range exactLayerSizes {
		inferredSizes[k] = v
	}

	for _, imgID := range dag.ImageOrder {
		node := dag.Images[imgID]
		var knownSum int64
		var unknownDigests []string
		for _, digest := range node.Layers {
			if sz, ok := inferredSizes[digest]; ok {
				knownSum += sz
			} else {
				unknownDigests = append(unknownDigests, digest)
			}
		}
		if len(unknownDigests) == 0 {
			continue
		}
		residual := node.ReportedSize - knownSum
		if residual < 0 {
			residual = 0
		}
		count := int64(len(unknownDigests))
		baseShare := residual / count
		rem := residual % count
		for idx, digest := range unknownDigests {
			share := baseShare
			if int64(idx) < rem {
				share++
			}
			if share > inferredSizes[digest] {
				inferredSizes[digest] = share
			}
		}
	}

	// Materialize LayerNodes and propagate pinning from container-backed or protected images.
	for _, imgID := range dag.ImageOrder {
		node := dag.Images[imgID]
		imagePinned := !node.IsEligible()

		for _, digest := range node.Layers {
			ln, exists := dag.Layers[digest]
			if !exists {
				ln = &LayerNode{
					Digest:    digest,
					SizeBytes: inferredSizes[digest],
				}
				dag.Layers[digest] = ln
			}
			ln.ImageIDs = append(ln.ImageIDs, imgID)
			if imagePinned {
				ln.Pinned = true
			}
		}
	}

	dag.LayerOrder = make([]string, 0, len(dag.Layers))
	for digest, ln := range dag.Layers {
		slices.Sort(ln.ImageIDs)
		ln.ImageIDs = slices.Compact(ln.ImageIDs)
		dag.LayerOrder = append(dag.LayerOrder, digest)

		dag.TotalUniqueLayerBytes += ln.SizeBytes
		if ln.Pinned {
			dag.PinnedLayerBytes += ln.SizeBytes
		} else {
			dag.ReclaimableLayerBytes += ln.SizeBytes
		}
	}
	slices.Sort(dag.LayerOrder)

	// Populate per-image ExclusiveBytes, ReclaimableSharedBytes, and PinnedSharedBytes.
	for _, imgID := range dag.ImageOrder {
		node := dag.Images[imgID]
		for _, digest := range node.Layers {
			ln := dag.Layers[digest]
			if len(ln.ImageIDs) == 1 {
				node.ExclusiveBytes += ln.SizeBytes
				continue
			}
			node.SharedBytes += ln.SizeBytes
			if ln.Pinned {
				node.PinnedSharedBytes += ln.SizeBytes
			} else {
				node.ReclaimableSharedBytes += ln.SizeBytes
			}
		}
	}

	if dag.TotalUniqueLayerBytes > 0 {
		dag.SharedBloatRatio = float64(dag.TotalReportedImageBytes) / float64(dag.TotalUniqueLayerBytes)
	} else {
		dag.SharedBloatRatio = 1.0
	}

	return dag
}

// MarginalGain computes the exact supermodular byte delta ΔB(S | E) and newly unlocked
// layer count if eligible images in candidateIDs are evicted on top of alreadyEvicted.
func (d *DAG) MarginalGain(candidateIDs []string, alreadyEvicted map[string]bool) (bytes int64, unlockedLayers int) {
	if d == nil || len(candidateIDs) == 0 {
		return 0, 0
	}

	candidateSet := make(map[string]struct{}, len(candidateIDs))
	for _, id := range candidateIDs {
		if alreadyEvicted[id] {
			continue
		}
		node, ok := d.Images[id]
		if !ok || !node.IsEligible() {
			continue
		}
		candidateSet[id] = struct{}{}
	}
	if len(candidateSet) == 0 {
		return 0, 0
	}

	inspectedLayers := make(map[string]struct{})
	for id := range candidateSet {
		node := d.Images[id]
		for _, digest := range node.Layers {
			if _, seen := inspectedLayers[digest]; seen {
				continue
			}
			inspectedLayers[digest] = struct{}{}

			ln := d.Layers[digest]
			if ln == nil || ln.Pinned {
				continue
			}

			allHoldersGone := true
			for _, holderID := range ln.ImageIDs {
				if alreadyEvicted[holderID] {
					continue
				}
				if _, inCandidate := candidateSet[holderID]; inCandidate {
					continue
				}
				allHoldersGone = false
				break
			}

			if allHoldersGone {
				bytes += ln.SizeBytes
				unlockedLayers++
			}
		}
	}

	return bytes, unlockedLayers
}

// UniqueLayerUnionCount returns the cardinality |∪_{i ∈ S} L(i)| used as the
// rebuild-cost denominator in marginal byte density scoring.
func (d *DAG) UniqueLayerUnionCount(imageIDs []string) int {
	if d == nil || len(imageIDs) == 0 {
		return 0
	}
	if len(imageIDs) == 1 {
		if node, ok := d.Images[imageIDs[0]]; ok {
			return len(node.Layers)
		}
		return 0
	}
	union := make(map[string]struct{})
	for _, id := range imageIDs {
		node, ok := d.Images[id]
		if !ok {
			continue
		}
		for _, digest := range node.Layers {
			union[digest] = struct{}{}
		}
	}
	return len(union)
}

func matchBijectiveHistorySizes(rawLayers []string, history []docker.ImageHistoryItem) (map[string]int64, bool) {
	if len(rawLayers) == 0 || len(history) == 0 {
		return nil, false
	}

	// Moby ImageHistory is ordered newest-to-oldest, whereas RootFS.Layers is oldest-to-newest.
	nonEmpty := make([]int64, 0, len(rawLayers))
	for _, h := range history {
		if h.Size > 0 {
			nonEmpty = append(nonEmpty, h.Size)
		}
	}

	out := make(map[string]int64, len(rawLayers))
	if len(nonEmpty) == len(rawLayers) {
		for i, digest := range rawLayers {
			sz := nonEmpty[len(nonEmpty)-1-i]
			out[digest] = maxInt64(out[digest], sz)
		}
		return out, true
	}

	if len(history) == len(rawLayers) {
		for i, digest := range rawLayers {
			sz := maxInt64(0, history[len(history)-1-i].Size)
			out[digest] = maxInt64(out[digest], sz)
		}
		return out, true
	}

	return nil, false
}

func resolveContainerImage(
	ctr docker.ContainerSummary,
	images map[string]*ImageNode,
	imageOrder []string,
	tagToImageID map[string]string,
) *ImageNode {
	rawID := strings.TrimSpace(ctr.ImageID)
	if rawID != "" {
		if node, ok := images[rawID]; ok {
			return node
		}
		if !strings.HasPrefix(rawID, "sha256:") {
			if node, ok := images["sha256:"+rawID]; ok {
				return node
			}
		}
		// Prefix match in deterministic sorted order for abbreviated IDs.
		normPrefix := strings.TrimPrefix(rawID, "sha256:")
		if len(normPrefix) >= 12 {
			for _, id := range imageOrder {
				if strings.HasPrefix(strings.TrimPrefix(id, "sha256:"), normPrefix) {
					return images[id]
				}
			}
		}
	}

	ref := strings.TrimSpace(ctr.Image)
	if ref != "" {
		if mappedID, ok := tagToImageID[ref]; ok {
			return images[mappedID]
		}
		if node, ok := images[ref]; ok {
			return node
		}
		if !strings.HasPrefix(ref, "sha256:") {
			if node, ok := images["sha256:"+ref]; ok {
				return node
			}
		}
	}
	return nil
}

func resolveCreatedAt(sum docker.ImageSummary, inspectCreated string) time.Time {
	if sum.Created > 0 {
		return sum.CreatedTime()
	}
	trimmed := strings.TrimSpace(inspectCreated)
	if trimmed != "" {
		if t, err := time.Parse(time.RFC3339Nano, trimmed); err == nil {
			return t.UTC()
		}
		if t, err := time.Parse(time.RFC3339, trimmed); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}

func mergeUniqueStrings(a, b []string) []string {
	seen := make(map[string]struct{}, len(a)+len(b))
	out := make([]string, 0, len(a)+len(b))
	for _, list := range [][]string{a, b} {
		for _, item := range list {
			trimmed := strings.TrimSpace(item)
			if trimmed == "" || trimmed == "<none>:<none>" || trimmed == "<none>@<none>" {
				continue
			}
			if _, ok := seen[trimmed]; !ok {
				seen[trimmed] = struct{}{}
				out = append(out, trimmed)
			}
		}
	}
	slices.Sort(out)
	return out
}

func mergeLabels(summaryLabels map[string]string, inspectCfg *docker.ImageConfig) map[string]string {
	var cfgLabels map[string]string
	if inspectCfg != nil {
		cfgLabels = inspectCfg.Labels
	}
	if len(summaryLabels) == 0 && len(cfgLabels) == 0 {
		return nil
	}
	out := make(map[string]string, len(summaryLabels)+len(cfgLabels))
	for k, v := range cfgLabels {
		out[k] = v
	}
	for k, v := range summaryLabels {
		out[k] = v
	}
	return out
}

func deduplicatePreservingOrder(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		trimmed := strings.TrimSpace(s)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; !ok {
			seen[trimmed] = struct{}{}
			out = append(out, trimmed)
		}
	}
	return out
}

func isDanglingTags(tags []string) bool {
	return len(tags) == 0
}

func maxInt64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}
