package graph

import (
	"context"
	"fmt"
	"math/rand"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/PedroMartinezag/dock-prune-daemon/internal/docker"
)

func TestDAG_SharedLayerIllusion_AndPinnedLayerImmunity(t *testing.T) {
	t.Parallel()

	const mib = int64(1024 * 1024)
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)

	// Base layer L_ubuntu (500 MiB) is pinned by running container "prod-api" on imgProd.
	// Orphan image imgOld shares L_ubuntu (500 MiB) + exclusive L_old (40 MiB) => Docker reports 540 MiB!
	// Protected image imgGolden holds exclusive L_gold (300 MiB).
	rawImages := []RawImageInput{
		makeRawImage("sha256:imgProd", []string{"org/api:prod"}, now.Add(-72*time.Hour),
			[]layerSpec{{"sha256:L_ubuntu", 500 * mib}, {"sha256:L_prod", 60 * mib}}),
		makeRawImage("sha256:imgOld", []string{"org/api:v0.9"}, now.Add(-96*time.Hour),
			[]layerSpec{{"sha256:L_ubuntu", 500 * mib}, {"sha256:L_old", 40 * mib}}),
		makeRawImage("sha256:imgGolden", []string{"org/golden:base"}, now.Add(-120*time.Hour),
			[]layerSpec{{"sha256:L_gold", 300 * mib}}),
	}

	containers := []docker.ContainerSummary{
		{
			ID:      "ctr_prod_111111111111",
			Names:   []string{"/prod-api"},
			ImageID: "sha256:imgProd",
			State:   "running",
		},
	}

	dag := Build(rawImages, containers, SnapshotOptions{
		Now: now,
		ProtectCheck: func(img ImageNode) (bool, string) {
			if slices.Contains(img.RepoTags, "org/golden:base") {
				return true, "matched protected image pattern org/golden:*"
			}
			return false, ""
		},
	})

	oldNode := dag.Images["sha256:imgOld"]
	if oldNode == nil {
		t.Fatal("missing imgOld in DAG")
	}
	if oldNode.ReportedSize != 540*mib {
		t.Fatalf("ReportedSize = %d, want %d", oldNode.ReportedSize, 540*mib)
	}
	if oldNode.ExclusiveBytes != 40*mib {
		t.Fatalf("ExclusiveBytes = %d, want %d (shared-layer illusion failed)", oldNode.ExclusiveBytes, 40*mib)
	}
	if oldNode.PinnedSharedBytes != 500*mib || oldNode.ReclaimableSharedBytes != 0 {
		t.Fatalf("expected 500 MiB pinned shared and 0 reclaimable shared, got pinned=%d reclaimable=%d",
			oldNode.PinnedSharedBytes, oldNode.ReclaimableSharedBytes)
	}
	if oldNode.SharedIllusionBytes() != 500*mib {
		t.Fatalf("SharedIllusionBytes() = %d, want %d", oldNode.SharedIllusionBytes(), 500*mib)
	}

	// Protected and container-pinned images must contribute 0 bytes even if passed directly to MarginalGain.
	gain, layers := dag.MarginalGain([]string{"sha256:imgProd", "sha256:imgOld", "sha256:imgGolden"}, nil)
	if gain != 40*mib || layers != 1 {
		t.Fatalf("MarginalGain = (%d bytes, %d layers), want (%d, 1)", gain, layers, 40*mib)
	}

	// Because L_ubuntu is pinned by prod-api, imgOld must NOT form a false orphan clique with imgProd!
	if cliques := FindOrphanCliques(dag); len(cliques) != 0 {
		t.Fatalf("expected 0 orphan cliques when shared layer is container-pinned, got %+v", cliques)
	}
}

func TestPlanner_OrphanCliqueSuperlinearUnlock_AndSurgicalLayerCoalition(t *testing.T) {
	t.Parallel()

	const mib = int64(1024 * 1024)
	const gib = 1024 * mib
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	created := now.Add(-48 * time.Hour)

	// Hierarchical unreferenced family of 4 images sharing L_python (100 MiB):
	// - ml-gpu:v1 and ml-gpu:v2 additionally share heavy L_cuda (2 GiB), each having 10 MiB top layer.
	// - ml-cpu:v1 and ml-cpu:v2 only sit on L_python (100 MiB), each having 15 MiB top layer.
	// Standalone image legacy:tool has 180 MiB exclusive.
	rawImages := []RawImageInput{
		makeRawImage("sha256:gpu1", []string{"ml-gpu:v1"}, created, []layerSpec{
			{"sha256:L_python", 100 * mib},
			{"sha256:L_cuda", 2 * gib},
			{"sha256:L_gpu1", 10 * mib},
		}),
		makeRawImage("sha256:gpu2", []string{"ml-gpu:v2"}, created, []layerSpec{
			{"sha256:L_python", 100 * mib},
			{"sha256:L_cuda", 2 * gib},
			{"sha256:L_gpu2", 10 * mib},
		}),
		makeRawImage("sha256:cpu1", []string{"ml-cpu:v1"}, created, []layerSpec{
			{"sha256:L_python", 100 * mib},
			{"sha256:L_cpu1", 15 * mib},
		}),
		makeRawImage("sha256:cpu2", []string{"ml-cpu:v2"}, created, []layerSpec{
			{"sha256:L_python", 100 * mib},
			{"sha256:L_cpu2", 15 * mib},
		}),
		makeRawImage("sha256:legacy", []string{"legacy:tool"}, created, []layerSpec{
			{"sha256:L_legacy", 180 * mib},
		}),
	}

	dag := Build(rawImages, nil, SnapshotOptions{Now: now})

	// 1. Connected component analysis finds 1 4-image orphan clique over L_python + L_cuda.
	cliques := FindOrphanCliques(dag)
	if len(cliques) != 1 || len(cliques[0].ImageIDs) != 4 {
		t.Fatalf("expected 1 4-member orphan clique, got %+v", cliques)
	}
	wantCliqueTotal := 100*mib + 2*gib + 10*mib + 10*mib + 15*mib + 15*mib
	if cliques[0].TotalReclaimBytes != wantCliqueTotal {
		t.Fatalf("clique TotalReclaimBytes = %d, want %d", cliques[0].TotalReclaimBytes, wantCliqueTotal)
	}

	// 2. Requesting 1.8 GiB surgically picks ONLY the 2-image {gpu1, gpu2} layer coalition (2 GiB + 20 MiB),
	// unlocking L_cuda while sparing cpu1, cpu2, and legacy:tool!
	plan := PlanReclamation(dag, PlanOptions{TargetBytes: 1800 * mib})
	if !plan.TargetSatisfied {
		t.Fatalf("expected TargetSatisfied=true, got %+v", plan)
	}
	if len(plan.Steps) != 1 {
		t.Fatalf("expected single surgical coalition step, got %d steps: %+v", len(plan.Steps), plan.Steps)
	}
	step1 := plan.Steps[0]
	if step1.Kind != CandidateLayerCoalition {
		t.Fatalf("step 1 Kind = %s, want %s", step1.Kind, CandidateLayerCoalition)
	}
	wantPair := []string{"sha256:gpu1", "sha256:gpu2"}
	if !slices.Equal(step1.ImageIDs, wantPair) {
		t.Fatalf("step 1 ImageIDs = %v, want %v", step1.ImageIDs, wantPair)
	}
	wantStep1Bytes := 2*gib + 20*mib
	if step1.MarginalBytes != wantStep1Bytes {
		t.Fatalf("step 1 MarginalBytes = %d, want %d", step1.MarginalBytes, wantStep1Bytes)
	}
}

func TestDAG_CrossImageLayerSizeInferenceFallback(t *testing.T) {
	t.Parallel()

	const mib = int64(1024 * 1024)
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)

	// Base image provides exact history for sha256:base (200 MiB).
	baseInput := makeRawImage("sha256:baseImg", []string{"alpine:custom"}, now, []layerSpec{
		{"sha256:base", 200 * mib},
	})

	// Derived squashed/imported image has 3 layers totaling 300 MiB, but History is unavailable (nil).
	derivedInput := RawImageInput{
		Summary: docker.ImageSummary{
			ID:       "sha256:derivedImg",
			RepoTags: []string{"service:squashed"},
			Size:     300 * mib,
			Created:  now.Unix(),
		},
		Inspect: docker.ImageInspect{
			ID:       "sha256:derivedImg",
			RepoTags: []string{"service:squashed"},
			Size:     300 * mib,
			RootFS: docker.RootFS{
				Type:   "layers",
				Layers: []string{"sha256:base", "sha256:mid", "sha256:top"},
			},
		},
		History: nil,
	}

	dag := Build([]RawImageInput{baseInput, derivedInput}, nil, SnapshotOptions{Now: now})

	if dag.Layers["sha256:base"].SizeBytes != 200*mib {
		t.Fatalf("base layer size = %d, want %d", dag.Layers["sha256:base"].SizeBytes, 200*mib)
	}
	if dag.Layers["sha256:mid"].SizeBytes != 50*mib || dag.Layers["sha256:top"].SizeBytes != 50*mib {
		t.Fatalf("expected residual 100 MiB split into 50 MiB + 50 MiB, got mid=%d top=%d",
			dag.Layers["sha256:mid"].SizeBytes, dag.Layers["sha256:top"].SizeBytes)
	}
	if dag.Images["sha256:derivedImg"].ExclusiveBytes != 100*mib {
		t.Fatalf("derived ExclusiveBytes = %d, want %d", dag.Images["sha256:derivedImg"].ExclusiveBytes, 100*mib)
	}
}

func TestPlanner_HundredIterationDeterministicTieBreaking(t *testing.T) {
	t.Parallel()

	const mib = int64(1024 * 1024)
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	sameTime := now.Add(-24 * time.Hour)

	baseInputs := make([]RawImageInput, 0, 10)
	// 6 identical standalone images + 2 identical 2-image orphan cliques with identical byte sizes & ages.
	for i := 0; i < 6; i++ {
		id := fmt.Sprintf("sha256:single_%02d", i)
		baseInputs = append(baseInputs, makeRawImage(id, []string{fmt.Sprintf("app:s%d", i)}, sameTime, []layerSpec{
			{fmt.Sprintf("sha256:L_s_%02d", i), 100 * mib},
		}))
	}
	for c := 0; c < 2; c++ {
		sharedDigest := fmt.Sprintf("sha256:L_shared_%d", c)
		for m := 0; m < 2; m++ {
			id := fmt.Sprintf("sha256:clique_%d_%d", c, m)
			baseInputs = append(baseInputs, makeRawImage(id, []string{fmt.Sprintf("svc:c%d-%d", c, m)}, sameTime, []layerSpec{
				{sharedDigest, 150 * mib},
				{fmt.Sprintf("sha256:L_top_%d_%d", c, m), 25 * mib},
			}))
		}
	}

	refDAG := Build(baseInputs, nil, SnapshotOptions{Now: now})
	refPlan := PlanReclamation(refDAG, PlanOptions{TargetBytes: 0})
	refOrder := refPlan.OrderedImageIDs()

	rng := rand.New(rand.NewSource(20261122))
	for iter := 0; iter < 100; iter++ {
		shuffled := slices.Clone(baseInputs)
		rng.Shuffle(len(shuffled), func(i, j int) {
			shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
		})

		d := Build(shuffled, nil, SnapshotOptions{Now: now})
		p := PlanReclamation(d, PlanOptions{TargetBytes: 0})
		gotOrder := p.OrderedImageIDs()
		if !slices.Equal(gotOrder, refOrder) {
			t.Fatalf("non-deterministic eviction order on iteration %d:\ngot:  %v\nwant: %v", iter, gotOrder, refOrder)
		}
	}
}

type fakeGraphEngine struct {
	docker.Engine
	containers []docker.ContainerSummary
	summaries  []docker.ImageSummary
	inspects   map[string]docker.ImageInspect
	histories  map[string][]docker.ImageHistoryItem
}

func (f *fakeGraphEngine) ListContainers(context.Context, docker.ListContainersOptions) ([]docker.ContainerSummary, error) {
	return f.containers, nil
}

func (f *fakeGraphEngine) ListImages(context.Context, docker.ListImagesOptions) ([]docker.ImageSummary, error) {
	return f.summaries, nil
}

func (f *fakeGraphEngine) InspectImage(_ context.Context, id string) (docker.ImageInspect, error) {
	insp, ok := f.inspects[id]
	if !ok {
		return docker.ImageInspect{}, &docker.APIError{
			StatusCode: 404,
			Method:     "GET",
			Endpoint:   "/images/" + id + "/json",
			Message:    "No such image",
		}
	}
	return insp, nil
}

func (f *fakeGraphEngine) ImageHistory(_ context.Context, id string) ([]docker.ImageHistoryItem, error) {
	hist, ok := f.histories[id]
	if !ok {
		return nil, &docker.APIError{StatusCode: 404, Method: "GET", Endpoint: "/images/" + id + "/history"}
	}
	return hist, nil
}

func TestBuildFromEngine_GracefullySkipsConcurrent404Disappearance(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	const mib = int64(1024 * 1024)

	surviving := makeRawImage("sha256:alive", []string{"worker:v2"}, now.Add(-10*time.Hour), []layerSpec{
		{"sha256:L1", 80 * mib},
	})

	eng := &fakeGraphEngine{
		summaries: []docker.ImageSummary{
			surviving.Summary,
			{ID: "sha256:vanished_mid_scan", RepoTags: []string{"ephemeral:tmp"}, Size: 50 * mib},
		},
		inspects: map[string]docker.ImageInspect{
			"sha256:alive": surviving.Inspect,
		},
		histories: map[string][]docker.ImageHistoryItem{
			"sha256:alive": surviving.History,
		},
	}

	dag, err := BuildFromEngine(context.Background(), eng, SnapshotOptions{
		Now:            now,
		MaxConcurrency: 2,
	})
	if err != nil {
		t.Fatalf("BuildFromEngine failed on concurrent 404 disappearance: %v", err)
	}
	if len(dag.ImageOrder) != 1 || dag.ImageOrder[0] != "sha256:alive" {
		t.Fatalf("expected only surviving image in DAG, got %v", dag.ImageOrder)
	}
	if dag.TotalUniqueLayerBytes != 80*mib {
		t.Fatalf("TotalUniqueLayerBytes = %d, want %d", dag.TotalUniqueLayerBytes, 80*mib)
	}
}

type layerSpec struct {
	digest string
	size   int64
}

func makeRawImage(id string, tags []string, created time.Time, specs []layerSpec) RawImageInput {
	var total int64
	layers := make([]string, 0, len(specs))
	history := make([]docker.ImageHistoryItem, 0, len(specs)+1)

	for _, sp := range specs {
		layers = append(layers, sp.digest)
		total += sp.size
	}
	// History is ordered newest-to-oldest plus a synthetic 0-byte CMD metadata entry.
	history = append(history, docker.ImageHistoryItem{
		Created:   created.Unix(),
		CreatedBy: "CMD [\"/app\"]",
		Size:      0,
	})
	for i := len(specs) - 1; i >= 0; i-- {
		history = append(history, docker.ImageHistoryItem{
			ID:        strings.TrimPrefix(specs[i].digest, "sha256:"),
			Created:   created.Unix(),
			CreatedBy: "ADD layer",
			Size:      specs[i].size,
		})
	}

	return RawImageInput{
		Summary: docker.ImageSummary{
			ID:       id,
			RepoTags: tags,
			Created:  created.Unix(),
			Size:     total,
		},
		Inspect: docker.ImageInspect{
			ID:       id,
			RepoTags: tags,
			Created:  created.UTC().Format(time.RFC3339Nano),
			Size:     total,
			RootFS: docker.RootFS{
				Type:   "layers",
				Layers: layers,
			},
		},
		History: history,
	}
}
