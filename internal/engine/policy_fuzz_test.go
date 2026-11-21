package engine

import (
	"strings"
	"testing"
	"time"

	"github.com/PedroMartinezag/dock-prune-daemon/internal/config"
	"github.com/PedroMartinezag/dock-prune-daemon/internal/docker"
	"github.com/PedroMartinezag/dock-prune-daemon/internal/graph"
)

func TestMatchGlob_OCIRefs_CharacterClasses_AndMalformedBrackets(t *testing.T) {
	t.Parallel()

	cases := []struct {
		pattern string
		target  string
		want    bool
	}{
		{"postgres:*", "postgres:16-alpine", true},
		{"ghcr.io/org/*", "ghcr.io/org/platform/api:v2.1.0", true},
		{"*:prod-*", "registry.internal:5000/payments:prod-20261122", true},
		{"app:v[1-3].?", "app:v2.4", true},
		{"app:v[1-3].?", "app:v8.4", false},
		{"app:v[!0-2].*", "app:v3.0", true},
		{"app:v[!0-2].*", "app:v1.0", false},
		{"literal-[unclosed*", "literal-[unclosed-tag", true},
		{"*", "", true},
		{"", "", true},
		{"alpine:3", "alpine:3.19", false},
	}

	for _, tc := range cases {
		if got := MatchGlob(tc.pattern, tc.target); got != tc.want {
			t.Errorf("MatchGlob(%q, %q) = %v, want %v", tc.pattern, tc.target, got, tc.want)
		}
	}
}

func TestGuard_ContainerImageAndVolumeImmunity(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	guard := NewGuard(config.PruneConfig{
		MinResourceAge:             config.Duration(1 * time.Hour),
		EnableVolumePrune:          true,
		ProtectedLabels:            []string{"io.dockprune.keep=true", "com.company.critical"},
		ProtectedImagePatterns:     []string{"postgres:*", "ghcr.io/core/*"},
		ProtectedContainerPrefixes: []string{"k8s_", " stateful-"},
	})

	// 1. Container prefix & active state checks
	if ok, _ := guard.CheckContainer(docker.ContainerSummary{
		ID:      "c1",
		Names:   []string{"/worker-1"},
		State:   "running",
		Created: now.Add(-5 * time.Hour).Unix(),
	}, now); !ok {
		t.Fatal("running container must always be protected")
	}

	if ok, _ := guard.CheckContainer(docker.ContainerSummary{
		ID:      "c2",
		Names:   []string{"/k8s_POD_coredns"},
		State:   "exited",
		Created: now.Add(-5 * time.Hour).Unix(),
	}, now); !ok {
		t.Fatal("container matching k8s_ prefix must be protected")
	}

	if ok, _ := guard.CheckContainer(docker.ContainerSummary{
		ID:      "c3",
		Names:   []string{"/ephemeral-job"},
		State:   "exited",
		Created: now.Add(-15 * time.Minute).Unix(),
	}, now); !ok {
		t.Fatal("container younger than 1h min_resource_age must be protected")
	}

	if ok, reason := guard.CheckContainer(docker.ContainerSummary{
		ID:      "c4",
		Names:   []string{"/ephemeral-old-job"},
		State:   "exited",
		Created: now.Add(-3 * time.Hour).Unix(),
	}, now); ok {
		t.Fatalf("expected old exited container to be eligible, got protected (%s)", reason)
	}

	// 2. Docker Hub canonical alias matching ("docker.io/library/postgres:16" matched by "postgres:*")
	if ok, _ := guard.CheckImageNode(graph.ImageNode{
		ID:        "sha256:pg",
		RepoTags:  []string{"docker.io/library/postgres:16"},
		CreatedAt: now.Add(-48 * time.Hour),
	}, now); !ok {
		t.Fatal("expected docker.io/library/postgres:16 to match protected pattern postgres:*")
	}

	// Bare key existence label rule ("com.company.critical")
	if ok, _ := guard.CheckImageNode(graph.ImageNode{
		ID:        "sha256:lbl",
		RepoTags:  []string{"scratch-app:1"},
		Labels:    map[string]string{"com.company.critical": "any-value"},
		CreatedAt: now.Add(-48 * time.Hour),
	}, now); !ok {
		t.Fatal("expected bare key label rule com.company.critical to grant immunity")
	}

	// 3. Volume immunity: named volumes NEVER pruned; only unreferenced anonymous old volumes eligible
	if ok, _ := guard.CheckVolume(docker.Volume{
		Name:      "postgres_prod_data",
		CreatedAt: now.Add(-720 * time.Hour).Format(time.RFC3339),
	}, nil, now); !ok {
		t.Fatal("named volume must be permanently immune even when EnableVolumePrune=true")
	}

	anonName := strings.Repeat("a", 64)
	if ok, _ := guard.CheckVolume(docker.Volume{
		Name:      anonName,
		CreatedAt: now.Add(-72 * time.Hour).Format(time.RFC3339),
	}, map[string]bool{anonName: true}, now); !ok {
		t.Fatal("mounted anonymous volume must be protected")
	}

	if ok, reason := guard.CheckVolume(docker.Volume{
		Name:      anonName,
		CreatedAt: now.Add(-72 * time.Hour).Format(time.RFC3339),
	}, nil, now); ok {
		t.Fatalf("unmounted old anonymous volume should be eligible, got protected: %s", reason)
	}
}

func FuzzMatchGlob(f *testing.F) {
	f.Add("ghcr.io/org/*", "ghcr.io/org/service:v1.0.0")
	f.Add("*a*a*a*a*a*a*b", "aaaaaaaaaaaaaaaaaaaaaaaaac")
	f.Add("[!a-z]*[0-9?", "A_test[0-9X")
	f.Add("****", "")
	f.Add("", "ubuntu:24.04")

	f.Fuzz(func(t *testing.T, pattern, target string) {
		if len(pattern) > 512 || len(target) > 512 {
			return
		}
		_ = MatchGlob(pattern, target)

		// Universal wildcard invariant: "*" must always match every string.
		if !MatchGlob("*", target) {
			t.Fatalf("MatchGlob('*', %q) returned false", target)
		}
	})
}

func FuzzPolicyGuardImageEvaluation(f *testing.F) {
	f.Add("postgres:*,ghcr.io/team/*", "io.dockprune.keep=true,tier", "docker.io/library/postgres:16", "tier", "1")
	f.Add("*[invalid", "k=v", "custom/app:latest", "other", "v")

	f.Fuzz(func(t *testing.T, rawPatterns, rawLabels, imageTag, lblKey, lblVal string) {
		if len(rawPatterns) > 256 || len(rawLabels) > 256 || len(imageTag) > 256 {
			return
		}
		guard := NewGuard(config.PruneConfig{
			MinResourceAge:         config.Duration(30 * time.Minute),
			ProtectedLabels:        strings.Split(rawLabels, ","),
			ProtectedImagePatterns: strings.Split(rawPatterns, ","),
		})

		now := time.Unix(1750000000, 0).UTC()
		node := graph.ImageNode{
			ID:        "sha256:fuzz",
			RepoTags:  []string{imageTag},
			Labels:    map[string]string{lblKey: lblVal},
			CreatedAt: now.Add(-2 * time.Hour),
		}

		p1, r1 := guard.CheckImageNode(node, now)
		p2, r2 := guard.CheckImageNode(node, now)
		if p1 != p2 || r1 != r2 {
			t.Fatalf("non-deterministic policy decision: (%v,%q) vs (%v,%q)", p1, r1, p2, r2)
		}
	})
}
