// Package engine implements the 5-stage surgical storage reclamation waterfall,
// Stage 0 forensic O_APPEND container log truncation, and multi-rule resource
// immunity policy evaluation.
package engine

import (
	"fmt"
	"strings"
	"time"

	"github.com/PedroMartinezag/dock-prune-daemon/internal/config"
	"github.com/PedroMartinezag/dock-prune-daemon/internal/docker"
	"github.com/PedroMartinezag/dock-prune-daemon/internal/graph"
)

type labelRule struct {
	raw      string
	key      string
	hasValue bool
	value    string
}

// Guard enforces operator-configured immunity rules across containers, OCI images,
// and volumes (protected labels, glob patterns, container prefixes, and minimum age).
type Guard struct {
	minAge            time.Duration
	enableVolumePrune bool
	rawLabels         []string
	labelRules        []labelRule
	imagePatterns     []string
	containerPrefixes []string
}

// NewGuard compiles a PruneConfig into an immutable, concurrency-safe policy guard.
func NewGuard(cfg config.PruneConfig) *Guard {
	rules := make([]labelRule, 0, len(cfg.ProtectedLabels))
	rawLabels := make([]string, 0, len(cfg.ProtectedLabels))
	for _, expr := range cfg.ProtectedLabels {
		trimmed := strings.TrimSpace(expr)
		if trimmed == "" {
			continue
		}
		rawLabels = append(rawLabels, trimmed)
		if eqIdx := strings.IndexByte(trimmed, '='); eqIdx >= 0 {
			k := strings.TrimSpace(trimmed[:eqIdx])
			v := strings.TrimSpace(trimmed[eqIdx+1:])
			if k != "" {
				rules = append(rules, labelRule{
					raw:      trimmed,
					key:      k,
					hasValue: true,
					value:    v,
				})
			}
		} else {
			rules = append(rules, labelRule{
				raw:      trimmed,
				key:      trimmed,
				hasValue: false,
			})
		}
	}

	patterns := make([]string, 0, len(cfg.ProtectedImagePatterns))
	for _, pat := range cfg.ProtectedImagePatterns {
		if trimmed := strings.TrimSpace(pat); trimmed != "" {
			patterns = append(patterns, trimmed)
		}
	}

	prefixes := make([]string, 0, len(cfg.ProtectedContainerPrefixes))
	for _, pfx := range cfg.ProtectedContainerPrefixes {
		clean := strings.TrimPrefix(strings.TrimSpace(pfx), "/")
		if clean != "" {
			prefixes = append(prefixes, clean)
		}
	}

	minAge := cfg.MinResourceAge.Std()
	if minAge < 0 {
		minAge = 0
	}

	return &Guard{
		minAge:            minAge,
		enableVolumePrune: cfg.EnableVolumePrune,
		rawLabels:         rawLabels,
		labelRules:        rules,
		imagePatterns:     patterns,
		containerPrefixes: prefixes,
	}
}

// BaseDockerFilters builds server-side Moby query filters enforcing minimum age
// and protected label exclusions on bulk prune endpoints.
func (g *Guard) BaseDockerFilters() docker.Filters {
	f := docker.NewFilters()
	if g == nil {
		return f
	}
	if g.minAge > 0 {
		f.AddUntil(g.minAge)
	}
	if len(g.rawLabels) > 0 {
		f.ExcludeLabels(g.rawLabels)
	}
	return f
}

// CheckLabels reports whether a resource's label map matches any protected label rule.
func (g *Guard) CheckLabels(labels map[string]string) (protected bool, reason string) {
	if g == nil || len(labels) == 0 || len(g.labelRules) == 0 {
		return false, ""
	}
	for _, rule := range g.labelRules {
		actual, exists := labels[rule.key]
		if !exists {
			continue
		}
		if !rule.hasValue || actual == rule.value {
			return true, fmt.Sprintf("protected by label %q", rule.raw)
		}
	}
	return false, ""
}

// CheckContainer evaluates whether a container is immune from Stage 1 removal.
func (g *Guard) CheckContainer(ctr docker.ContainerSummary, now time.Time) (protected bool, reason string) {
	if ctr.IsRunning() {
		return true, fmt.Sprintf("container is active (state=%s)", ctr.State)
	}
	if g == nil {
		return false, ""
	}

	for _, rawName := range ctr.Names {
		clean := strings.TrimPrefix(strings.TrimSpace(rawName), "/")
		for _, pfx := range g.containerPrefixes {
			if strings.HasPrefix(clean, pfx) {
				return true, fmt.Sprintf("container name %q matches protected prefix %q", clean, pfx)
			}
		}
	}

	if ok, lblReason := g.CheckLabels(ctr.Labels); ok {
		return true, lblReason
	}

	if g.minAge > 0 {
		created := ctr.CreatedTime()
		if !created.IsZero() && now.After(created) && now.Sub(created) < g.minAge {
			return true, fmt.Sprintf("younger than min_resource_age (%s)", g.minAge)
		}
		if !created.IsZero() && !now.After(created) {
			return true, fmt.Sprintf("created in future/current instant relative to min_resource_age (%s)", g.minAge)
		}
	}
	return false, ""
}

// CheckContainerInspect evaluates whether a container's log file is immune from
// Stage 0 truncation due to protected labels or protected container name prefixes.
func (g *Guard) CheckContainerInspect(insp docker.ContainerInspect) (protected bool, reason string) {
	if g == nil {
		return false, ""
	}
	cleanName := strings.TrimPrefix(strings.TrimSpace(insp.Name), "/")
	for _, pfx := range g.containerPrefixes {
		if cleanName != "" && strings.HasPrefix(cleanName, pfx) {
			return true, fmt.Sprintf("container name %q matches protected prefix %q", cleanName, pfx)
		}
	}
	return g.CheckLabels(insp.Config.Labels)
}

// CheckImageNode evaluates whether a DAG ImageNode is immune from Stage 4 eviction.
func (g *Guard) CheckImageNode(img graph.ImageNode, now time.Time) (protected bool, reason string) {
	if g == nil {
		return false, ""
	}
	if ok, lblReason := g.CheckLabels(img.Labels); ok {
		return true, lblReason
	}
	if ok, patReason := g.matchImageRefs(img.RepoTags, img.RepoDigests); ok {
		return true, patReason
	}
	if g.minAge > 0 && !img.CreatedAt.IsZero() {
		if !now.After(img.CreatedAt) || now.Sub(img.CreatedAt) < g.minAge {
			return true, fmt.Sprintf("image younger than min_resource_age (%s)", g.minAge)
		}
	}
	return false, ""
}

// GraphProtectCheck binds now and returns a closure satisfying graph.ProtectionCheckFunc.
func (g *Guard) GraphProtectCheck(now time.Time) graph.ProtectionCheckFunc {
	return func(img graph.ImageNode) (bool, string) {
		return g.CheckImageNode(img, now)
	}
}

// CheckImageSummary evaluates immunity on a raw Docker ImageSummary (used in Stage 2).
func (g *Guard) CheckImageSummary(sum docker.ImageSummary, now time.Time) (protected bool, reason string) {
	if g == nil {
		return false, ""
	}
	if ok, lblReason := g.CheckLabels(sum.Labels); ok {
		return true, lblReason
	}
	if ok, patReason := g.matchImageRefs(sum.RepoTags, sum.RepoDigests); ok {
		return true, patReason
	}
	created := sum.CreatedTime()
	if g.minAge > 0 && !created.IsZero() {
		if !now.After(created) || now.Sub(created) < g.minAge {
			return true, fmt.Sprintf("image younger than min_resource_age (%s)", g.minAge)
		}
	}
	return false, ""
}

// CheckVolume enforces strict Stage 4 volume safety: volume pruning must be explicitly
// enabled, named volumes are unconditionally immune, mounted volumes are immune,
// and protected labels + minimum resource age are respected.
func (g *Guard) CheckVolume(
	vol docker.Volume,
	mountedVolumes map[string]bool,
	now time.Time,
) (protected bool, reason string) {
	if g == nil || !g.enableVolumePrune {
		return true, "volume pruning is disabled"
	}
	if mountedVolumes[vol.Name] {
		return true, "volume is mounted by a container"
	}
	if vol.UsageData != nil && vol.UsageData.RefCount > 0 {
		return true, fmt.Sprintf("volume has active ref_count=%d", vol.UsageData.RefCount)
	}
	if !vol.IsAnonymous() {
		return true, "named volumes are permanently immune"
	}
	if ok, lblReason := g.CheckLabels(vol.Labels); ok {
		return true, lblReason
	}
	if g.minAge > 0 && strings.TrimSpace(vol.CreatedAt) != "" {
		if created, err := parseVolumeTime(vol.CreatedAt); err == nil {
			if !now.After(created) || now.Sub(created) < g.minAge {
				return true, fmt.Sprintf("volume younger than min_resource_age (%s)", g.minAge)
			}
		}
	}
	return false, ""
}

func (g *Guard) matchImageRefs(repoTags, repoDigests []string) (bool, string) {
	if len(g.imagePatterns) == 0 {
		return false, ""
	}
	for _, rawRef := range repoTags {
		for _, alias := range expandDockerRefAliases(rawRef) {
			for _, pat := range g.imagePatterns {
				if MatchGlob(pat, alias) {
					return true, fmt.Sprintf("image ref %q matched protected pattern %q", rawRef, pat)
				}
			}
		}
	}
	for _, rawDigest := range repoDigests {
		trimmed := strings.TrimSpace(rawDigest)
		if trimmed == "" || trimmed == "<none>@<none>" {
			continue
		}
		for _, pat := range g.imagePatterns {
			if MatchGlob(pat, trimmed) {
				return true, fmt.Sprintf("image digest %q matched protected pattern %q", trimmed, pat)
			}
		}
	}
	return false, ""
}

// expandDockerRefAliases normalizes Docker Hub official/short image names so patterns
// like "postgres:*" and "docker.io/library/postgres:*" match interchangeably.
func expandDockerRefAliases(raw string) []string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" || trimmed == "<none>:<none>" {
		return nil
	}
	aliases := []string{trimmed}
	addUnique := func(candidate string) {
		if candidate == "" {
			return
		}
		for _, existing := range aliases {
			if existing == candidate {
				return
			}
		}
		aliases = append(aliases, candidate)
	}

	withoutHub := strings.TrimPrefix(trimmed, "docker.io/")
	withoutHub = strings.TrimPrefix(withoutHub, "index.docker.io/")
	addUnique(withoutHub)

	withoutLib := strings.TrimPrefix(withoutHub, "library/")
	addUnique(withoutLib)

	// If reference has no registry domain (e.g. "postgres:16" or "org/app:v1"), synthesize canonical forms.
	firstSlash := strings.IndexByte(withoutHub, '/')
	if firstSlash < 0 {
		addUnique("library/" + withoutHub)
		addUnique("docker.io/library/" + withoutHub)
	} else {
		firstSeg := withoutHub[:firstSlash]
		if !strings.ContainsAny(firstSeg, ".:") && firstSeg != "localhost" {
			addUnique("docker.io/" + withoutHub)
		}
	}
	return aliases
}

// MatchGlob performs non-recursive, O(|pattern| * |target|) wildcard matching across
// full OCI image references (allowing '*' and '?' to span '/' and ':'), supporting
// '[abc]', '[a-z]', and '[!a-z]'/'[^a-z]' character classes without ReDoS risk.
func MatchGlob(pattern, target string) bool {
	p := []rune(pattern)
	s := []rune(target)

	pi, si := 0, 0
	starIdx := -1
	matchIdx := 0

	for si < len(s) {
		if pi < len(p) && p[pi] == '*' {
			for pi < len(p) && p[pi] == '*' {
				pi++
			}
			starIdx = pi - 1
			matchIdx = si
			continue
		}

		if pi < len(p) {
			if p[pi] == '?' {
				pi++
				si++
				continue
			}
			if p[pi] == '[' {
				if matched, nextPI, validClass := matchBracketClass(p, pi, s[si]); validClass {
					if matched {
						pi = nextPI
						si++
						continue
					}
				} else if p[pi] == s[si] {
					// Unclosed '[' falls back deterministically to literal rune comparison.
					pi++
					si++
					continue
				}
			} else if p[pi] == s[si] {
				pi++
				si++
				continue
			}
		}

		if starIdx != -1 {
			pi = starIdx + 1
			matchIdx++
			si = matchIdx
			continue
		}
		return false
	}

	for pi < len(p) && p[pi] == '*' {
		pi++
	}
	return pi == len(p)
}

func matchBracketClass(p []rune, openIdx int, ch rune) (matched bool, nextIdx int, valid bool) {
	i := openIdx + 1
	if i >= len(p) {
		return false, 0, false
	}

	negated := false
	if p[i] == '!' || p[i] == '^' {
		negated = true
		i++
	}

	// Find closing ']' (a ']' immediately at start of class is treated as a literal member).
	closeIdx := -1
	for scan := i; scan < len(p); scan++ {
		if p[scan] == ']' && scan > i {
			closeIdx = scan
			break
		}
	}
	if closeIdx == -1 {
		return false, 0, false
	}

	hit := false
	for cur := i; cur < closeIdx; cur++ {
		if cur+2 < closeIdx && p[cur+1] == '-' {
			lo, hi := p[cur], p[cur+2]
			if lo > hi {
				lo, hi = hi, lo
			}
			if ch >= lo && ch <= hi {
				hit = true
			}
			cur += 2
			continue
		}
		if p[cur] == ch {
			hit = true
		}
	}

	if negated {
		hit = !hit
	}
	return hit, closeIdx + 1, true
}

func parseVolumeTime(raw string) (time.Time, error) {
	trimmed := strings.TrimSpace(raw)
	if t, err := time.Parse(time.RFC3339Nano, trimmed); err == nil {
		return t.UTC(), nil
	}
	return time.Parse(time.RFC3339, trimmed)
}
