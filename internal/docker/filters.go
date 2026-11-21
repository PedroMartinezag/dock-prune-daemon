package docker

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Filters builds canonical Moby REST API filter maps (map[string]map[string]bool)
// with deterministic lexicographical JSON serialization across all Go runtimes.
type Filters struct {
	terms map[string]map[string]bool
}

// NewFilters creates an empty Docker API filter set.
func NewFilters() Filters {
	return Filters{
		terms: make(map[string]map[string]bool),
	}
}

// Clone returns an isolated deep copy of Filters.
func (f Filters) Clone() Filters {
	out := NewFilters()
	for k, inner := range f.terms {
		copied := make(map[string]bool, len(inner))
		for val, active := range inner {
			copied[val] = active
		}
		out.terms[k] = copied
	}
	return out
}

// Add inserts a filter key/value pair, ignoring empty keys or values.
func (f *Filters) Add(key, value string) *Filters {
	k := strings.TrimSpace(key)
	v := strings.TrimSpace(value)
	if k == "" || v == "" {
		return f
	}
	if f.terms == nil {
		f.terms = make(map[string]map[string]bool)
	}
	bucket, ok := f.terms[k]
	if !ok {
		bucket = make(map[string]bool)
		f.terms[k] = bucket
	}
	bucket[v] = true
	return f
}

// AddUntil appends an 'until' age threshold formatted in whole seconds ("3600s")
// for universal compatibility across Docker, Moby, and Podman REST engines.
func (f *Filters) AddUntil(minAge time.Duration) *Filters {
	if minAge <= 0 {
		return f
	}
	secs := int64(minAge.Seconds())
	if secs < 1 {
		secs = 1
	}
	return f.Add("until", strconv.FormatInt(secs, 10)+"s")
}

// AddDangling restricts image queries or prunes to dangling (<none>:<none>) or tagged images.
func (f *Filters) AddDangling(dangling bool) *Filters {
	return f.Add("dangling", strconv.FormatBool(dangling))
}

// IncludeLabels restricts matches to resources carrying all specified label expressions.
func (f *Filters) IncludeLabels(labels []string) *Filters {
	for _, lbl := range labels {
		f.Add("label", lbl)
	}
	return f
}

// ExcludeLabels grants immunity to resources carrying any of the specified label expressions.
func (f *Filters) ExcludeLabels(labels []string) *Filters {
	for _, lbl := range labels {
		f.Add("label!", lbl)
	}
	return f
}

// IsEmpty reports whether zero filter predicates have been registered.
func (f Filters) IsEmpty() bool {
	return len(f.terms) == 0
}

// Len returns the number of distinct top-level filter keys.
func (f Filters) Len() int {
	return len(f.terms)
}

// EncodeJSON serializes the filter set into canonical JSON, or "" when empty.
func (f Filters) EncodeJSON() (string, error) {
	if f.IsEmpty() {
		return "", nil
	}
	raw, err := json.Marshal(f.terms)
	if err != nil {
		return "", fmt.Errorf("marshal docker filters: %w", err)
	}
	return string(raw), nil
}

// ApplyQuery sets the "filters" query parameter on q when the filter set is non-empty.
func (f Filters) ApplyQuery(q url.Values) error {
	if q == nil || f.IsEmpty() {
		return nil
	}
	encoded, err := f.EncodeJSON()
	if err != nil {
		return err
	}
	q.Set("filters", encoded)
	return nil
}
