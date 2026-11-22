// Package docker provides a zero-dependency HTTP-over-Unix-Socket and TCP client
// for the Docker/Moby Engine REST API with automatic version negotiation,
// 3-state circuit breaking, and resilient NDJSON event streaming.
package docker

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// PingInfo captures engine readiness headers returned by GET/HEAD /_ping.
type PingInfo struct {
	APIVersion     string `json:"api_version"`
	OSType         string `json:"os_type"`
	BuilderVersion string `json:"builder_version"`
	Experimental   bool   `json:"experimental"`
}

// VersionInfo models the payload returned by GET /version.
type VersionInfo struct {
	Version       string `json:"Version"`
	APIVersion    string `json:"ApiVersion"`
	MinAPIVersion string `json:"MinAPIVersion"`
	GitCommit     string `json:"GitCommit"`
	Os            string `json:"Os"`
	Arch          string `json:"Arch"`
	KernelVersion string `json:"KernelVersion"`
}

// MountPoint describes a volume or bind mount attached to a container.
type MountPoint struct {
	Type        string `json:"Type"`
	Name        string `json:"Name"`
	Source      string `json:"Source"`
	Destination string `json:"Destination"`
	Mode        string `json:"Mode"`
	RW          bool   `json:"RW"`
}

// ContainerSummary models an entry from GET /containers/json.
type ContainerSummary struct {
	ID         string            `json:"Id"`
	Names      []string          `json:"Names"`
	Image      string            `json:"Image"`
	ImageID    string            `json:"ImageID"`
	Command    string            `json:"Command"`
	Created    int64             `json:"Created"`
	State      string            `json:"State"`
	Status     string            `json:"Status"`
	Labels     map[string]string `json:"Labels"`
	SizeRw     int64             `json:"SizeRw,omitempty"`
	SizeRootFs int64             `json:"SizeRootFs,omitempty"`
	Mounts     []MountPoint      `json:"Mounts"`
}

// PrimaryName returns the canonical container name without a leading slash.
func (c ContainerSummary) PrimaryName() string {
	for _, raw := range c.Names {
		clean := strings.TrimPrefix(strings.TrimSpace(raw), "/")
		if clean != "" {
			return clean
		}
	}
	if len(c.ID) >= 12 {
		return c.ID[:12]
	}
	return c.ID
}

// CreatedTime converts the Unix epoch timestamp into UTC time.Time.
func (c ContainerSummary) CreatedTime() time.Time {
	if c.Created <= 0 {
		return time.Time{}
	}
	return time.Unix(c.Created, 0).UTC()
}

// IsRunning reports whether the container is actively executing or restarting.
func (c ContainerSummary) IsRunning() bool {
	switch strings.ToLower(strings.TrimSpace(c.State)) {
	case "running", "restarting", "paused":
		return true
	default:
		return false
	}
}

// ContainerState holds runtime execution state from GET /containers/{id}/json.
type ContainerState struct {
	Status     string `json:"Status"`
	Running    bool   `json:"Running"`
	Paused     bool   `json:"Paused"`
	Restarting bool   `json:"Restarting"`
	OOMKilled  bool   `json:"OOMKilled"`
	Dead       bool   `json:"Dead"`
	Pid        int    `json:"Pid"`
	ExitCode   int    `json:"ExitCode"`
	StartedAt  string `json:"StartedAt"`
	FinishedAt string `json:"FinishedAt"`
}

// ContainerConfig holds user-level metadata inside ContainerInspect.
type ContainerConfig struct {
	Hostname string            `json:"Hostname"`
	Image    string            `json:"Image"`
	Labels   map[string]string `json:"Labels"`
}

// LogConfig captures logging driver configuration inside HostConfig.
type LogConfig struct {
	Type   string            `json:"Type"`
	Config map[string]string `json:"Config"`
}

// HostConfig captures host runtime parameters inside ContainerInspect.
type HostConfig struct {
	LogConfig   LogConfig `json:"LogConfig"`
	AutoRemove  bool      `json:"AutoRemove"`
	NetworkMode string    `json:"NetworkMode"`
}

// ContainerInspect models the detailed response of GET /containers/{id}/json.
type ContainerInspect struct {
	ID         string          `json:"Id"`
	Created    string          `json:"Created"`
	Name       string          `json:"Name"`
	Image      string          `json:"Image"`
	LogPath    string          `json:"LogPath"`
	State      ContainerState  `json:"State"`
	Config     ContainerConfig `json:"Config"`
	HostConfig HostConfig      `json:"HostConfig"`
	SizeRw     *int64          `json:"SizeRw,omitempty"`
	SizeRootFs *int64          `json:"SizeRootFs,omitempty"`
	Mounts     []MountPoint    `json:"Mounts"`
}
// ImageSummary models an entry from GET /images/json.
type ImageSummary struct {
	ID          string            `json:"Id"`
	ParentID    string            `json:"ParentId"`
	RepoTags    []string          `json:"RepoTags"`
	RepoDigests []string          `json:"RepoDigests"`
	Created     int64             `json:"Created"`
	Size        int64             `json:"Size"`
	SharedSize  int64             `json:"SharedSize"`
	VirtualSize int64             `json:"VirtualSize,omitempty"`
	Labels      map[string]string `json:"Labels"`
	Containers  int64             `json:"Containers"`
}

// CreatedTime converts the image creation epoch timestamp into UTC time.Time.
func (img ImageSummary) CreatedTime() time.Time {
	if img.Created <= 0 {
		return time.Time{}
	}
	return time.Unix(img.Created, 0).UTC()
}

// IsDangling reports whether the image has no meaningful repository tag attached.
func (img ImageSummary) IsDangling() bool {
	if len(img.RepoTags) == 0 {
		return true
	}
	for _, tag := range img.RepoTags {
		trimmed := strings.TrimSpace(tag)
		if trimmed != "" && trimmed != "<none>:<none>" {
			return false
		}
	}
	return true
}

// RootFS contains ordered OCI layer diff_ids from GET /images/{id}/json.
type RootFS struct {
	Type   string   `json:"Type"`
	Layers []string `json:"Layers"`
}

// GraphDriverData describes the backing storage driver (overlay2, btrfs, zfs).
type GraphDriverData struct {
	Name string            `json:"Name"`
	Data map[string]string `json:"Data"`
}

// ImageMetadata captures local engine metadata such as LastTagTime.
type ImageMetadata struct {
	LastTagTime string `json:"LastTagTime"`
}

// ImageConfig holds OCI image configuration metadata and labels.
type ImageConfig struct {
	Labels     map[string]string `json:"Labels"`
	User       string            `json:"User"`
	Cmd        []string          `json:"Cmd"`
	Entrypoint []string          `json:"Entrypoint"`
}

// ImageInspect models the response of GET /images/{id}/json.
type ImageInspect struct {
	ID          string          `json:"Id"`
	RepoTags    []string        `json:"RepoTags"`
	RepoDigests []string        `json:"RepoDigests"`
	Parent      string          `json:"Parent"`
	Created     string          `json:"Created"`
	Size        int64           `json:"Size"`
	VirtualSize int64           `json:"VirtualSize,omitempty"`
	Config      *ImageConfig    `json:"Config"`
	RootFS      RootFS          `json:"RootFS"`
	GraphDriver GraphDriverData `json:"GraphDriver"`
	Metadata    ImageMetadata   `json:"Metadata"`
}

// ImageHistoryItem models a layer construction entry from GET /images/{id}/history.
type ImageHistoryItem struct {
	ID        string   `json:"Id"`
	Created   int64    `json:"Created"`
	CreatedBy string   `json:"CreatedBy"`
	Tags      []string `json:"Tags"`
	Size      int64    `json:"Size"`
	Comment   string   `json:"Comment"`
}

// VolumeUsageData holds reference count and byte usage when reported by the engine.
type VolumeUsageData struct {
	Size     int64 `json:"Size"`
	RefCount int64 `json:"RefCount"`
}

// Volume models a Docker storage volume from GET /volumes.
type Volume struct {
	Name       string            `json:"Name"`
	Driver     string            `json:"Driver"`
	Mountpoint string            `json:"Mountpoint"`
	CreatedAt  string            `json:"CreatedAt"`
	Labels     map[string]string `json:"Labels"`
	Scope      string            `json:"Scope"`
	Options    map[string]string `json:"Options"`
	UsageData  *VolumeUsageData  `json:"UsageData,omitempty"`
}

// IsAnonymous reports whether the volume is an unnamed/anonymous engine volume
// (either explicitly marked by Moby >= 23 or identified by a 64-hex random ID).
func (v Volume) IsAnonymous() bool {
	if v.Labels != nil {
		if _, ok := v.Labels["com.docker.volume.anonymous"]; ok {
			return true
		}
	}
	if len(v.Name) != 64 {
		return false
	}
	for i := 0; i < 64; i++ {
		ch := v.Name[i]
		if !((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f')) {
			return false
		}
	}
	return true
}

// VolumeListResponse models the envelope returned by GET /volumes.
type VolumeListResponse struct {
	Volumes  []Volume `json:"Volumes"`
	Warnings []string `json:"Warnings"`
}
// ContainersPruneReport models POST /containers/prune output.
type ContainersPruneReport struct {
	ContainersDeleted []string `json:"ContainersDeleted"`
	SpaceReclaimed    uint64   `json:"SpaceReclaimed"`
}

// ImageDeleteItem represents an untagged or deleted layer entry from image removal.
type ImageDeleteItem struct {
	Untagged string `json:"Untagged,omitempty"`
	Deleted  string `json:"Deleted,omitempty"`
}

// ImagesPruneReport models POST /images/prune output.
type ImagesPruneReport struct {
	ImagesDeleted  []ImageDeleteItem `json:"ImagesDeleted"`
	SpaceReclaimed uint64            `json:"SpaceReclaimed"`
}

// NetworksPruneReport models POST /networks/prune output.
type NetworksPruneReport struct {
	NetworksDeleted []string `json:"NetworksDeleted"`
}

// VolumesPruneReport models POST /volumes/prune output.
type VolumesPruneReport struct {
	VolumesDeleted []string `json:"VolumesDeleted"`
	SpaceReclaimed uint64   `json:"SpaceReclaimed"`
}

// BuildCachePruneReport models POST /build/prune output.
type BuildCachePruneReport struct {
	CachesDeleted  []string `json:"CachesDeleted"`
	SpaceReclaimed uint64   `json:"SpaceReclaimed"`
}

// EventActor holds the object identifier and attributes inside an EventMessage.
type EventActor struct {
	ID         string            `json:"ID"`
	Attributes map[string]string `json:"Attributes"`
}

// EventMessage models a real-time NDJSON event emitted by GET /events.
type EventMessage struct {
	Type     string     `json:"Type"`
	Action   string     `json:"Action"`
	Actor    EventActor `json:"Actor"`
	Scope    string     `json:"scope"`
	Time     int64      `json:"time"`
	TimeNano int64      `json:"timeNano"`
}

// Timestamp returns the highest-precision UTC timestamp available on the event.
func (e EventMessage) Timestamp() time.Time {
	if e.TimeNano > 0 {
		return time.Unix(0, e.TimeNano).UTC()
	}
	if e.Time > 0 {
		return time.Unix(e.Time, 0).UTC()
	}
	return time.Time{}
}

// ListContainersOptions parameterizes GET /containers/json.
type ListContainersOptions struct {
	All     bool
	Size    bool
	Filters Filters
}

// RemoveContainerOptions parameterizes DELETE /containers/{id}.
type RemoveContainerOptions struct {
	Force         bool
	RemoveVolumes bool
}

// ListImagesOptions parameterizes GET /images/json.
type ListImagesOptions struct {
	All        bool
	SharedSize bool
	Filters    Filters
}

// RemoveImageOptions parameterizes DELETE /images/{id}.
type RemoveImageOptions struct {
	Force   bool
	NoPrune bool
}

// BuildCachePruneOptions parameterizes POST /build/prune.
type BuildCachePruneOptions struct {
	All         bool
	KeepStorage int64
	Filters     Filters
}

// EventsOptions parameterizes GET /events.
type EventsOptions struct {
	Since   string
	Until   string
	Filters Filters
}

// APIError represents an HTTP error response returned by the Docker Engine daemon.
type APIError struct {
	StatusCode int    `json:"status_code"`
	Method     string `json:"method"`
	Endpoint   string `json:"endpoint"`
	Message    string `json:"message"`
}

// Error formats the HTTP status, endpoint, and daemon diagnostic message.
func (e *APIError) Error() string {
	if e == nil {
		return ""
	}
	if e.Message != "" {
		return fmt.Sprintf("docker API %s %s failed (HTTP %d): %s", e.Method, e.Endpoint, e.StatusCode, e.Message)
	}
	return fmt.Sprintf("docker API %s %s failed (HTTP %d)", e.Method, e.Endpoint, e.StatusCode)
}

// IsNotFound reports whether the requested resource or endpoint returned HTTP 404.
func (e *APIError) IsNotFound() bool {
	return e != nil && e.StatusCode == 404
}

// IsConflict reports whether the resource is actively in use (HTTP 409).
func (e *APIError) IsConflict() bool {
	return e != nil && e.StatusCode == 409
}

// IsNotImplemented reports whether the engine lacks support for an endpoint (HTTP 501).
func (e *APIError) IsNotImplemented() bool {
	return e != nil && e.StatusCode == 501
}

// IsServerFault reports whether the daemon experienced an internal 5xx failure.
func (e *APIError) IsServerFault() bool {
	return e != nil && e.StatusCode >= 500
}

// Engine defines the complete Docker/Moby control contract consumed by the OCI DAG
// planner, 5-stage waterfall pruner, diagnostic doctor, and event-driven daemon.
type Engine interface {
	Ping(ctx context.Context) (PingInfo, error)
	Version(ctx context.Context) (VersionInfo, error)

	ListContainers(ctx context.Context, opts ListContainersOptions) ([]ContainerSummary, error)
	InspectContainer(ctx context.Context, id string) (ContainerInspect, error)
	RemoveContainer(ctx context.Context, id string, opts RemoveContainerOptions) error
	PruneContainers(ctx context.Context, filters Filters) (ContainersPruneReport, error)

	ListImages(ctx context.Context, opts ListImagesOptions) ([]ImageSummary, error)
	InspectImage(ctx context.Context, id string) (ImageInspect, error)
	ImageHistory(ctx context.Context, id string) ([]ImageHistoryItem, error)
	RemoveImage(ctx context.Context, id string, opts RemoveImageOptions) ([]ImageDeleteItem, error)
	PruneImages(ctx context.Context, danglingOnly bool, filters Filters) (ImagesPruneReport, error)

	PruneNetworks(ctx context.Context, filters Filters) (NetworksPruneReport, error)
	PruneBuildCache(ctx context.Context, opts BuildCachePruneOptions) (BuildCachePruneReport, error)

	ListVolumes(ctx context.Context, filters Filters) (VolumeListResponse, error)
	RemoveVolume(ctx context.Context, name string, force bool) error
	PruneVolumes(ctx context.Context, filters Filters) (VolumesPruneReport, error)

	StreamEvents(ctx context.Context, opts EventsOptions, onEvent func(EventMessage)) error
	BreakerStats() BreakerStats
	Close() error
}
