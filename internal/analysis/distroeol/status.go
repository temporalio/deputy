package distroeol

import (
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	vulnerabilityv1 "github.com/temporalio/deputy/gen/deputy/vulnerability/v1"
)

// Status evaluates an identity against the dataset at t and returns the
// coverage record for it. subject names the image reference for an
// OriginImageRef identity.
func (d *Dataset) Status(id Identity, subject string, t time.Time) *vulnerabilityv1.DistroRelease {
	out := &vulnerabilityv1.DistroRelease{
		Distribution:    id.Distribution,
		Release:         id.Release,
		Version:         id.Version,
		Status:          vulnerabilityv1.DistroStatus_DISTRO_STATUS_UNKNOWN,
		Origin:          id.Origin,
		Subject:         subject,
		DatasetSnapshot: d.Snapshot,
	}
	rel, ok := d.Lookup(id.Distribution, id.Release)
	if !ok {
		return out
	}
	out.Release = rel.Name
	out.Codename = rel.Codename
	out.Eol = timestamppb.New(rel.EOL)
	if !rel.ExtendedSupport.IsZero() {
		out.ExtendedSupportUntil = timestamppb.New(rel.ExtendedSupport)
	}
	out.DaysPastEol = daysBetween(rel.EOL, t)
	if t.Before(rel.EOL) {
		out.Status = vulnerabilityv1.DistroStatus_DISTRO_STATUS_SUPPORTED
	} else {
		out.Status = vulnerabilityv1.DistroStatus_DISTRO_STATUS_EOL
	}
	if oldest, latest, ok := d.Supported(id.Distribution, t, rel.LTS); ok {
		out.OldestSupportedRelease = oldest.Name
		out.LatestRelease = latest.Name
	}
	return out
}

// daysBetween returns whole days from a to b, negative when b is before a.
func daysBetween(a, b time.Time) int32 {
	return int32(b.Sub(a) / (24 * time.Hour))
}
