/*
Copyright © 2022 GUILLAUME FOURNIER

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package events

import (
	"fmt"
	"time"

	"github.com/DataDog/gopsutil/host"
	"golang.org/x/sys/unix"
)

// TimeResolver converts kernel monotonic timestamps to absolute times
type TimeResolver struct {
	bootTime time.Time
}

// NewTimeResolver returns a new time resolver
func NewTimeResolver() (*TimeResolver, error) {
	bt, err := host.BootTime()
	if err != nil {
		return nil, err
	}

	tr := TimeResolver{
		bootTime: time.Unix(int64(bt), 0),
	}
	return &tr, nil
}

func (tr *TimeResolver) getUptimeOffset() (time.Duration, error) {
	upTime := new(unix.Timespec)
	err := unix.ClockGettime(unix.CLOCK_MONOTONIC, upTime)
	if err != nil {
		return 0, fmt.Errorf("couldn't get system up time: %w", err)
	}
	return time.Since(tr.bootTime) - time.Duration(upTime.Nano()), nil
}

// ResolveMonotonicTimestamp converts a kernel monotonic timestamp to an absolute time
func (tr *TimeResolver) ResolveMonotonicTimestamp(timestamp uint64) time.Time {
	if timestamp > 0 {
		// ignore uptime resolution failure: default back to previous behavior
		offset, _ := tr.getUptimeOffset()
		return tr.bootTime.Add(time.Duration(timestamp) + offset)
	}
	return time.Time{}
}

// ApplyBootTime return the time re-aligned from the boot time
func (tr *TimeResolver) ApplyBootTime(timestamp time.Time) time.Time {
	if !timestamp.IsZero() {
		// ignore uptime resolution failure: default back to previous behavior
		offset, _ := tr.getUptimeOffset()
		return timestamp.Add(time.Duration(tr.bootTime.UnixNano()) + offset)
	}
	return time.Time{}
}

// ComputeMonotonicTimestamp converts an absolute time to a kernel monotonic timestamp
func (tr *TimeResolver) ComputeMonotonicTimestamp(timestamp time.Time) int64 {
	if !timestamp.IsZero() {
		// ignore uptime resolution failure: default back to previous behavior
		offset, _ := tr.getUptimeOffset()
		return timestamp.Sub(tr.bootTime.Add(offset)).Nanoseconds()
	}
	return 0
}
