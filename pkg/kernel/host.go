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

package kernel

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/acobaugh/osrelease"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/features"
	"golang.org/x/sys/unix"

	"github.com/DataDog/btf-internals/sys"
)

var (
	// KERNEL_VERSION(a,b,c) = (a << 16) + (b << 8) + (c)

	// Kernel4_9 is the KernelVersion representation of kernel version 4.9
	Kernel4_9 = VersionCode(4, 9, 0) //nolint:deadcode,unused
	// Kernel4_10 is the KernelVersion representation of kernel version 4.10
	Kernel4_10 = VersionCode(4, 10, 0) //nolint:deadcode,unused
	// Kernel4_12 is the KernelVersion representation of kernel version 4.12
	Kernel4_12 = VersionCode(4, 12, 0) //nolint:deadcode,unused
	// Kernel4_13 is the KernelVersion representation of kernel version 4.13
	Kernel4_13 = VersionCode(4, 13, 0) //nolint:deadcode,unused
	// Kernel4_14 is the KernelVersion representation of kernel version 4.14
	Kernel4_14 = VersionCode(4, 14, 0) //nolint:deadcode,unused
	// Kernel4_15 is the KernelVersion representation of kernel version 4.15
	Kernel4_15 = VersionCode(4, 15, 0) //nolint:deadcode,unused
	// Kernel4_16 is the KernelVersion representation of kernel version 4.16
	Kernel4_16 = VersionCode(4, 16, 0) //nolint:deadcode,unused
	// Kernel4_18 is the KernelVersion representation of kernel version 4.18
	Kernel4_18 = VersionCode(4, 18, 0) //nolint:deadcode,unused
	// Kernel4_19 is the KernelVersion representation of kernel version 4.19
	Kernel4_19 = VersionCode(4, 19, 0) //nolint:deadcode,unused
	// Kernel4_20 is the KernelVersion representation of kernel version 4.20
	Kernel4_20 = VersionCode(4, 20, 0) //nolint:deadcode,unused
	// Kernel5_0 is the KernelVersion representation of kernel version 5.0
	Kernel5_0 = VersionCode(5, 0, 0) //nolint:deadcode,unused
	// Kernel5_1 is the KernelVersion representation of kernel version 5.1
	Kernel5_1 = VersionCode(5, 1, 0) //nolint:deadcode,unused
	// Kernel5_3 is the KernelVersion representation of kernel version 5.3
	Kernel5_3 = VersionCode(5, 3, 0) //nolint:deadcode,unused
	// Kernel5_4 is the KernelVersion representation of kernel version 5.4
	Kernel5_4 = VersionCode(5, 4, 0) //nolint:deadcode,unused
	// Kernel5_5 is the KernelVersion representation of kernel version 5.5
	Kernel5_5 = VersionCode(5, 5, 0) //nolint:deadcode,unused
	// Kernel5_6 is the KernelVersion representation of kernel version 5.6
	Kernel5_6 = VersionCode(5, 6, 0) //nolint:deadcode,unused
	// Kernel5_7 is the KernelVersion representation of kernel version 5.7
	Kernel5_7 = VersionCode(5, 7, 0) //nolint:deadcode,unused
	// Kernel5_8 is the KernelVersion representation of kernel version 5.8
	Kernel5_8 = VersionCode(5, 8, 0) //nolint:deadcode,unused
	// Kernel5_9 is the KernelVersion representation of kernel version 5.9
	Kernel5_9 = VersionCode(5, 9, 0) //nolint:deadcode,unused
	// Kernel5_10 is the KernelVersion representation of kernel version 5.10
	Kernel5_10 = VersionCode(5, 10, 0) //nolint:deadcode,unused
	// Kernel5_11 is the KernelVersion representation of kernel version 5.11
	Kernel5_11 = VersionCode(5, 11, 0) //nolint:deadcode,unused
	// Kernel5_12 is the KernelVersion representation of kernel version 5.12
	Kernel5_12 = VersionCode(5, 12, 0) //nolint:deadcode,unused
	// Kernel5_13 is the KernelVersion representation of kernel version 5.13
	Kernel5_13 = VersionCode(5, 13, 0) //nolint:deadcode,unused
	// Kernel5_14 is the KernelVersion representation of kernel version 5.14
	Kernel5_14 = VersionCode(5, 14, 0) //nolint:deadcode,unused
	// Kernel5_15 is the KernelVersion representation of kernel version 5.15
	Kernel5_15 = VersionCode(5, 15, 0) //nolint:deadcode,unused
	// Kernel5_16 is the KernelVersion representation of kernel version 5.16
	Kernel5_16 = VersionCode(5, 16, 0) //nolint:deadcode,unused
)

// Host defines a the kernel and OS of a host helper
type Host struct {
	OsRelease     map[string]string
	OsReleasePath string
	Code          Version
	UnameRelease  string

	haveMmapableMaps *bool
	haveRingBuffers  *bool
}

func (k *Host) String() string {
	return fmt.Sprintf("kernel %s - %v - %s", k.Code, k.OsRelease, k.UnameRelease)
}

var kernelVersionCache struct {
	sync.Mutex
	*Host
}

// NewHost returns a new kernel version helper
func NewHost() (*Host, error) {
	kernelVersionCache.Lock()
	defer kernelVersionCache.Unlock()

	if kernelVersionCache.Host != nil {
		return kernelVersionCache.Host, nil
	}

	var err error
	kernelVersionCache.Host, err = newHost()
	return kernelVersionCache.Host, err
}

func newHost() (*Host, error) {
	osReleasePaths := make([]string, 0, 2*3)

	// First look at os-release files based on the `HOST_ROOT` env variable
	if hostRoot := os.Getenv("HOST_ROOT"); hostRoot != "" {
		osReleasePaths = append(
			osReleasePaths,
			filepath.Join(hostRoot, osrelease.UsrLibOsRelease),
			filepath.Join(hostRoot, osrelease.EtcOsRelease),
		)
	}

	// Finally default to actual default values
	// This is last in the search order since we don't want os-release files
	// from the distribution of the container when deployed on a host with
	// different values
	osReleasePaths = append(
		osReleasePaths,
		osrelease.UsrLibOsRelease,
		osrelease.EtcOsRelease,
	)

	kv, err := HostVersion()
	if err != nil {
		return nil, fmt.Errorf("failed to detect kernel version: %w", err)
	}

	var uname unix.Utsname
	if err := unix.Uname(&uname); err != nil {
		return nil, fmt.Errorf("error calling uname: %w", err)
	}
	unameRelease := unix.ByteSliceToString(uname.Release[:])

	var release map[string]string
	for _, osReleasePath := range osReleasePaths {
		release, err = osrelease.ReadFile(osReleasePath)
		if err == nil {
			return &Host{
				OsRelease:     release,
				OsReleasePath: osReleasePath,
				Code:          kv,
				UnameRelease:  unameRelease,
			}, nil
		}
	}

	return nil, errors.New("failed to detect operating system version")
}

// IsDebianKernel returns whether the kernel is a debian kernel
func (k *Host) IsDebianKernel() bool {
	return k.OsRelease["ID"] == "debian"
}

// IsUbuntuKernel returns whether the kernel is an ubuntu kernel
func (k *Host) IsUbuntuKernel() bool {
	return k.OsRelease["ID"] == "ubuntu"
}

// UbuntuKernelVersion returns a parsed ubuntu kernel version or nil if not on ubuntu or if parsing failed
func (k *Host) UbuntuKernelVersion() *UbuntuKernelVersion {
	if k.OsRelease["ID"] != "ubuntu" {
		return nil
	}

	ukv, err := NewUbuntuKernelVersion(k.UnameRelease)
	if err != nil {
		return nil
	}
	return ukv
}

// IsRH7Kernel returns whether the kernel is a rh7 kernel
func (k *Host) IsRH7Kernel() bool {
	return (k.OsRelease["ID"] == "centos" || k.OsRelease["ID"] == "rhel") && k.OsRelease["VERSION_ID"] == "7"
}

// IsRH8Kernel returns whether the kernel is a rh8 kernel
func (k *Host) IsRH8Kernel() bool {
	return k.OsRelease["PLATFORM_ID"] == "platform:el8"
}

// IsSuseKernel returns whether the kernel is a suse kernel
func (k *Host) IsSuseKernel() bool {
	return k.IsSLESKernel() || k.OsRelease["ID"] == "opensuse-leap"
}

// IsSuse12Kernel returns whether the kernel is a sles 12 kernel
func (k *Host) IsSuse12Kernel() bool {
	return k.IsSuseKernel() && strings.HasPrefix(k.OsRelease["VERSION_ID"], "12")
}

// IsSuse15Kernel returns whether the kernel is a sles 15 kernel
func (k *Host) IsSuse15Kernel() bool {
	return k.IsSuseKernel() && strings.HasPrefix(k.OsRelease["VERSION_ID"], "15")
}

// IsSLESKernel returns whether the kernel is a sles kernel
func (k *Host) IsSLESKernel() bool {
	return k.OsRelease["ID"] == "sles"
}

// IsOracleUEKKernel returns whether the kernel is an oracle uek kernel
func (k *Host) IsOracleUEKKernel() bool {
	return k.OsRelease["ID"] == "ol" && k.Code >= Kernel5_4
}

// IsCOSKernel returns whether the kernel is a suse kernel
func (k *Host) IsCOSKernel() bool {
	return k.OsRelease["ID"] == "cos"
}

// IsAmazonLinuxKernel returns whether the kernel is an amazon kernel
func (k *Host) IsAmazonLinuxKernel() bool {
	return k.OsRelease["ID"] == "amzn"
}

// IsInRangeCloseOpen returns whether the kernel version is between the begin
// version (included) and the end version (excluded)
func (k *Host) IsInRangeCloseOpen(begin Version, end Version) bool {
	return k.Code != 0 && begin <= k.Code && k.Code < end
}

// HaveMmapableMaps returns whether the kernel supports mmapable maps.
func (k *Host) HaveMmapableMaps() bool {
	if k.haveMmapableMaps != nil {
		return *k.haveMmapableMaps
	}

	// This checks BPF_F_MMAPABLE, which appeared in 5.5 for array maps.
	m, err := sys.MapCreate(&sys.MapCreateAttr{
		MapType:    sys.MapType(ebpf.Array),
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 1,
		MapFlags:   unix.BPF_F_MMAPABLE,
	})
	k.haveMmapableMaps = new(bool)
	*k.haveMmapableMaps = err == nil

	if err != nil {
		return false
	}
	_ = m.Close()
	return true
}

// HaveRingBuffers returns whether the kernel supports ring buffer.
func (k *Host) HaveRingBuffers() bool {
	if k.haveRingBuffers != nil {
		return *k.haveRingBuffers
	}

	// This checks ring buffer maps, which appeared in 5.8
	err := features.HaveMapType(ebpf.RingBuf)
	k.haveRingBuffers = new(bool)
	*k.haveRingBuffers = err == nil

	return *k.haveRingBuffers
}
