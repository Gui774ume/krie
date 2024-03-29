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
	"bytes"
	"errors"
	"fmt"
	"strings"

	manager "github.com/DataDog/ebpf-manager"
	"golang.org/x/sys/unix"

	"github.com/Gui774ume/krie/pkg/kernel"
)

// RuntimeArch holds the CPU architecture of the running machine
var RuntimeArch string

func resolveRuntimeArch() {
	var uname unix.Utsname
	if err := unix.Uname(&uname); err != nil {
		panic(err)
	}

	switch string(uname.Machine[:bytes.IndexByte(uname.Machine[:], 0)]) {
	case "x86_64":
		RuntimeArch = "x64"
	case "aarch64":
		RuntimeArch = "arm64"
	default:
		RuntimeArch = "ia32"
	}
}

// currentHost represents the current host
var currentHost *kernel.Host

func resolveCurrentHost() error {
	var err error
	currentHost, err = kernel.NewHost()
	if err != nil {
		return errors.New("couldn't resolve kernel version")
	}
	return nil
}

// cache of the syscall prefix depending on kernel version
var syscallPrefix string
var ia32SyscallPrefix string

func getSyscallPrefix() string {
	if syscallPrefix == "" {
		syscall, err := manager.GetSyscallFnName("open")
		if err != nil {
			fmt.Errorf("couldn't find open syscall name: %w", err)
			return "__unknown__"
		}
		syscallPrefix = strings.ToLower(strings.TrimSuffix(syscall, "open"))
		if syscallPrefix != "sys_" {
			ia32SyscallPrefix = "__ia32_"
		} else {
			ia32SyscallPrefix = "compat_"
		}
	}

	return syscallPrefix
}

func getSyscallFnName(name string) string {
	return getSyscallPrefix() + name
}

func getIA32SyscallFnName(name string) string {
	return ia32SyscallPrefix + "sys_" + name
}

func getCompatSyscallFnName(name string) string {
	return ia32SyscallPrefix + "compat_sys_" + name
}

// ShouldUseSyscallExitTracepoints returns true if the kernel version is old and we need to use tracepoints to handle syscall exits
// instead of kretprobes
func ShouldUseSyscallExitTracepoints() uint64 {
	_ = resolveCurrentHost()
	if currentHost != nil && (currentHost.Code < kernel.Kernel4_12 || currentHost.IsRH7Kernel()) {
		return uint64(1)
	}
	return uint64(0)
}

// IsBPFSendSignalHelperAvailable returns true if the bpf_send_signal helper is available in the current kernel
func IsBPFSendSignalHelperAvailable() uint64 {
	_ = resolveCurrentHost()
	if currentHost != nil && (currentHost.Code >= kernel.Kernel5_3) {
		return uint64(1)
	}
	return uint64(0)
}

// IsBPFOverrideReturnAvailable returns true if the bpf_override_return helper is available in the current kernel
func IsBPFOverrideReturnAvailable() uint64 {
	_ = resolveCurrentHost()
	if currentHost != nil && (currentHost.Code >= kernel.Kernel4_16 || currentHost.IsRH7Kernel() || currentHost.IsRH8Kernel()) {
		return uint64(1)
	}
	return uint64(0)
}

// IsCgroupSysctlProgramAvailable returns true if the cgroup sysctl program type is available in the current kernel
func IsCgroupSysctlProgramAvailable() bool {
	_ = resolveCurrentHost()
	if currentHost != nil && (currentHost.Code >= kernel.Kernel5_2) {
		return true
	}
	return false
}

// HasOneMillionInstructionsAvailable returns true if the current kernel accepts programs with 1 million instructions
func HasOneMillionInstructionsAvailable() bool {
	_ = resolveCurrentHost()
	if currentHost != nil && (currentHost.Code >= kernel.Kernel5_3) {
		return true
	}
	return false
}

func IsBPFLSMAvailable() bool {
	_ = resolveCurrentHost()
	if currentHost != nil && (currentHost.Code >= kernel.Kernel5_7) {
		return true
	}
	return false
}

// GetCheckHelperCallInputType returns 1 or 2 defending on the prototype of the check_helper_call function in the current kernel
func GetCheckHelperCallInputType() uint64 {
	input := uint64(1)

	host, err := kernel.NewHost()
	if err == nil {
		if host.Code != 0 && host.Code >= kernel.Kernel5_14 {
			input = uint64(2)
		}
	}
	return input
}

func expandKprobe(hookpoint string, syscallName string, flag int) []string {
	var sections []string
	if flag&Entry == Entry {
		sections = append(sections, "kprobe/"+hookpoint)
	}
	if flag&Exit == Exit {
		if len(syscallName) == 0 || ShouldUseSyscallExitTracepoints() == uint64(0) {
			sections = append(sections, "kretprobe/"+hookpoint)
		}
	}
	return sections
}

func expandSyscallSections(syscallName string, flag int, compat ...bool) []string {
	sections := expandKprobe(getSyscallFnName(syscallName), syscallName, flag)

	if RuntimeArch == "x64" {
		if len(compat) > 0 && compat[0] && syscallPrefix != "sys_" {
			sections = append(sections, expandKprobe(getCompatSyscallFnName(syscallName), "", flag)...)
		} else {
			sections = append(sections, expandKprobe(getIA32SyscallFnName(syscallName), "", flag)...)
		}
	}

	return sections
}

const (
	// Entry indicates that the entry kprobe should be expanded
	Entry = 1 << 0
	// Exit indicates that the exit kretprobe should be expanded
	Exit = 1 << 1
	// ExpandTime32 indicates that the _time32 suffix should be added to the provided probe if needed
	ExpandTime32 = 1 << 2

	// EntryAndExit indicates that both the entry kprobe and exit kretprobe should be expanded
	EntryAndExit = Entry | Exit
)

// getFunctionNameFromSection returns the generated function name from the generated section
func getFunctionNameFromSection(section string) string {
	funcName := section
	if syscallPrefix == "sys_" {
		funcName = strings.ReplaceAll(funcName, "kprobe/", "kprobe__64_")
		funcName = strings.ReplaceAll(funcName, "kretprobe/", "kretprobe__64_")
	} else {
		// amd64
		funcName = strings.ReplaceAll(funcName, "__ia32_", "__32_")
		funcName = strings.ReplaceAll(funcName, "__x64_", "__64_")
		// arm
		funcName = strings.ReplaceAll(funcName, "__arm64_", "__64_")
		funcName = strings.ReplaceAll(funcName, "__arm32_", "__32_")
		// utils
		funcName = strings.ReplaceAll(funcName, "/_", "_")
	}
	funcName = strings.ReplaceAll(funcName, "tracepoint/syscalls/", "tracepoint_syscalls_")
	return funcName
}

// ExpandSyscallProbes returns the list of available hook probes for the syscall func name of the provided probe
func ExpandSyscallProbes(probe *manager.Probe, flag int, compat ...bool) []*manager.Probe {
	var probes []*manager.Probe
	syscallName := probe.SyscallFuncName
	probe.SyscallFuncName = ""

	if len(RuntimeArch) == 0 {
		resolveRuntimeArch()
	}

	if currentHost == nil {
		_ = resolveCurrentHost()
	}

	if flag&ExpandTime32 == ExpandTime32 {
		// check if _time32 should be expanded
		if getSyscallPrefix() == "sys_" {
			return probes
		}
		syscallName += "_time32"
	}

	for _, section := range expandSyscallSections(syscallName, flag, compat...) {
		probeCopy := probe.Copy()
		probeCopy.EBPFSection = section
		probeCopy.EBPFFuncName = getFunctionNameFromSection(section)
		probes = append(probes, probeCopy)
	}

	return probes
}

// ExpandSyscallProbesSelector returns the list of a ProbesSelector required to query all the probes available for a syscall
func ExpandSyscallProbesSelector(id manager.ProbeIdentificationPair, flag int, compat ...bool) []manager.ProbesSelector {
	var selectors []manager.ProbesSelector

	if len(RuntimeArch) == 0 {
		resolveRuntimeArch()
	}

	if currentHost == nil {
		_ = resolveCurrentHost()
	}

	if flag&ExpandTime32 == ExpandTime32 {
		// check if _time32 should be expanded
		if getSyscallPrefix() == "sys_" {
			return selectors
		}
		id.EBPFSection += "_time32"
	}

	for _, section := range expandSyscallSections(id.EBPFSection, flag, compat...) {
		selector := &manager.ProbeSelector{ProbeIdentificationPair: manager.ProbeIdentificationPair{UID: id.UID, EBPFSection: section, EBPFFuncName: getFunctionNameFromSection(section)}}
		selectors = append(selectors, selector)
	}

	return selectors
}
