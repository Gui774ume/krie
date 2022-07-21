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

package krie

import (
	"bytes"
	"fmt"
	"math"
	"strings"
	"time"

	manager "github.com/DataDog/ebpf-manager"
	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"

	"github.com/Gui774ume/krie/pkg/assets"
)

// KRIEUID is the UID used to uniquely identify kernel space programs
const KRIEUID = "krie"

func (e *KRIE) startManager() error {
	// fetch ebpf assets
	asset, err := e.fetchAssets()
	if err != nil {
		return err
	}

	// setup a default manager
	e.prepareManager()

	// initialize the manager
	if err = e.manager.InitWithOptions(asset, e.managerOptions); err != nil {
		return fmt.Errorf("couldn't init manager: %w", err)
	}

	// select kernel space maps
	if err = e.selectMaps(); err != nil {
		return err
	}

	// start the manager
	if err = e.manager.Start(); err != nil {
		return fmt.Errorf("couldn't start manager: %w", err)
	}

	e.startTime = time.Now()
	return nil
}

func (e *KRIE) loadAsset(name string) (*bytes.Reader, error) {
	buf, err := assets.Asset(name)
	if err != nil {
		return nil, fmt.Errorf("couldn't find load asset %s: %w", name, err)
	}
	return bytes.NewReader(buf), nil
}

func (e *KRIE) fetchAssets() (*bytes.Reader, error) {
	openSyscall, err := manager.GetSyscallFnName("open")
	if err != nil {
		return nil, fmt.Errorf("couldn't determine which asset to use: %w", err)
	}

	if !strings.HasPrefix(openSyscall, "SyS_") && !strings.HasPrefix(openSyscall, "sys_") {
		return e.loadAsset("/probe_syscall_wrapper.o")
	}
	return e.loadAsset("/probe.o")
}

func (e *KRIE) prepareManager() {
	e.managerOptions = manager.Options{
		// DefaultKProbeMaxActive is the maximum number of active kretprobe at a given time
		DefaultKProbeMaxActive: 512,

		VerifierOptions: ebpf.CollectionOptions{
			Programs: ebpf.ProgramOptions{
				// LogSize is the size of the log buffer given to the verifier. Give it a big enough (2 * 1024 * 1024)
				// value so that all our programs fit. If the verifier ever outputs a `no space left on device` error,
				// we'll need to increase this value.
				LogSize: 2097152,
			},
		},

		// Extend RLIMIT_MEMLOCK (8) size
		// On some systems, the default for RLIMIT_MEMLOCK may be as low as 64 bytes.
		// This will result in an EPERM (Operation not permitted) error, when trying to create an eBPF map
		// using bpf(2) with BPF_MAP_CREATE.
		//
		// We are setting the limit to infinity until we have a better handle on the true requirements.
		RLimit: &unix.Rlimit{
			Cur: math.MaxUint64,
			Max: math.MaxUint64,
		},

		TailCallRouter: []manager.TailCallRoute{
			{
				ProgArrayName: "sys_exit_progs",
				Key:           uint32(1),
				ProbeIdentificationPair: manager.ProbeIdentificationPair{
					EBPFSection:  "tracepoint/handle_sys_mkdir_exit",
					EBPFFuncName: "tracepoint_handle_sys_mkdir_exit",
				},
			},
		},

		ConstantEditors: []manager.ConstantEditor{
			{
				Name:  "raw_syscall_tracepoint_fallback",
				Value: uint64(1),
			},
		},
	}
	e.prepareProbes()
	e.prepareProbeSelectors()
}

func (e *KRIE) selectMaps() error {
	return nil
}

func (e *KRIE) prepareProbes() {
	e.manager = &manager.Manager{
		Probes: []*manager.Probe{
			{
				ProbeIdentificationPair: manager.ProbeIdentificationPair{
					UID:          KRIEUID,
					EBPFSection:  "kprobe/vfs_mkdir",
					EBPFFuncName: "kprobe_vfs_mkdir",
				},
			},
			{
				ProbeIdentificationPair: manager.ProbeIdentificationPair{
					UID:          KRIEUID,
					EBPFSection:  "tracepoint/raw_syscalls/sys_exit",
					EBPFFuncName: "sys_exit",
				},
			},
		},
	}

	e.manager.Probes = append(e.manager.Probes, ExpandSyscallProbes(&manager.Probe{
		ProbeIdentificationPair: manager.ProbeIdentificationPair{
			UID: KRIEUID,
		},
		SyscallFuncName: "mkdir",
	}, EntryAndExit)...)
}

func (e *KRIE) prepareProbeSelectors() {
	e.managerOptions.ActivatedProbes = []manager.ProbesSelector{
		&manager.AllOf{
			Selectors: []manager.ProbesSelector{
				&manager.ProbeSelector{ProbeIdentificationPair: manager.ProbeIdentificationPair{UID: KRIEUID, EBPFSection: "tracepoint/raw_syscalls/sys_exit", EBPFFuncName: "sys_exit"}},
				&manager.ProbeSelector{ProbeIdentificationPair: manager.ProbeIdentificationPair{UID: KRIEUID, EBPFSection: "kprobe/vfs_mkdir", EBPFFuncName: "kprobe_vfs_mkdir"}},
				&manager.OneOf{Selectors: ExpandSyscallProbesSelector(
					manager.ProbeIdentificationPair{UID: KRIEUID, EBPFSection: "mkdir"}, EntryAndExit),
				},
			},
		},
	}
}
