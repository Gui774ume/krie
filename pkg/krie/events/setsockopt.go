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

//go:generate go run github.com/mailru/easyjson/easyjson -no_std_marshalers $GOFILE

package events

import (
	manager "github.com/DataDog/ebpf-manager"
)

func addSetSockOptProbes(all *[]*manager.Probe) {
	*all = append(*all, []*manager.Probe{
		{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				UID:          KRIEUID,
				EBPFSection:  "kprobe/sk_attach_filter",
				EBPFFuncName: "kprobe_sk_attach_filter",
			},
		},
		{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				UID:          KRIEUID,
				EBPFSection:  "kprobe/sk_detach_filter",
				EBPFFuncName: "kprobe_sk_detach_filter",
			},
		},
	}...)
	*all = append(*all, ExpandSyscallProbes(&manager.Probe{
		ProbeIdentificationPair: manager.ProbeIdentificationPair{
			UID: KRIEUID,
		},
		SyscallFuncName: "setsockopt",
	}, EntryAndExit)...)
}

func addSetSockOptRoutes(all *[]manager.TailCallRoute) {
	*all = append(*all, []manager.TailCallRoute{
		{
			ProgArrayName: "sys_exit_progs",
			Key:           uint32(BPFFilterEventType),
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				EBPFSection:  "tracepoint/handle_sys_setsockopt_exit",
				EBPFFuncName: "tracepoint_handle_sys_setsockopt_exit",
			},
		},
	}...)
}

func addSetSockOptSelectors(all *[]manager.ProbesSelector) {
	*all = append(*all,
		&manager.ProbeSelector{ProbeIdentificationPair: manager.ProbeIdentificationPair{UID: KRIEUID, EBPFSection: "kprobe/sk_attach_filter", EBPFFuncName: "kprobe_sk_attach_filter"}},
		&manager.ProbeSelector{ProbeIdentificationPair: manager.ProbeIdentificationPair{UID: KRIEUID, EBPFSection: "kprobe/sk_detach_filter", EBPFFuncName: "kprobe_sk_detach_filter"}},
		&manager.OneOf{Selectors: ExpandSyscallProbesSelector(
			manager.ProbeIdentificationPair{UID: KRIEUID, EBPFSection: "setsockopt"}, EntryAndExit),
		},
	)
}
