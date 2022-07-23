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
	"fmt"

	manager "github.com/DataDog/ebpf-manager"
)

func addPTraceProbes(all *[]*manager.Probe) {
	*all = append(*all, ExpandSyscallProbes(&manager.Probe{
		ProbeIdentificationPair: manager.ProbeIdentificationPair{
			UID: KRIEUID,
		},
		SyscallFuncName: "ptrace",
	}, EntryAndExit)...)
}

func addPTraceRoutes(all *[]manager.TailCallRoute) {
	*all = append(*all, []manager.TailCallRoute{
		{
			ProgArrayName: "sys_exit_progs",
			Key:           uint32(PTraceEventType),
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				EBPFSection:  "tracepoint/handle_sys_ptrace_exit",
				EBPFFuncName: "tracepoint_handle_sys_ptrace_exit",
			},
		},
	}...)
}

func addPTraceSelectors(all *[]manager.ProbesSelector) {
	*all = append(*all,
		&manager.OneOf{Selectors: ExpandSyscallProbesSelector(
			manager.ProbeIdentificationPair{UID: KRIEUID, EBPFSection: "ptrace"}, EntryAndExit),
		},
	)
}

// PTraceEvent represents a ptrace event
type PTraceEvent struct {
	Address MemoryPointer `json:"address,omitempty"`
	Request PTraceRequest `json:"request"`
	PID     uint32        `json:"pid,omitempty"`
}

// UnmarshallBinary unmarshalls a binary representation of itself
func (e *PTraceEvent) UnmarshallBinary(data []byte) (int, error) {
	if len(data) < 16 {
		return 0, fmt.Errorf("while parsing PtraceEvent, got len %d, needed %d: %w", len(data), 16, ErrNotEnoughData)
	}
	e.Address = MemoryPointer(ByteOrder.Uint64(data[0:8]))
	e.Request = PTraceRequest(ByteOrder.Uint32(data[8:12]))
	e.PID = ByteOrder.Uint32(data[12:16])
	return 16, nil
}

// PtraceEventSerializer is used to serialize PTraceEvent
// easyjson:json
type PtraceEventSerializer struct {
	*PTraceEvent
}

// NewPtraceEventSerializer returns a new instance of PtraceEventSerializer
func NewPtraceEventSerializer(e *PTraceEvent) *PtraceEventSerializer {
	return &PtraceEventSerializer{
		PTraceEvent: e,
	}
}
