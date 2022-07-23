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
	"bytes"
	"fmt"

	manager "github.com/DataDog/ebpf-manager"
)

// ModuleNameLen is the length of the name of a kernel module
const ModuleNameLen = 56

func addKernelModuleProbes(all *[]*manager.Probe) {
	// init_module
	*all = append(*all, []*manager.Probe{
		{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				UID:          KRIEUID,
				EBPFSection:  "kprobe/do_init_module",
				EBPFFuncName: "kprobe_do_init_module",
			},
		},
		{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				UID:          KRIEUID,
				EBPFSection:  "kprobe/module_put",
				EBPFFuncName: "kprobe_module_put",
			},
		},
	}...)
	*all = append(*all, ExpandSyscallProbes(&manager.Probe{
		ProbeIdentificationPair: manager.ProbeIdentificationPair{
			UID: KRIEUID,
		},
		SyscallFuncName: "init_module",
	}, EntryAndExit)...)
	*all = append(*all, ExpandSyscallProbes(&manager.Probe{
		ProbeIdentificationPair: manager.ProbeIdentificationPair{
			UID: KRIEUID,
		},
		SyscallFuncName: "finit_module",
	}, EntryAndExit)...)

	// delete_module
	*all = append(*all, ExpandSyscallProbes(&manager.Probe{
		ProbeIdentificationPair: manager.ProbeIdentificationPair{
			UID: KRIEUID,
		},
		SyscallFuncName: "delete_module",
	}, EntryAndExit)...)
}

func addKernelModuleTailCallRoutes(all *[]manager.TailCallRoute) {
	*all = append(*all, []manager.TailCallRoute{
		// init_module
		{
			ProgArrayName: "sys_exit_progs",
			Key:           uint32(InitModuleEventType),
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				EBPFSection:  "tracepoint/handle_sys_init_module_exit",
				EBPFFuncName: "tracepoint_handle_sys_init_module_exit",
			},
		},
		// delete_module
		{
			ProgArrayName: "sys_exit_progs",
			Key:           uint32(DeleteModuleEventType),
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				EBPFSection:  "tracepoint/handle_sys_delete_module_exit",
				EBPFFuncName: "tracepoint_handle_sys_delete_module_exit",
			},
		},
	}...)
}

func addAllKernelModuleProbesSelectors(all *[]manager.ProbesSelector) {
	*all = append(*all,
		// init_module
		&manager.ProbeSelector{ProbeIdentificationPair: manager.ProbeIdentificationPair{UID: KRIEUID, EBPFSection: "kprobe/module_put", EBPFFuncName: "kprobe_module_put"}},
		&manager.ProbeSelector{ProbeIdentificationPair: manager.ProbeIdentificationPair{UID: KRIEUID, EBPFSection: "kprobe/do_init_module", EBPFFuncName: "kprobe_do_init_module"}},
		&manager.OneOf{Selectors: ExpandSyscallProbesSelector(
			manager.ProbeIdentificationPair{UID: KRIEUID, EBPFSection: "init_module"}, EntryAndExit),
		},
		&manager.OneOf{Selectors: ExpandSyscallProbesSelector(
			manager.ProbeIdentificationPair{UID: KRIEUID, EBPFSection: "finit_module"}, EntryAndExit),
		},

		// delete_module
		&manager.OneOf{Selectors: ExpandSyscallProbesSelector(
			manager.ProbeIdentificationPair{UID: KRIEUID, EBPFSection: "delete_module"}, EntryAndExit),
		},
	)
}

// InitModuleEvent is used to parse an init_module event
type InitModuleEvent struct {
	LoadedFromMemory bool   `json:"loaded_from_memory"`
	Name             string `json:"name"`
}

// UnmarshallBinary unmarshalls a binary representation of itself
func (e *InitModuleEvent) UnmarshallBinary(data []byte) (int, error) {
	if len(data) < 8+ModuleNameLen {
		return 0, fmt.Errorf("while parsing InitModuleEvent, got len %d, needed %d: %w", len(data), 8+ModuleNameLen, ErrNotEnoughData)
	}

	if ByteOrder.Uint32(data[0:4]) == 1 {
		e.LoadedFromMemory = true
	}
	var err error
	e.Name, err = UnmarshalString(data[8:8+ModuleNameLen], ModuleNameLen)
	if err != nil {
		return 0, err
	}
	return 8 + ModuleNameLen, nil
}

// InitModuleEventSerializer is used to serialize InitModuleEvent
// easyjson:json
type InitModuleEventSerializer struct {
	*InitModuleEvent
}

// NewInitModuleSerializer returns a new instance of InitModuleEventSerializer
func NewInitModuleSerializer(im *InitModuleEvent) *InitModuleEventSerializer {
	return &InitModuleEventSerializer{
		InitModuleEvent: im,
	}
}

// DeleteModuleEvent is used to parse an delete_module event
type DeleteModuleEvent struct {
	Name string `json:"name"`
}

// UnmarshallBinary unmarshalls a binary representation of itself
func (dm *DeleteModuleEvent) UnmarshallBinary(data []byte) (int, error) {
	if len(data) < ModuleNameLen {
		return 0, fmt.Errorf("while parsing DeleteModuleEvent, got len %d, needed %d: %w", len(data), ModuleNameLen, ErrNotEnoughData)
	}
	dm.Name = string(bytes.Trim(data[0:ModuleNameLen], "\x00"))
	return ModuleNameLen, nil
}

// DeleteModuleEventSerializer is used to serialize DeleteModuleEvent
// easyjson:json
type DeleteModuleEventSerializer struct {
	*DeleteModuleEvent
}

// NewDeleteModuleSerializer returns a new instance of DeleteModuleEventSerializer
func NewDeleteModuleSerializer(dm *DeleteModuleEvent) *DeleteModuleEventSerializer {
	return &DeleteModuleEventSerializer{
		DeleteModuleEvent: dm,
	}
}
