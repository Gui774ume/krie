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
)

// KernelSymbol is used to identify a kernel syscall handler
type KernelSymbol struct {
	Address MemoryPointer `json:"address,omitempty"`
	Symbol  string        `json:"symbol,omitempty"`
	Module  string        `json:"module,omitempty"`
}

// HookedSyscallEvent represents a hooked_syscall or hooked_syscall_table event
type HookedSyscallEvent struct {
	Syscall      *Syscall     `json:"syscall,omitempty"`
	IA32Syscall  *IA32Syscall `json:"ia_32_syscall,omitempty"`
	SyscallTable SyscallTable `json:"syscall_table"`

	InitialHandler KernelSymbol `json:"initial_handler"`
	NewHandler     KernelSymbol `json:"new_handler"`
}

// UnmarshallBinary unmarshalls a binary representation of itself
func (e *HookedSyscallEvent) UnmarshallBinary(data []byte) (int, error) {
	if len(data) < 24 {
		return 0, fmt.Errorf("while parsing HookedSyscallEvent, got len %d, needed %d: %w", len(data), 24, ErrNotEnoughData)
	}
	e.SyscallTable = SyscallTable(ByteOrder.Uint32(data[4:8]))
	switch e.SyscallTable {
	case IA32SysCallTable:
		e.Syscall = nil
		e.IA32Syscall = new(IA32Syscall)
		*e.IA32Syscall = IA32Syscall(ByteOrder.Uint32(data[0:4]))
	default:
		e.Syscall = new(Syscall)
		e.IA32Syscall = nil
		*e.Syscall = Syscall(ByteOrder.Uint32(data[0:4]))
	}

	e.InitialHandler.Address = MemoryPointer(ByteOrder.Uint64(data[8:16]))
	e.NewHandler.Address = MemoryPointer(ByteOrder.Uint64(data[16:24]))

	return 4, nil
}

// HookedSyscallEventSerializer is used to serialize HookedSyscallEvent
// easyjson:json
type HookedSyscallEventSerializer struct {
	*HookedSyscallEvent
}

// NewHookedSyscallEventSerializer returns a new instance of HookedSyscallEventSerializer
func NewHookedSyscallEventSerializer(e *HookedSyscallEvent) *HookedSyscallEventSerializer {
	return &HookedSyscallEventSerializer{
		HookedSyscallEvent: e,
	}
}
