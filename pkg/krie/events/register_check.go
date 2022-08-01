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

// RegisterCheckEvent represents a register_check event
type RegisterCheckEvent struct {
	StackPointer       MemoryPointer `json:"stack_pointer"`
	InstructionPointer MemoryPointer `json:"instruction_pointer"`
	FramePointer       MemoryPointer `json:"frame_pointer"`
	HookPoint          HookPoint     `json:"hook_point"`
}

// UnmarshallBinary unmarshalls a binary representation of itself
func (e *RegisterCheckEvent) UnmarshallBinary(data []byte) (int, error) {
	if len(data) < 28 {
		return 0, fmt.Errorf("while parsing RegisterCheckEvent, got len %d, needed %d: %w", len(data), 28, ErrNotEnoughData)
	}
	e.StackPointer = MemoryPointer(ByteOrder.Uint64(data[0:8]))
	e.InstructionPointer = MemoryPointer(ByteOrder.Uint64(data[8:16]))
	e.FramePointer = MemoryPointer(ByteOrder.Uint64(data[16:24]))
	e.HookPoint = HookPoint(ByteOrder.Uint32(data[24:28]))
	return 28, nil
}

// RegisterCheckEventSerializer is used to serialize RegisterCheckEvent
// easyjson:json
type RegisterCheckEventSerializer struct {
	*RegisterCheckEvent
}

// NewRegisterCheckEventSerializer returns a new instance of PtraceEventSerializer
func NewRegisterCheckEventSerializer(e *RegisterCheckEvent) *RegisterCheckEventSerializer {
	return &RegisterCheckEventSerializer{
		RegisterCheckEvent: e,
	}
}
