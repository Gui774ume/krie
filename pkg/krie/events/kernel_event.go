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

import "time"

// KernelEvent represents the default kernel event context
type KernelEvent struct {
	Time   time.Time `json:"time"`
	Retval int64     `json:"retval"`
	CPU    uint32    `json:"cpu"`
	Type   EventType `json:"type"`
	Action Action    `json:"action"`
}

// UnmarshalBinary unmarshalls a binary representation of itself
func (ke *KernelEvent) UnmarshalBinary(data []byte, resolver *TimeResolver) (int, error) {
	if len(data) < 32 {
		return 0, ErrNotEnoughData
	}
	ke.Time = resolver.ResolveMonotonicTimestamp(ByteOrder.Uint64(data[0:8]))
	ke.Retval = int64(ByteOrder.Uint64(data[8:16]))
	ke.CPU = ByteOrder.Uint32(data[16:20])
	ke.Type = EventType(ByteOrder.Uint32(data[20:24]))
	ke.Action = Action(ByteOrder.Uint32(data[24:28]))
	// padding 4 bytes
	return 32, nil
}

// KernelEventSerializer is used to serialize KernelEvent
// easyjson:json
type KernelEventSerializer struct {
	*KernelEvent
}

// NewKernelEventSerializer returns a new instance of KernelEventSerializer
func NewKernelEventSerializer(ke *KernelEvent) *KernelEventSerializer {
	return &KernelEventSerializer{
		KernelEvent: ke,
	}
}
