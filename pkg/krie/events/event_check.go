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

// EventCheckEvent represents a event_check event
type EventCheckEvent struct {
	CheckedEventType EventType `json:"checked_event_type"`
}

// UnmarshallBinary unmarshalls a binary representation of itself
func (e *EventCheckEvent) UnmarshallBinary(data []byte) (int, error) {
	if len(data) < 4 {
		return 0, fmt.Errorf("while parsing EventCheckEvent, got len %d, needed %d: %w", len(data), 4, ErrNotEnoughData)
	}
	e.CheckedEventType = EventType(ByteOrder.Uint32(data[0:4]))
	return 4, nil
}

// EventCheckEventSerializer is used to serialize EventCheckEvent
// easyjson:json
type EventCheckEventSerializer struct {
	*EventCheckEvent
}

// NewEventCheckEventSerializer returns a new instance of PtraceEventSerializer
func NewEventCheckEventSerializer(e *EventCheckEvent) *EventCheckEventSerializer {
	return &EventCheckEventSerializer{
		EventCheckEvent: e,
	}
}
