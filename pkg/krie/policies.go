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
	"fmt"
)

func (e *KRIE) loadPolicies() error {
	// load parameters
	for eventType, action := range e.options.Events.ParseEventsActions() {
		if err := e.policiesMap.Put(eventType, action); err != nil {
			return fmt.Errorf("failed to push \"%s\" policy for \"%s\": %w", action.String(), eventType.String(), err)
		}
	}
	return nil
}
