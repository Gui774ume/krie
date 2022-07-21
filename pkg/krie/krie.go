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
	"time"

	manager "github.com/DataDog/ebpf-manager"
)

// KRIE is the main KRIE structure
type KRIE struct {
	handleEvent    func(data []byte)
	options        Options
	manager        *manager.Manager
	managerOptions manager.Options
	startTime      time.Time

	timeResolver *TimeResolver
	numCPU       int
}

// NewKRIE creates a new KRIE instance
func NewKRIE(options Options) (*KRIE, error) {
	var err error

	if err = options.IsValid(); err != nil {
		return nil, err
	}

	e := &KRIE{
		options:     options,
		handleEvent: options.EventHandler,
	}
	if e.handleEvent == nil {
		e.handleEvent = e.defaultEventHandler
	}

	e.timeResolver, err = NewTimeResolver()
	if err != nil {
		return nil, err
	}

	e.numCPU, err = NumCPU()
	if err != nil {
		return nil, err
	}
	return e, nil
}

// Start hooks on the requested symbols and begins tracing
func (e *KRIE) Start() error {
	if err := e.startManager(); err != nil {
		return err
	}
	return nil
}

// Stop shuts down KRIE
func (e *KRIE) Stop() error {
	if e.manager == nil {
		// nothing to stop, return
		return nil
	}
	if err := e.manager.Stop(manager.CleanAll); err != nil {
		return fmt.Errorf("couldn't stop manager: %w", err)
	}
	return nil
}

func (e *KRIE) pushFilters() error {
	return nil
}

func (e *KRIE) defaultEventHandler(data []byte) {
}
