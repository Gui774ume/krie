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

package events

import "fmt"

// CgroupSubsystemID is used to parse a cgroup subsystem ID
type CgroupSubsystemID uint32

const (
	CgroupSubsystemCPUSet CgroupSubsystemID = iota
	CgroupSubsystemCPU
	CgroupSubsystemCPUAcct
	CgroupSubsystemIO
	CgroupSubsystemMemory
	CgroupSubsystemDevices
	CgroupSubsystemFreezer
	CgroupSubsystemNetCLS
	CgroupSubsystemPerfEvent
	CgroupSubsystemNetPrio
	CgroupSubsystemHugeTLB
	CgroupSubsystemPIDs
	CgroupSubsystemRDMA
	CgroupSubsystemMisc
	CgroupSubsystemMax
)

func (id CgroupSubsystemID) String() string {
	switch id {
	case CgroupSubsystemCPUSet:
		return "cpuset"
	case CgroupSubsystemCPU:
		return "cpu"
	case CgroupSubsystemCPUAcct:
		return "cpuacct"
	case CgroupSubsystemIO:
		return "io"
	case CgroupSubsystemMemory:
		return "memory"
	case CgroupSubsystemDevices:
		return "devices"
	case CgroupSubsystemFreezer:
		return "freezer"
	case CgroupSubsystemNetCLS:
		return "net_cls"
	case CgroupSubsystemPerfEvent:
		return "perf_event"
	case CgroupSubsystemNetPrio:
		return "net_prio"
	case CgroupSubsystemHugeTLB:
		return "hugetlb"
	case CgroupSubsystemPIDs:
		return "pids"
	case CgroupSubsystemRDMA:
		return "rdma"
	case CgroupSubsystemMisc:
		return "misc"
	default:
		return fmt.Sprintf("CgroupSubsystem(%d)", id)
	}
}

func (id CgroupSubsystemID) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf("\"%s\"", id.String())), nil
}
