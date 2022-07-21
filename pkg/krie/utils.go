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

import "github.com/DataDog/gopsutil/cpu"

// NumCPU returns the count of CPUs in the CPU affinity mask of the pid 1 process
func NumCPU() (int, error) {
	cpuInfos, err := cpu.Info()
	if err != nil {
		return 0, err
	}
	var count int32
	for _, inf := range cpuInfos {
		count += inf.Cores
	}
	return int(count), nil
}
