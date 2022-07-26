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
	"archive/tar"
	"bytes"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/DataDog/gopsutil/cpu"
	"github.com/smira/go-xz"
)

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

func createBTFReaderFromTarball(archivePath string) (io.ReaderAt, error) {
	archiveFile, err := os.Open(archivePath)
	if err != nil {
		return nil, err
	}

	xzReader, err := xz.NewReader(archiveFile)
	if err != nil {
		return nil, err
	}

	tarReader := tar.NewReader(xzReader)

	btfBuffer := bytes.NewBuffer([]byte{})
outer:
	for {
		hdr, err := tarReader.Next()
		if err == io.EOF {
			break // End of archive
		}
		if err != nil {
			return nil, fmt.Errorf("failed to read entry from tarball: %w", err)
		}

		switch hdr.Typeflag {
		case tar.TypeReg:
			if strings.HasSuffix(hdr.Name, ".btf") {
				if _, err := io.Copy(btfBuffer, tarReader); err != nil {
					return nil, fmt.Errorf("failed to uncompress file %s: %w", hdr.Name, err)
				}
				break outer
			}
		}
	}

	return bytes.NewReader(btfBuffer.Bytes()), nil
}

// Getpid returns the current process ID in the host namespace
func Getpid() int32 {
	// try to prevent pid namespace shenanigans (hoping the host /proc is mounted at /proc)
	p, err := os.Readlink("/proc/self")
	if err == nil {
		if pid, err := strconv.ParseInt(p, 10, 32); err == nil {
			return int32(pid)
		}
	}
	return int32(os.Getpid())
}
