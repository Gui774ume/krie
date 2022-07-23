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
	"encoding/json"
	"fmt"
)

const (
	CgroupNameLength = 72
	TaskCommLength   = 16
)

// CgroupContext is used to parse the cgroup context of an event
type CgroupContext struct {
	SubsystemID CgroupSubsystemID `json:"-"`
	ID          uint32            `json:"id"`
	Name        string            `json:"name,omitempty"`
}

// UnmarshalBinary unmarshalls a binary representation of itself
func (cc *CgroupContext) UnmarshalBinary(data []byte) (int, error) {
	if len(data) < 8+CgroupNameLength {
		return 0, fmt.Errorf("while parsing CgroupContext, got len %d, needed %d: %w", len(data), 8+CgroupNameLength, ErrNotEnoughData)
	}
	cc.SubsystemID = CgroupSubsystemID(ByteOrder.Uint32(data[0:4]))
	cc.ID = ByteOrder.Uint32(data[4:8])
	cc.Name = string(bytes.Trim(data[8:8+CgroupNameLength], "\x00"))
	return 8 + CgroupNameLength, nil
}

// CredentialsContext is used to parse the credentials context of an event
type CredentialsContext struct {
	UID            uint32 `json:"uid"`
	GID            uint32 `json:"gid"`
	SUID           uint32 `json:"suid"`
	SGID           uint32 `json:"sgid"`
	EUID           uint32 `json:"euid"`
	EGID           uint32 `json:"egid"`
	FSUID          uint32 `json:"fsuid"`
	FSGID          uint32 `json:"fsgid"`
	SecureBits     uint32 `json:"secure_bits"`
	CapInheritable uint64 `json:"cap_inheritable"`
	CapPermitted   uint64 `json:"cap_permitted"`
	CapEffective   uint64 `json:"cap_effective"`
	CapBSET        uint64 `json:"cap_bset"`
	CapAmbiant     uint64 `json:"cap_ambiant"`
}

// UnmarshalBinary unmarshalls a binary representation of itself
func (cc *CredentialsContext) UnmarshalBinary(data []byte) (int, error) {
	if len(data) < 80 {
		return 0, fmt.Errorf("while parsing CredentialsContext, got len %d, needed 80: %w", len(data), ErrNotEnoughData)
	}
	cc.UID = ByteOrder.Uint32(data[:4])
	cc.GID = ByteOrder.Uint32(data[4:8])
	cc.SUID = ByteOrder.Uint32(data[8:12])
	cc.SGID = ByteOrder.Uint32(data[12:16])
	cc.EUID = ByteOrder.Uint32(data[16:20])
	cc.EGID = ByteOrder.Uint32(data[20:24])
	cc.FSUID = ByteOrder.Uint32(data[24:28])
	cc.FSGID = ByteOrder.Uint32(data[28:32])
	cc.SecureBits = ByteOrder.Uint32(data[32:36])
	// padding
	cc.CapInheritable = ByteOrder.Uint64(data[40:48])
	cc.CapPermitted = ByteOrder.Uint64(data[48:56])
	cc.CapEffective = ByteOrder.Uint64(data[56:64])
	cc.CapBSET = ByteOrder.Uint64(data[64:72])
	cc.CapAmbiant = ByteOrder.Uint64(data[72:80])
	return 80, nil
}

// NamespaceContext is used to parse the namespace context of an event
type NamespaceContext struct {
	CgroupNamespace uint32 `json:"cgroup_namespace"`
	IPCNamespace    uint32 `json:"ipc_namespace"`
	NetNamespace    uint32 `json:"net_namespace"`
	MntNamespace    uint32 `json:"mnt_namespace"`
	PIDNamespace    uint32 `json:"pid_namespace"`
	TimeNamespace   uint32 `json:"time_namespace"`
	UserNamespace   uint32 `json:"user_namespace"`
	UTSNamespace    uint32 `json:"uts_namespace"`
}

// UnmarshalBinary unmarshalls a binary representation of itself
func (nc *NamespaceContext) UnmarshalBinary(data []byte) (int, error) {
	if len(data) < 32 {
		return 0, fmt.Errorf("while parsing NamespaceContext, got len %d, needed 32: %w", len(data), ErrNotEnoughData)
	}
	nc.CgroupNamespace = ByteOrder.Uint32(data[:4])
	nc.IPCNamespace = ByteOrder.Uint32(data[4:8])
	nc.NetNamespace = ByteOrder.Uint32(data[8:12])
	nc.MntNamespace = ByteOrder.Uint32(data[12:16])
	nc.PIDNamespace = ByteOrder.Uint32(data[16:20])
	nc.TimeNamespace = ByteOrder.Uint32(data[20:24])
	nc.UserNamespace = ByteOrder.Uint32(data[24:28])
	nc.UTSNamespace = ByteOrder.Uint32(data[28:32])
	return 32, nil
}

// Cgroups is used to wrap the CgroupContext and ease serialization
type Cgroups [CgroupSubsystemMax]CgroupContext

func (c Cgroups) MarshalJSON() ([]byte, error) {
	out := make(map[string]CgroupContext)
	for k, v := range c {
		out[CgroupSubsystemID(k).String()] = v
	}
	return json.Marshal(out)
}

// ProcessContext is used to parse the process context of an event
type ProcessContext struct {
	Cgroups          Cgroups            `json:"cgroups"`
	NamespaceContext NamespaceContext   `json:"namespace_context"`
	Credentials      CredentialsContext `json:"credentials"`
	Comm             string             `json:"comm"`
	PID              uint32             `json:"pid"`
	TID              uint32             `json:"tid"`
}

// UnmarshalBinary unmarshalls a binary representation of itself
func (pc *ProcessContext) UnmarshalBinary(data []byte) (int, error) {
	var cursor, read int
	var err error

	read, err = pc.NamespaceContext.UnmarshalBinary(data[cursor:])
	if err != nil {
		return 0, err
	}
	cursor += read

	read, err = pc.Credentials.UnmarshalBinary(data[cursor:])
	if err != nil {
		return 0, err
	}
	cursor += read

	if len(data[cursor:]) < TaskCommLength {
		return 0, fmt.Errorf("while parsing ProcessContext.Comm: got len %d, needed %d: %w", len(data[cursor:]), TaskCommLength, err)
	}
	pc.Comm = string(bytes.Trim(data[cursor:cursor+TaskCommLength], "\x00"))
	cursor += TaskCommLength

	for i := 0; i < int(CgroupSubsystemMax); i++ {
		read, err = pc.Cgroups[i].UnmarshalBinary(data[cursor:])
		if err != nil {
			return 0, err
		}
		cursor += read
	}

	if len(data[cursor:]) < 8 {
		return 0, fmt.Errorf("while parsing ProcessContext.PID: got len %d, needed %d: %w", len(data[cursor:]), 8, err)
	}
	pc.PID = ByteOrder.Uint32(data[cursor : cursor+4])
	pc.TID = ByteOrder.Uint32(data[cursor+4 : cursor+8])
	cursor += 8

	return cursor, nil
}

// ProcessContextSerializer is used to serialize ProcessContext
// easyjson:json
type ProcessContextSerializer struct {
	*ProcessContext
}

// NewProcessContextSerializer returns a new instance of ProcessContextSerializer
func NewProcessContextSerializer(pc *ProcessContext) *ProcessContextSerializer {
	return &ProcessContextSerializer{
		ProcessContext: pc,
	}
}
