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

//go:generate go run golang.org/x/tools/cmd/stringer -type Syscall -output syscalls_string_linux.go

package krie

import (
	"strings"

	"github.com/pkg/errors"
)

var (
	ErrNotEnoughData = errors.New("not enough data")
)

// Syscall represents a syscall identifier
type Syscall int

func (i Syscall) MarshalBinary() ([]byte, error) {
	rawSyscall := make([]byte, 4)
	ByteOrder.PutUint32(rawSyscall[:], uint32(i))
	return rawSyscall, nil
}

func (i *Syscall) UnmarshalSyscall(data []byte) (int, error) {
	if len(data) < 4 {
		return 0, errors.Wrapf(ErrNotEnoughData, "parsing Syscall: got len %d, needed 4", len(data))
	}
	*i = Syscall(int(ByteOrder.Uint32(data[:4])))
	return 4, nil
}

func (i *Syscall) UnmarshalBinary(data []byte) error {
	_, err := i.UnmarshalSyscall(data)
	return err
}

// Linux syscall identifiers
const (
	SysRead                  Syscall = 0
	SysWrite                 Syscall = 1
	SysOpen                  Syscall = 2
	SysClose                 Syscall = 3
	SysStat                  Syscall = 4
	SysFstat                 Syscall = 5
	SysLstat                 Syscall = 6
	SysPoll                  Syscall = 7
	SysLseek                 Syscall = 8
	SysMmap                  Syscall = 9
	SysMprotect              Syscall = 10
	SysMunmap                Syscall = 11
	SysBrk                   Syscall = 12
	SysRtSigaction           Syscall = 13
	SysRtSigprocmask         Syscall = 14
	SysRtSigreturn           Syscall = 15
	SysIoctl                 Syscall = 16
	SysPread64               Syscall = 17
	SysPwrite64              Syscall = 18
	SysReadv                 Syscall = 19
	SysWritev                Syscall = 20
	SysAccess                Syscall = 21
	SysPipe                  Syscall = 22
	SysSelect                Syscall = 23
	SysSchedYield            Syscall = 24
	SysMremap                Syscall = 25
	SysMsync                 Syscall = 26
	SysMincore               Syscall = 27
	SysMadvise               Syscall = 28
	SysShmget                Syscall = 29
	SysShmat                 Syscall = 30
	SysShmctl                Syscall = 31
	SysDup                   Syscall = 32
	SysDup2                  Syscall = 33
	SysPause                 Syscall = 34
	SysNanosleep             Syscall = 35
	SysGetitimer             Syscall = 36
	SysAlarm                 Syscall = 37
	SysSetitimer             Syscall = 38
	SysGetpid                Syscall = 39
	SysSendfile              Syscall = 40
	SysSocket                Syscall = 41
	SysConnect               Syscall = 42
	SysAccept                Syscall = 43
	SysSendto                Syscall = 44
	SysRecvfrom              Syscall = 45
	SysSendmsg               Syscall = 46
	SysRecvmsg               Syscall = 47
	SysShutdown              Syscall = 48
	SysBind                  Syscall = 49
	SysListen                Syscall = 50
	SysGetsockname           Syscall = 51
	SysGetpeername           Syscall = 52
	SysSocketpair            Syscall = 53
	SysSetsockopt            Syscall = 54
	SysGetsockopt            Syscall = 55
	SysClone                 Syscall = 56
	SysFork                  Syscall = 57
	SysVfork                 Syscall = 58
	SysExecve                Syscall = 59
	SysExit                  Syscall = 60
	SysWait4                 Syscall = 61
	SysKill                  Syscall = 62
	SysUname                 Syscall = 63
	SysSemget                Syscall = 64
	SysSemop                 Syscall = 65
	SysSemctl                Syscall = 66
	SysShmdt                 Syscall = 67
	SysMsgget                Syscall = 68
	SysMsgsnd                Syscall = 69
	SysMsgrcv                Syscall = 70
	SysMsgctl                Syscall = 71
	SysFcntl                 Syscall = 72
	SysFlock                 Syscall = 73
	SysFsync                 Syscall = 74
	SysFdatasync             Syscall = 75
	SysTruncate              Syscall = 76
	SysFtruncate             Syscall = 77
	SysGetdents              Syscall = 78
	SysGetcwd                Syscall = 79
	SysChdir                 Syscall = 80
	SysFchdir                Syscall = 81
	SysRename                Syscall = 82
	SysMkdir                 Syscall = 83
	SysRmdir                 Syscall = 84
	SysCreat                 Syscall = 85
	SysLink                  Syscall = 86
	SysUnlink                Syscall = 87
	SysSymlink               Syscall = 88
	SysReadlink              Syscall = 89
	SysChmod                 Syscall = 90
	SysFchmod                Syscall = 91
	SysChown                 Syscall = 92
	SysFchown                Syscall = 93
	SysLchown                Syscall = 94
	SysUmask                 Syscall = 95
	SysGettimeofday          Syscall = 96
	SysGetrlimit             Syscall = 97
	SysGetrusage             Syscall = 98
	SysSysinfo               Syscall = 99
	SysTimes                 Syscall = 100
	SysPtrace                Syscall = 101
	SysGetuid                Syscall = 102
	SysSyslog                Syscall = 103
	SysGetgid                Syscall = 104
	SysSetuid                Syscall = 105
	SysSetgid                Syscall = 106
	SysGeteuid               Syscall = 107
	SysGetegid               Syscall = 108
	SysSetpgid               Syscall = 109
	SysGetppid               Syscall = 110
	SysGetpgrp               Syscall = 111
	SysSetsid                Syscall = 112
	SysSetreuid              Syscall = 113
	SysSetregid              Syscall = 114
	SysGetgroups             Syscall = 115
	SysSetgroups             Syscall = 116
	SysSetresuid             Syscall = 117
	SysGetresuid             Syscall = 118
	SysSetresgid             Syscall = 119
	SysGetresgid             Syscall = 120
	SysGetpgid               Syscall = 121
	SysSetfsuid              Syscall = 122
	SysSetfsgid              Syscall = 123
	SysGetsid                Syscall = 124
	SysCapget                Syscall = 125
	SysCapset                Syscall = 126
	SysRtSigpending          Syscall = 127
	SysRtSigtimedwait        Syscall = 128
	SysRtSigqueueinfo        Syscall = 129
	SysRtSigsuspend          Syscall = 130
	SysSigaltstack           Syscall = 131
	SysUtime                 Syscall = 132
	SysMknod                 Syscall = 133
	SysUselib                Syscall = 134
	SysPersonality           Syscall = 135
	SysUstat                 Syscall = 136
	SysStatfs                Syscall = 137
	SysFstatfs               Syscall = 138
	SysSysfs                 Syscall = 139
	SysGetpriority           Syscall = 140
	SysSetpriority           Syscall = 141
	SysSchedSetparam         Syscall = 142
	SysSchedGetparam         Syscall = 143
	SysSchedSetscheduler     Syscall = 144
	SysSchedGetscheduler     Syscall = 145
	SysSchedGetPriorityMax   Syscall = 146
	SysSchedGetPriorityMin   Syscall = 147
	SysSchedRrGetInterval    Syscall = 148
	SysMlock                 Syscall = 149
	SysMunlock               Syscall = 150
	SysMlockall              Syscall = 151
	SysMunlockall            Syscall = 152
	SysVhangup               Syscall = 153
	SysModifyLdt             Syscall = 154
	SysPivotRoot             Syscall = 155
	SysSysctl                Syscall = 156
	SysPrctl                 Syscall = 157
	SysArchPrctl             Syscall = 158
	SysAdjtimex              Syscall = 159
	SysSetrlimit             Syscall = 160
	SysChroot                Syscall = 161
	SysSync                  Syscall = 162
	SysAcct                  Syscall = 163
	SysSettimeofday          Syscall = 164
	SysMount                 Syscall = 165
	SysUmount2               Syscall = 166
	SysSwapon                Syscall = 167
	SysSwapoff               Syscall = 168
	SysReboot                Syscall = 169
	SysSethostname           Syscall = 170
	SysSetdomainname         Syscall = 171
	SysIopl                  Syscall = 172
	SysIoperm                Syscall = 173
	SysCreateModule          Syscall = 174
	SysInitModule            Syscall = 175
	SysDeleteModule          Syscall = 176
	SysGetKernelSyms         Syscall = 177
	SysQueryModule           Syscall = 178
	SysQuotactl              Syscall = 179
	SysNfsservctl            Syscall = 180
	SysGetpmsg               Syscall = 181
	SysPutpmsg               Syscall = 182
	SysAfsSyscall            Syscall = 183
	SysTuxcall               Syscall = 184
	SysSecurity              Syscall = 185
	SysGettid                Syscall = 186
	SysReadahead             Syscall = 187
	SysSetxattr              Syscall = 188
	SysLsetxattr             Syscall = 189
	SysFsetxattr             Syscall = 190
	SysGetxattr              Syscall = 191
	SysLgetxattr             Syscall = 192
	SysFgetxattr             Syscall = 193
	SysListxattr             Syscall = 194
	SysLlistxattr            Syscall = 195
	SysFlistxattr            Syscall = 196
	SysRemovexattr           Syscall = 197
	SysLremovexattr          Syscall = 198
	SysFremovexattr          Syscall = 199
	SysTkill                 Syscall = 200
	SysTime                  Syscall = 201
	SysFutex                 Syscall = 202
	SysSchedSetaffinity      Syscall = 203
	SysSchedGetaffinity      Syscall = 204
	SysSetThreadArea         Syscall = 205
	SysIoSetup               Syscall = 206
	SysIoDestroy             Syscall = 207
	SysIoGetevents           Syscall = 208
	SysIoSubmit              Syscall = 209
	SysIoCancel              Syscall = 210
	SysGetThreadArea         Syscall = 211
	SysLookupDcookie         Syscall = 212
	SysEpollCreate           Syscall = 213
	SysEpollCtlOld           Syscall = 214
	SysEpollWaitOld          Syscall = 215
	SysRemapFilePages        Syscall = 216
	SysGetdents64            Syscall = 217
	SysSetTidAddress         Syscall = 218
	SysRestartSyscall        Syscall = 219
	SysSemtimedop            Syscall = 220
	SysFadvise64             Syscall = 221
	SysTimerCreate           Syscall = 222
	SysTimerSettime          Syscall = 223
	SysTimerGettime          Syscall = 224
	SysTimerGetoverrun       Syscall = 225
	SysTimerDelete           Syscall = 226
	SysClockSettime          Syscall = 227
	SysClockGettime          Syscall = 228
	SysClockGetres           Syscall = 229
	SysClockNanosleep        Syscall = 230
	SysExitGroup             Syscall = 231
	SysEpollWait             Syscall = 232
	SysEpollCtl              Syscall = 233
	SysTgkill                Syscall = 234
	SysUtimes                Syscall = 235
	SysVserver               Syscall = 236
	SysMbind                 Syscall = 237
	SysSetMempolicy          Syscall = 238
	SysGetMempolicy          Syscall = 239
	SysMqOpen                Syscall = 240
	SysMqUnlink              Syscall = 241
	SysMqTimedsend           Syscall = 242
	SysMqTimedreceive        Syscall = 243
	SysMqNotify              Syscall = 244
	SysMqGetsetattr          Syscall = 245
	SysKexecLoad             Syscall = 246
	SysWaitid                Syscall = 247
	SysAddKey                Syscall = 248
	SysRequestKey            Syscall = 249
	SysKeyctl                Syscall = 250
	SysIoprioSet             Syscall = 251
	SysIoprioGet             Syscall = 252
	SysInotifyInit           Syscall = 253
	SysInotifyAddWatch       Syscall = 254
	SysInotifyRmWatch        Syscall = 255
	SysMigratePages          Syscall = 256
	SysOpenat                Syscall = 257
	SysMkdirat               Syscall = 258
	SysMknodat               Syscall = 259
	SysFchownat              Syscall = 260
	SysFutimesat             Syscall = 261
	SysNewfstatat            Syscall = 262
	SysUnlinkat              Syscall = 263
	SysRenameat              Syscall = 264
	SysLinkat                Syscall = 265
	SysSymlinkat             Syscall = 266
	SysReadlinkat            Syscall = 267
	SysFchmodat              Syscall = 268
	SysFaccessat             Syscall = 269
	SysPselect6              Syscall = 270
	SysPpoll                 Syscall = 271
	SysUnshare               Syscall = 272
	SysSetRobustList         Syscall = 273
	SysGetRobustList         Syscall = 274
	SysSplice                Syscall = 275
	SysTee                   Syscall = 276
	SysSyncFileRange         Syscall = 277
	SysVmsplice              Syscall = 278
	SysMovePages             Syscall = 279
	SysUtimensat             Syscall = 280
	SysEpollPwait            Syscall = 281
	SysSignalfd              Syscall = 282
	SysTimerfdCreate         Syscall = 283
	SysEventfd               Syscall = 284
	SysFallocate             Syscall = 285
	SysTimerfdSettime        Syscall = 286
	SysTimerfdGettime        Syscall = 287
	SysAccept4               Syscall = 288
	SysSignalfd4             Syscall = 289
	SysEventfd2              Syscall = 290
	SysEpollCreate1          Syscall = 291
	SysDup3                  Syscall = 292
	SysPipe2                 Syscall = 293
	SysInotifyInit1          Syscall = 294
	SysPreadv                Syscall = 295
	SysPwritev               Syscall = 296
	SysRtTgsigqueueinfo      Syscall = 297
	SysPerfEventOpen         Syscall = 298
	SysRecvmmsg              Syscall = 299
	SysFanotifyInit          Syscall = 300
	SysFanotifyMark          Syscall = 301
	SysPrlimit64             Syscall = 302
	SysNameToHandleAt        Syscall = 303
	SysOpenByHandleAt        Syscall = 304
	SysClockAdjtime          Syscall = 305
	SysSyncfs                Syscall = 306
	SysSendmmsg              Syscall = 307
	SysSetns                 Syscall = 308
	SysGetcpu                Syscall = 309
	SysProcessVmReadv        Syscall = 310
	SysProcessVmWritev       Syscall = 311
	SysKcmp                  Syscall = 312
	SysFinitModule           Syscall = 313
	SysSchedSetattr          Syscall = 314
	SysSchedGetattr          Syscall = 315
	SysRenameat2             Syscall = 316
	SysSeccomp               Syscall = 317
	SysGetrandom             Syscall = 318
	SysMemfdCreate           Syscall = 319
	SysKexecFileLoad         Syscall = 320
	SysBpf                   Syscall = 321
	SysExecveat              Syscall = 322
	SysUserfaultfd           Syscall = 323
	SysMembarrier            Syscall = 324
	SysMlock2                Syscall = 325
	SysCopyFileRange         Syscall = 326
	SysPreadv2               Syscall = 327
	SysPwritev2              Syscall = 328
	SysPkeyMprotect          Syscall = 329
	SysPkeyAlloc             Syscall = 330
	SysPkeyFree              Syscall = 331
	SysStatx                 Syscall = 332
	SysIoPgetevents          Syscall = 333
	SysRseq                  Syscall = 334
	SysPidfdSendSignal       Syscall = 424
	SysIoUringSetup          Syscall = 425
	SysIoUringEnter          Syscall = 426
	SysIoUringRegister       Syscall = 427
	SysOpenTree              Syscall = 428
	SysMoveMount             Syscall = 429
	SysFsopen                Syscall = 430
	SysFsconfig              Syscall = 431
	SysFsmount               Syscall = 432
	SysFspick                Syscall = 433
	SysPidfdOpen             Syscall = 434
	SysClone3                Syscall = 435
	SysCloseRange            Syscall = 436
	SysOpenat2               Syscall = 437
	SysPidfdGetfd            Syscall = 438
	SysFaccessat2            Syscall = 439
	SysProcessMadvise        Syscall = 440
	SysEpollPwait2           Syscall = 441
	SysMountSetattr          Syscall = 442
	SysQuotactlFd            Syscall = 443
	SysLandlockCreateRuleset Syscall = 444
	SysLandlockAddRule       Syscall = 445
	SysLandlockRestrictSelf  Syscall = 446
	SysMemfdSecret           Syscall = 447
	SysLastSyscall           Syscall = 448
)

// MarshalText maps the syscall identifier to UTF-8-encoded text and returns the result
func (i Syscall) MarshalText() ([]byte, error) {
	return []byte(strings.ToLower(strings.TrimPrefix(i.String(), "Sys"))), nil
}

// ParseSyscallName returns the Syscall number of the provided syscall name
func ParseSyscallName(name string) Syscall {
	switch name {
	case "read":
		return SysRead
	case "write":
		return SysWrite
	case "open":
		return SysOpen
	case "close":
		return SysClose
	case "stat":
		return SysStat
	case "fstat":
		return SysFstat
	case "lstat":
		return SysLstat
	case "poll":
		return SysPoll
	case "lseek":
		return SysLseek
	case "mmap":
		return SysMmap
	case "mprotect":
		return SysMprotect
	case "munmap":
		return SysMunmap
	case "brk":
		return SysBrk
	case "rt_sigaction":
		return SysRtSigaction
	case "rt_sigprocmask":
		return SysRtSigprocmask
	case "rt_sigreturn":
		return SysRtSigreturn
	case "ioctl":
		return SysIoctl
	case "pread64":
		return SysPread64
	case "pwrite64":
		return SysPwrite64
	case "readv":
		return SysReadv
	case "writev":
		return SysWritev
	case "access":
		return SysAccess
	case "pipe":
		return SysPipe
	case "select":
		return SysSelect
	case "sched_yield":
		return SysSchedYield
	case "mremap":
		return SysMremap
	case "msync":
		return SysMsync
	case "mincore":
		return SysMincore
	case "madvise":
		return SysMadvise
	case "shmget":
		return SysShmget
	case "shmat":
		return SysShmat
	case "shmctl":
		return SysShmctl
	case "dup":
		return SysDup
	case "dup2":
		return SysDup2
	case "pause":
		return SysPause
	case "nanosleep":
		return SysNanosleep
	case "getitimer":
		return SysGetitimer
	case "alarm":
		return SysAlarm
	case "setitimer":
		return SysSetitimer
	case "getpid":
		return SysGetpid
	case "sendfile":
		return SysSendfile
	case "socket":
		return SysSocket
	case "connect":
		return SysConnect
	case "accept":
		return SysAccept
	case "sendto":
		return SysSendto
	case "recvfrom":
		return SysRecvfrom
	case "sendmsg":
		return SysSendmsg
	case "recvmsg":
		return SysRecvmsg
	case "shutdown":
		return SysShutdown
	case "bind":
		return SysBind
	case "listen":
		return SysListen
	case "getsockname":
		return SysGetsockname
	case "getpeername":
		return SysGetpeername
	case "socketpair":
		return SysSocketpair
	case "setsockopt":
		return SysSetsockopt
	case "getsockopt":
		return SysGetsockopt
	case "clone":
		return SysClone
	case "fork":
		return SysFork
	case "vfork":
		return SysVfork
	case "execve":
		return SysExecve
	case "exit":
		return SysExit
	case "wait4":
		return SysWait4
	case "kill":
		return SysKill
	case "uname":
		return SysUname
	case "semget":
		return SysSemget
	case "semop":
		return SysSemop
	case "semctl":
		return SysSemctl
	case "shmdt":
		return SysShmdt
	case "msgget":
		return SysMsgget
	case "msgsnd":
		return SysMsgsnd
	case "msgrcv":
		return SysMsgrcv
	case "msgctl":
		return SysMsgctl
	case "fcntl":
		return SysFcntl
	case "flock":
		return SysFlock
	case "fsync":
		return SysFsync
	case "fdatasync":
		return SysFdatasync
	case "truncate":
		return SysTruncate
	case "ftruncate":
		return SysFtruncate
	case "getdents":
		return SysGetdents
	case "getcwd":
		return SysGetcwd
	case "chdir":
		return SysChdir
	case "fchdir":
		return SysFchdir
	case "rename":
		return SysRename
	case "mkdir":
		return SysMkdir
	case "rmdir":
		return SysRmdir
	case "creat":
		return SysCreat
	case "link":
		return SysLink
	case "unlink":
		return SysUnlink
	case "symlink":
		return SysSymlink
	case "readlink":
		return SysReadlink
	case "chmod":
		return SysChmod
	case "fchmod":
		return SysFchmod
	case "chown":
		return SysChown
	case "fchown":
		return SysFchown
	case "lchown":
		return SysLchown
	case "umask":
		return SysUmask
	case "gettimeofday":
		return SysGettimeofday
	case "getrlimit":
		return SysGetrlimit
	case "getrusage":
		return SysGetrusage
	case "sysinfo":
		return SysSysinfo
	case "times":
		return SysTimes
	case "ptrace":
		return SysPtrace
	case "getuid":
		return SysGetuid
	case "syslog":
		return SysSyslog
	case "getgid":
		return SysGetgid
	case "setuid":
		return SysSetuid
	case "setgid":
		return SysSetgid
	case "geteuid":
		return SysGeteuid
	case "getegid":
		return SysGetegid
	case "setpgid":
		return SysSetpgid
	case "getppid":
		return SysGetppid
	case "getpgrp":
		return SysGetpgrp
	case "setsid":
		return SysSetsid
	case "setreuid":
		return SysSetreuid
	case "setregid":
		return SysSetregid
	case "getgroups":
		return SysGetgroups
	case "setgroups":
		return SysSetgroups
	case "setresuid":
		return SysSetresuid
	case "getresuid":
		return SysGetresuid
	case "setresgid":
		return SysSetresgid
	case "getresgid":
		return SysGetresgid
	case "getpgid":
		return SysGetpgid
	case "setfsuid":
		return SysSetfsuid
	case "setfsgid":
		return SysSetfsgid
	case "getsid":
		return SysGetsid
	case "capget":
		return SysCapget
	case "capset":
		return SysCapset
	case "rt_sigpending":
		return SysRtSigpending
	case "rt_sigtimedwait":
		return SysRtSigtimedwait
	case "rt_sigqueueinfo":
		return SysRtSigqueueinfo
	case "rt_sigsuspend":
		return SysRtSigsuspend
	case "sigaltstack":
		return SysSigaltstack
	case "utime":
		return SysUtime
	case "mknod":
		return SysMknod
	case "uselib":
		return SysUselib
	case "personality":
		return SysPersonality
	case "ustat":
		return SysUstat
	case "statfs":
		return SysStatfs
	case "fstatfs":
		return SysFstatfs
	case "sysfs":
		return SysSysfs
	case "getpriority":
		return SysGetpriority
	case "setpriority":
		return SysSetpriority
	case "sched_setparam":
		return SysSchedSetparam
	case "sched_getparam":
		return SysSchedGetparam
	case "sched_setscheduler":
		return SysSchedSetscheduler
	case "sched_getscheduler":
		return SysSchedGetscheduler
	case "sched_get_priority_max":
		return SysSchedGetPriorityMax
	case "sched_get_priority_min":
		return SysSchedGetPriorityMin
	case "sched_rr_get_interval":
		return SysSchedRrGetInterval
	case "mlock":
		return SysMlock
	case "munlock":
		return SysMunlock
	case "mlockall":
		return SysMlockall
	case "munlockall":
		return SysMunlockall
	case "vhangup":
		return SysVhangup
	case "modify_ldt":
		return SysModifyLdt
	case "pivot_root":
		return SysPivotRoot
	case "sysctl":
		return SysSysctl
	case "prctl":
		return SysPrctl
	case "arch_prctl":
		return SysArchPrctl
	case "adjtimex":
		return SysAdjtimex
	case "setrlimit":
		return SysSetrlimit
	case "chroot":
		return SysChroot
	case "sync":
		return SysSync
	case "acct":
		return SysAcct
	case "settimeofday":
		return SysSettimeofday
	case "mount":
		return SysMount
	case "umount":
		return SysUmount2
	case "swapon":
		return SysSwapon
	case "swapoff":
		return SysSwapoff
	case "reboot":
		return SysReboot
	case "sethostname":
		return SysSethostname
	case "setdomainname":
		return SysSetdomainname
	case "iopl":
		return SysIopl
	case "ioperm":
		return SysIoperm
	case "create_module":
		return SysCreateModule
	case "init_module":
		return SysInitModule
	case "delete_module":
		return SysDeleteModule
	case "get_kernel_syms":
		return SysGetKernelSyms
	case "query_module":
		return SysQueryModule
	case "quotactl":
		return SysQuotactl
	case "nfsservctl":
		return SysNfsservctl
	case "getpmsg":
		return SysGetpmsg
	case "putpmsg":
		return SysPutpmsg
	case "afs_syscall":
		return SysAfsSyscall
	case "tuxcall":
		return SysTuxcall
	case "security":
		return SysSecurity
	case "gettid":
		return SysGettid
	case "readahead":
		return SysReadahead
	case "setxattr":
		return SysSetxattr
	case "lsetxattr":
		return SysLsetxattr
	case "fsetxattr":
		return SysFsetxattr
	case "getxattr":
		return SysGetxattr
	case "lgetxattr":
		return SysLgetxattr
	case "fgetxattr":
		return SysFgetxattr
	case "listxattr":
		return SysListxattr
	case "llistxattr":
		return SysLlistxattr
	case "flistxattr":
		return SysFlistxattr
	case "removexattr":
		return SysRemovexattr
	case "lremovexattr":
		return SysLremovexattr
	case "fremovexattr":
		return SysFremovexattr
	case "tkill":
		return SysTkill
	case "time":
		return SysTime
	case "futex":
		return SysFutex
	case "sched_setaffinity":
		return SysSchedSetaffinity
	case "sched_getaffinity":
		return SysSchedGetaffinity
	case "set_thread_area":
		return SysSetThreadArea
	case "io_setup":
		return SysIoSetup
	case "io_destroy":
		return SysIoDestroy
	case "io_getevents":
		return SysIoGetevents
	case "io_submit":
		return SysIoSubmit
	case "io_cancel":
		return SysIoCancel
	case "get_thread_area":
		return SysGetThreadArea
	case "lookup_dcookie":
		return SysLookupDcookie
	case "epoll_create":
		return SysEpollCreate
	case "epoll_ctl_old":
		return SysEpollCtlOld
	case "epoll_wait_old":
		return SysEpollWaitOld
	case "remap_file_pages":
		return SysRemapFilePages
	case "getdents64":
		return SysGetdents64
	case "set_tid_address":
		return SysSetTidAddress
	case "restart_syscall":
		return SysRestartSyscall
	case "semtimedop":
		return SysSemtimedop
	case "fadvise64":
		return SysFadvise64
	case "timer_create":
		return SysTimerCreate
	case "timer_settime":
		return SysTimerSettime
	case "timer_gettime":
		return SysTimerGettime
	case "timer_getoverrun":
		return SysTimerGetoverrun
	case "timer_delete":
		return SysTimerDelete
	case "clock_settime":
		return SysClockSettime
	case "clock_gettime":
		return SysClockGettime
	case "clock_getres":
		return SysClockGetres
	case "clock_nanosleep":
		return SysClockNanosleep
	case "exit_group":
		return SysExitGroup
	case "epoll_wait":
		return SysEpollWait
	case "epoll_ctl":
		return SysEpollCtl
	case "tgkill":
		return SysTgkill
	case "utimes":
		return SysUtimes
	case "vserver":
		return SysVserver
	case "mbind":
		return SysMbind
	case "set_mempolicy":
		return SysSetMempolicy
	case "get_mempolicy":
		return SysGetMempolicy
	case "mq_open":
		return SysMqOpen
	case "mq_unlink":
		return SysMqUnlink
	case "mq_timedsend":
		return SysMqTimedsend
	case "mq_timedreceive":
		return SysMqTimedreceive
	case "mq_notify":
		return SysMqNotify
	case "mq_getsetattr":
		return SysMqGetsetattr
	case "kexec_load":
		return SysKexecLoad
	case "waitid":
		return SysWaitid
	case "add_key":
		return SysAddKey
	case "request_key":
		return SysRequestKey
	case "keyctl":
		return SysKeyctl
	case "ioprio_set":
		return SysIoprioSet
	case "ioprio_get":
		return SysIoprioGet
	case "inotify_init":
		return SysInotifyInit
	case "inotify_add_watch":
		return SysInotifyAddWatch
	case "inotify_rm_watch":
		return SysInotifyRmWatch
	case "migrate_pages":
		return SysMigratePages
	case "openat":
		return SysOpenat
	case "mkdirat":
		return SysMkdirat
	case "mknodat":
		return SysMknodat
	case "fchownat":
		return SysFchownat
	case "futimesat":
		return SysFutimesat
	case "newfstatat":
		return SysNewfstatat
	case "unlinkat":
		return SysUnlinkat
	case "renameat":
		return SysRenameat
	case "linkat":
		return SysLinkat
	case "symlinkat":
		return SysSymlinkat
	case "readlinkat":
		return SysReadlinkat
	case "fchmodat":
		return SysFchmodat
	case "faccessat":
		return SysFaccessat
	case "pselect6":
		return SysPselect6
	case "ppoll":
		return SysPpoll
	case "unshare":
		return SysUnshare
	case "set_robust_list":
		return SysSetRobustList
	case "get_robust_list":
		return SysGetRobustList
	case "splice":
		return SysSplice
	case "tee":
		return SysTee
	case "sync_file_range":
		return SysSyncFileRange
	case "vmsplice":
		return SysVmsplice
	case "move_pages":
		return SysMovePages
	case "utimensat":
		return SysUtimensat
	case "epoll_pwait":
		return SysEpollPwait
	case "signalfd":
		return SysSignalfd
	case "timerfd_create":
		return SysTimerfdCreate
	case "eventfd":
		return SysEventfd
	case "fallocate":
		return SysFallocate
	case "timerfd_settime":
		return SysTimerfdSettime
	case "timerfd_gettime":
		return SysTimerfdGettime
	case "accept4":
		return SysAccept4
	case "signalfd4":
		return SysSignalfd4
	case "eventfd2":
		return SysEventfd2
	case "epoll_create1":
		return SysEpollCreate1
	case "dup3":
		return SysDup3
	case "pipe2":
		return SysPipe2
	case "inotify_init1":
		return SysInotifyInit1
	case "preadv":
		return SysPreadv
	case "pwritev":
		return SysPwritev
	case "rt_tgsigqueueinfo":
		return SysRtTgsigqueueinfo
	case "perf_event_open":
		return SysPerfEventOpen
	case "recvmmsg":
		return SysRecvmmsg
	case "fanotify_init":
		return SysFanotifyInit
	case "fanotify_mark":
		return SysFanotifyMark
	case "prlimit64":
		return SysPrlimit64
	case "name_to_handle_at":
		return SysNameToHandleAt
	case "open_by_handle_at":
		return SysOpenByHandleAt
	case "clock_adjtime":
		return SysClockAdjtime
	case "syncfs":
		return SysSyncfs
	case "sendmmsg":
		return SysSendmmsg
	case "setns":
		return SysSetns
	case "getcpu":
		return SysGetcpu
	case "process_vm_readv":
		return SysProcessVmReadv
	case "process_vm_writev":
		return SysProcessVmWritev
	case "kcmp":
		return SysKcmp
	case "finit_module":
		return SysFinitModule
	case "sched_setattr":
		return SysSchedSetattr
	case "sched_getattr":
		return SysSchedGetattr
	case "renameat2":
		return SysRenameat2
	case "seccomp":
		return SysSeccomp
	case "getrandom":
		return SysGetrandom
	case "memfd_create":
		return SysMemfdCreate
	case "kexec_file_load":
		return SysKexecFileLoad
	case "bpf":
		return SysBpf
	case "execveat":
		return SysExecveat
	case "userfaultfd":
		return SysUserfaultfd
	case "membarrier":
		return SysMembarrier
	case "mlock2":
		return SysMlock2
	case "copy_file_range":
		return SysCopyFileRange
	case "preadv2":
		return SysPreadv2
	case "pwritev2":
		return SysPwritev2
	case "pkey_mprotect":
		return SysPkeyMprotect
	case "pkey_alloc":
		return SysPkeyAlloc
	case "pkey_free":
		return SysPkeyFree
	case "statx":
		return SysStatx
	case "io_pgetevents":
		return SysIoPgetevents
	case "rseq":
		return SysRseq
	case "pidfd_send_signal":
		return SysPidfdSendSignal
	case "io_uring_setup":
		return SysIoUringSetup
	case "io_uring_enter":
		return SysIoUringEnter
	case "io_uring_register":
		return SysIoUringRegister
	case "open_tree":
		return SysOpenTree
	case "move_mount":
		return SysMoveMount
	case "fsopen":
		return SysFsopen
	case "fsconfig":
		return SysFsconfig
	case "fsmount":
		return SysFsmount
	case "fspick":
		return SysFspick
	case "pidfd_open":
		return SysPidfdOpen
	case "clone3":
		return SysClone3
	case "close_range":
		return SysCloseRange
	case "openat2":
		return SysOpenat2
	case "pidfd_getfd":
		return SysPidfdGetfd
	case "faccessat2":
		return SysFaccessat2
	case "process_madvise":
		return SysProcessMadvise
	case "epoll_pwait2":
		return SysEpollPwait2
	case "mount_setattr":
		return SysMountSetattr
	case "quotactl_fd":
		return SysQuotactlFd
	case "landlock_create_ruleset":
		return SysLandlockCreateRuleset
	case "landlock_add_rule":
		return SysLandlockAddRule
	case "landlock_restrict_self":
		return SysLandlockRestrictSelf
	case "memfd_secret":
		return SysMemfdSecret
	default:
		if strings.HasPrefix(name, "new") {
			return ParseSyscallName(strings.TrimPrefix(name, "new"))
		}
		if strings.HasSuffix(name, "64") {
			return ParseSyscallName(strings.TrimSuffix(name, "64"))
		}
		return -1
	}
}
