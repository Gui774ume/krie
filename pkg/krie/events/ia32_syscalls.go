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

//go:generate go run golang.org/x/tools/cmd/stringer -type IA32Syscall -output ia32_syscalls_string_linux.go

package events

import (
	"strings"

	"github.com/pkg/errors"
)

// IA32Syscall represents a IA32Syscall identifier
type IA32Syscall int

func (i IA32Syscall) MarshalBinary() ([]byte, error) {
	rawIA32Syscall := make([]byte, 4)
	ByteOrder.PutUint32(rawIA32Syscall[:], uint32(i))
	return rawIA32Syscall, nil
}

func (i *IA32Syscall) UnmarshalIA32Syscall(data []byte) (int, error) {
	if len(data) < 4 {
		return 0, errors.Wrapf(ErrNotEnoughData, "parsing IA32Syscall: got len %d, needed 4", len(data))
	}
	*i = IA32Syscall(int(ByteOrder.Uint32(data[:4])))
	return 4, nil
}

func (i *IA32Syscall) UnmarshalBinary(data []byte) error {
	_, err := i.UnmarshalIA32Syscall(data)
	return err
}

// Linux IA32Syscall identifiers
const (
	IA32SysRestartSyscall             IA32Syscall = 0
	IA32SysExit                       IA32Syscall = 1
	IA32SysFork                       IA32Syscall = 2
	IA32SysRead                       IA32Syscall = 3
	IA32SysWrite                      IA32Syscall = 4
	IA32CompatSysOpen                 IA32Syscall = 5
	IA32SysClose                      IA32Syscall = 6
	IA32SysWaitpid                    IA32Syscall = 7
	IA32SysCreat                      IA32Syscall = 8
	IA32SysLink                       IA32Syscall = 9
	IA32SysUnlink                     IA32Syscall = 10
	IA32CompatSysExecve               IA32Syscall = 11
	IA32SysChdir                      IA32Syscall = 12
	IA32SysTime32                     IA32Syscall = 13
	IA32SysMknod                      IA32Syscall = 14
	IA32SysChmod                      IA32Syscall = 15
	IA32SysLchown16                   IA32Syscall = 16
	IA32Break                         IA32Syscall = 17
	IA32SysStat                       IA32Syscall = 18
	IA32CompatSysLseek                IA32Syscall = 19
	IA32SysGetpid                     IA32Syscall = 20
	IA32SysMount                      IA32Syscall = 21
	IA32SysOldumount                  IA32Syscall = 22
	IA32SysSetuid16                   IA32Syscall = 23
	IA32SysGetuid16                   IA32Syscall = 24
	IA32SysStime32                    IA32Syscall = 25
	IA32CompatSysPtrace               IA32Syscall = 26
	IA32SysAlarm                      IA32Syscall = 27
	IA32SysFstat                      IA32Syscall = 28
	IA32SysPause                      IA32Syscall = 29
	IA32SysUtime32                    IA32Syscall = 30
	IA32Stty                          IA32Syscall = 31
	IA32Gtty                          IA32Syscall = 32
	IA32SysAccess                     IA32Syscall = 33
	IA32SysNice                       IA32Syscall = 34
	IA32Ftime                         IA32Syscall = 35
	IA32SysSync                       IA32Syscall = 36
	IA32SysKill                       IA32Syscall = 37
	IA32SysRename                     IA32Syscall = 38
	IA32SysMkdir                      IA32Syscall = 39
	IA32SysRmdir                      IA32Syscall = 40
	IA32SysDup                        IA32Syscall = 41
	IA32SysPipe                       IA32Syscall = 42
	IA32CompatSysTimes                IA32Syscall = 43
	IA32Prof                          IA32Syscall = 44
	IA32SysBrk                        IA32Syscall = 45
	IA32SysSetgid16                   IA32Syscall = 46
	IA32SysGetgid16                   IA32Syscall = 47
	IA32SysSignal                     IA32Syscall = 48
	IA32SysGeteuid16                  IA32Syscall = 49
	IA32SysGetegid16                  IA32Syscall = 50
	IA32SysAcct                       IA32Syscall = 51
	IA32SysUmount                     IA32Syscall = 52
	IA32Lock                          IA32Syscall = 53
	IA32CompatSysIoctl                IA32Syscall = 54
	IA32CompatSysFcntl64              IA32Syscall = 55
	IA32Mpx                           IA32Syscall = 56
	IA32SysSetpgid                    IA32Syscall = 57
	IA32Ulimit                        IA32Syscall = 58
	IA32SysOlduname                   IA32Syscall = 59
	IA32SysUmask                      IA32Syscall = 60
	IA32SysChroot                     IA32Syscall = 61
	IA32CompatSysUstat                IA32Syscall = 62
	IA32SysDup2                       IA32Syscall = 63
	IA32SysGetppid                    IA32Syscall = 64
	IA32SysGetpgrp                    IA32Syscall = 65
	IA32SysSetsid                     IA32Syscall = 66
	IA32CompatSysSigaction            IA32Syscall = 67
	IA32SysSgetmask                   IA32Syscall = 68
	IA32SysSsetmask                   IA32Syscall = 69
	IA32SysSetreuid16                 IA32Syscall = 70
	IA32SysSetregid16                 IA32Syscall = 71
	IA32SysSigsuspend                 IA32Syscall = 72
	IA32CompatSysSigpending           IA32Syscall = 73
	IA32SysSethostname                IA32Syscall = 74
	IA32CompatSysSetrlimit            IA32Syscall = 75
	IA32CompatSysOldGetrlimit         IA32Syscall = 76
	IA32CompatSysGetrusage            IA32Syscall = 77
	IA32CompatSysGettimeofday         IA32Syscall = 78
	IA32CompatSysSettimeofday         IA32Syscall = 79
	IA32SysGetgroups16                IA32Syscall = 80
	IA32SysSetgroups16                IA32Syscall = 81
	IA32CompatSysOldSelect            IA32Syscall = 82
	IA32SysSymlink                    IA32Syscall = 83
	IA32SysLstat                      IA32Syscall = 84
	IA32SysReadlink                   IA32Syscall = 85
	IA32SysUselib                     IA32Syscall = 86
	IA32SysSwapon                     IA32Syscall = 87
	IA32SysReboot                     IA32Syscall = 88
	IA32CompatSysOldReaddir           IA32Syscall = 89
	IA32CompatSysIa32Mmap             IA32Syscall = 90
	IA32SysMunmap                     IA32Syscall = 91
	IA32CompatSysTruncate             IA32Syscall = 92
	IA32CompatSysFtruncate            IA32Syscall = 93
	IA32SysFchmod                     IA32Syscall = 94
	IA32SysFchown16                   IA32Syscall = 95
	IA32SysGetpriority                IA32Syscall = 96
	IA32SysSetpriority                IA32Syscall = 97
	IA32Profil                        IA32Syscall = 98
	IA32CompatSysStatfs               IA32Syscall = 99
	IA32CompatSysFstatfs              IA32Syscall = 100
	IA32SysIoperm                     IA32Syscall = 101
	IA32CompatSysSocketcall           IA32Syscall = 102
	IA32SysSyslog                     IA32Syscall = 103
	IA32CompatSysSetitimer            IA32Syscall = 104
	IA32CompatSysGetitimer            IA32Syscall = 105
	IA32CompatSysStat                 IA32Syscall = 106
	IA32CompatSysLstat                IA32Syscall = 107
	IA32CompatSysFstat                IA32Syscall = 108
	IA32SysUname                      IA32Syscall = 109
	IA32SysIopl                       IA32Syscall = 110
	IA32SysVhangup                    IA32Syscall = 111
	IA32Idle                          IA32Syscall = 112
	IA32CompatSysWait4                IA32Syscall = 114
	IA32SysSwapoff                    IA32Syscall = 115
	IA32CompatSysSysinfo              IA32Syscall = 116
	IA32CompatSysIpc                  IA32Syscall = 117
	IA32SysFsync                      IA32Syscall = 118
	IA32CompatSysSigreturn            IA32Syscall = 119
	IA32CompatSysIa32Clone            IA32Syscall = 120
	IA32SysSetdomainname              IA32Syscall = 121
	IA32SysNewUname                   IA32Syscall = 122
	IA32SysModifyLdt                  IA32Syscall = 123
	IA32SysAdjtimexTime32             IA32Syscall = 124
	IA32SysMprotect                   IA32Syscall = 125
	IA32CompatSysSigprocmask          IA32Syscall = 126
	IA32CreateModule                  IA32Syscall = 127
	IA32SysInitModule                 IA32Syscall = 128
	IA32SysDeleteModule               IA32Syscall = 129
	IA32GetKernelSyms                 IA32Syscall = 130
	IA32SysQuotactl                   IA32Syscall = 131
	IA32SysGetpgid                    IA32Syscall = 132
	IA32SysFchdir                     IA32Syscall = 133
	IA32SysSysfs                      IA32Syscall = 135
	IA32SysPersonality                IA32Syscall = 136
	IA32AfsSyscall                    IA32Syscall = 137
	IA32SysSetfsuid16                 IA32Syscall = 138
	IA32SysSetfsgid16                 IA32Syscall = 139
	IA32SysLlseek                     IA32Syscall = 140
	IA32CompatSysGetdents             IA32Syscall = 141
	IA32CompatSysSelect               IA32Syscall = 142
	IA32SysFlock                      IA32Syscall = 143
	IA32SysMsync                      IA32Syscall = 144
	IA32SysReadv                      IA32Syscall = 145
	IA32SysWritev                     IA32Syscall = 146
	IA32SysGetsid                     IA32Syscall = 147
	IA32SysFdatasync                  IA32Syscall = 148
	IA32SysMlock                      IA32Syscall = 150
	IA32SysMunlock                    IA32Syscall = 151
	IA32SysMlockall                   IA32Syscall = 152
	IA32SysMunlockall                 IA32Syscall = 153
	IA32SysSchedSetparam              IA32Syscall = 154
	IA32SysSchedGetparam              IA32Syscall = 155
	IA32SysSchedSetscheduler          IA32Syscall = 156
	IA32SysSchedGetscheduler          IA32Syscall = 157
	IA32SysSchedYield                 IA32Syscall = 158
	IA32SysSchedGetPriorityMax        IA32Syscall = 159
	IA32SysSchedGetPriorityMin        IA32Syscall = 160
	IA32SysSchedRrGetIntervalTime32   IA32Syscall = 161
	IA32SysNanosleepTime32            IA32Syscall = 162
	IA32SysMremap                     IA32Syscall = 163
	IA32SysSetresuid16                IA32Syscall = 164
	IA32SysGetresuid16                IA32Syscall = 165
	IA32QueryModule                   IA32Syscall = 167
	IA32SysPoll                       IA32Syscall = 168
	IA32Nfsservctl                    IA32Syscall = 169
	IA32SysSetresgid16                IA32Syscall = 170
	IA32SysGetresgid16                IA32Syscall = 171
	IA32SysPrctl                      IA32Syscall = 172
	IA32CompatSysRtSigreturn          IA32Syscall = 173
	IA32CompatSysRtSigaction          IA32Syscall = 174
	IA32CompatSysRtSigprocmask        IA32Syscall = 175
	IA32CompatSysRtSigpending         IA32Syscall = 176
	IA32CompatSysRtSigtimedwaitTime32 IA32Syscall = 177
	IA32CompatSysRtSigqueueinfo       IA32Syscall = 178
	IA32CompatSysRtSigsuspend         IA32Syscall = 179
	IA32SysIa32Pread64                IA32Syscall = 180
	IA32SysIa32Pwrite64               IA32Syscall = 181
	IA32SysChown16                    IA32Syscall = 182
	IA32SysGetcwd                     IA32Syscall = 183
	IA32SysCapget                     IA32Syscall = 184
	IA32SysCapset                     IA32Syscall = 185
	IA32CompatSysSigaltstack          IA32Syscall = 186
	IA32CompatSysSendfile             IA32Syscall = 187
	IA32Getpmsg                       IA32Syscall = 188
	IA32Putpmsg                       IA32Syscall = 189
	IA32SysVfork                      IA32Syscall = 190
	IA32CompatSysGetrlimit            IA32Syscall = 191
	IA32SysMmapPgoff                  IA32Syscall = 192
	IA32SysIa32Truncate64             IA32Syscall = 193
	IA32SysIa32Ftruncate64            IA32Syscall = 194
	IA32CompatSysIa32Stat64           IA32Syscall = 195
	IA32CompatSysIa32Lstat64          IA32Syscall = 196
	IA32CompatSysIa32Fstat64          IA32Syscall = 197
	IA32SysLchown                     IA32Syscall = 198
	IA32SysGetuid                     IA32Syscall = 199
	IA32SysGetgid                     IA32Syscall = 200
	IA32SysGeteuid                    IA32Syscall = 201
	IA32SysGetegid                    IA32Syscall = 202
	IA32SysSetreuid                   IA32Syscall = 203
	IA32SysSetregid                   IA32Syscall = 204
	IA32SysGetgroups                  IA32Syscall = 205
	IA32SysSetgroups                  IA32Syscall = 206
	IA32SysFchown                     IA32Syscall = 207
	IA32SysSetresuid                  IA32Syscall = 208
	IA32SysGetresuid                  IA32Syscall = 209
	IA32SysSetresgid                  IA32Syscall = 210
	IA32SysGetresgid                  IA32Syscall = 211
	IA32SysChown                      IA32Syscall = 212
	IA32SysSetuid                     IA32Syscall = 213
	IA32SysSetgid                     IA32Syscall = 214
	IA32SysSetfsuid                   IA32Syscall = 215
	IA32SysSetfsgid                   IA32Syscall = 216
	IA32SysPivotRoot                  IA32Syscall = 217
	IA32SysMincore                    IA32Syscall = 218
	IA32SysMadvise                    IA32Syscall = 219
	IA32SysGetdents64                 IA32Syscall = 220
	IA32CompatSysFcntl642             IA32Syscall = 221
	IA32SysGettid                     IA32Syscall = 224
	IA32SysIa32Readahead              IA32Syscall = 225
	IA32SysSetxattr                   IA32Syscall = 226
	IA32SysLsetxattr                  IA32Syscall = 227
	IA32SysFsetxattr                  IA32Syscall = 228
	IA32SysGetxattr                   IA32Syscall = 229
	IA32SysLgetxattr                  IA32Syscall = 230
	IA32SysFgetxattr                  IA32Syscall = 231
	IA32SysListxattr                  IA32Syscall = 232
	IA32SysLlistxattr                 IA32Syscall = 233
	IA32SysFlistxattr                 IA32Syscall = 234
	IA32SysRemovexattr                IA32Syscall = 235
	IA32SysLremovexattr               IA32Syscall = 236
	IA32SysFremovexattr               IA32Syscall = 237
	IA32SysTkill                      IA32Syscall = 238
	IA32SysSendfile64                 IA32Syscall = 239
	IA32SysFutexTime32                IA32Syscall = 240
	IA32CompatSysSchedSetaffinity     IA32Syscall = 241
	IA32CompatSysSchedGetaffinity     IA32Syscall = 242
	IA32SysSetThreadArea              IA32Syscall = 243
	IA32SysGetThreadArea              IA32Syscall = 244
	IA32CompatSysIoSetup              IA32Syscall = 245
	IA32SysIoDestroy                  IA32Syscall = 246
	IA32SysIoGeteventsTime32          IA32Syscall = 247
	IA32CompatSysIoSubmit             IA32Syscall = 248
	IA32SysIoCancel                   IA32Syscall = 249
	IA32SysIa32Fadvise64              IA32Syscall = 250
	IA32SysExitGroup                  IA32Syscall = 252
	IA32CompatSysLookupDcookie        IA32Syscall = 253
	IA32SysEpollCreate                IA32Syscall = 254
	IA32SysEpollCtl                   IA32Syscall = 255
	IA32SysEpollWait                  IA32Syscall = 256
	IA32SysRemapFilePages             IA32Syscall = 257
	IA32SysSetTidAddress              IA32Syscall = 258
	IA32CompatSysTimerCreate          IA32Syscall = 259
	IA32SysTimerSettime32             IA32Syscall = 260
	IA32SysTimerGettime32             IA32Syscall = 261
	IA32SysTimerGetoverrun            IA32Syscall = 262
	IA32SysTimerDelete                IA32Syscall = 263
	IA32SysClockSettime32             IA32Syscall = 264
	IA32SysClockGettime32             IA32Syscall = 265
	IA32SysClockGetresTime32          IA32Syscall = 266
	IA32SysClockNanosleepTime32       IA32Syscall = 267
	IA32CompatSysStatfs64             IA32Syscall = 268
	IA32CompatSysFstatfs64            IA32Syscall = 269
	IA32SysTgkill                     IA32Syscall = 270
	IA32SysUtimesTime32               IA32Syscall = 271
	IA32SysIa32Fadvise6464            IA32Syscall = 272
	IA32Vserver                       IA32Syscall = 273
	IA32SysMbind                      IA32Syscall = 274
	IA32SysGetMempolicy               IA32Syscall = 275
	IA32SysSetMempolicy               IA32Syscall = 276
	IA32CompatSysMqOpen               IA32Syscall = 277
	IA32SysMqUnlink                   IA32Syscall = 278
	IA32SysMqTimedsendTime32          IA32Syscall = 279
	IA32SysMqTimedreceiveTime32       IA32Syscall = 280
	IA32CompatSysMqNotify             IA32Syscall = 281
	IA32CompatSysMqGetsetattr         IA32Syscall = 282
	IA32CompatSysKexecLoad            IA32Syscall = 283
	IA32CompatSysWaitid               IA32Syscall = 284
	IA32SysAddKey                     IA32Syscall = 286
	IA32SysRequestKey                 IA32Syscall = 287
	IA32CompatSysKeyctl               IA32Syscall = 288
	IA32SysIoprioSet                  IA32Syscall = 289
	IA32SysIoprioGet                  IA32Syscall = 290
	IA32SysInotifyInit                IA32Syscall = 291
	IA32SysInotifyAddWatch            IA32Syscall = 292
	IA32SysInotifyRmWatch             IA32Syscall = 293
	IA32SysMigratePages               IA32Syscall = 294
	IA32CompatSysOpenat               IA32Syscall = 295
	IA32SysMkdirat                    IA32Syscall = 296
	IA32SysMknodat                    IA32Syscall = 297
	IA32SysFchownat                   IA32Syscall = 298
	IA32SysFutimesatTime32            IA32Syscall = 299
	IA32CompatSysIa32Fstatat64        IA32Syscall = 300
	IA32SysUnlinkat                   IA32Syscall = 301
	IA32SysRenameat                   IA32Syscall = 302
	IA32SysLinkat                     IA32Syscall = 303
	IA32SysSymlinkat                  IA32Syscall = 304
	IA32SysReadlinkat                 IA32Syscall = 305
	IA32SysFchmodat                   IA32Syscall = 306
	IA32SysFaccessat                  IA32Syscall = 307
	IA32CompatSysPselect6Time32       IA32Syscall = 308
	IA32CompatSysPpollTime32          IA32Syscall = 309
	IA32SysUnshare                    IA32Syscall = 310
	IA32CompatSysSetRobustList        IA32Syscall = 311
	IA32CompatSysGetRobustList        IA32Syscall = 312
	IA32SysSplice                     IA32Syscall = 313
	IA32SysIa32SyncFileRange          IA32Syscall = 314
	IA32SysTee                        IA32Syscall = 315
	IA32SysVmsplice                   IA32Syscall = 316
	IA32SysMovePages                  IA32Syscall = 317
	IA32SysGetcpu                     IA32Syscall = 318
	IA32SysEpollPwait                 IA32Syscall = 319
	IA32SysUtimensatTime32            IA32Syscall = 320
	IA32CompatSysSignalfd             IA32Syscall = 321
	IA32SysTimerfdCreate              IA32Syscall = 322
	IA32SysEventfd                    IA32Syscall = 323
	IA32SysIa32Fallocate              IA32Syscall = 324
	IA32SysTimerfdSettime32           IA32Syscall = 325
	IA32SysTimerfdGettime32           IA32Syscall = 326
	IA32CompatSysSignalfd4            IA32Syscall = 327
	IA32SysEventfd2                   IA32Syscall = 328
	IA32SysEpollCreate1               IA32Syscall = 329
	IA32SysDup3                       IA32Syscall = 330
	IA32SysPipe2                      IA32Syscall = 331
	IA32SysInotifyInit1               IA32Syscall = 332
	IA32CompatSysPreadv               IA32Syscall = 333
	IA32CompatSysPwritev              IA32Syscall = 334
	IA32CompatSysRtTgsigqueueinfo     IA32Syscall = 335
	IA32SysPerfEventOpen              IA32Syscall = 336
	IA32CompatSysRecvmmsgTime32       IA32Syscall = 337
	IA32SysFanotifyInit               IA32Syscall = 338
	IA32CompatSysFanotifyMark         IA32Syscall = 339
	IA32SysPrlimit64                  IA32Syscall = 340
	IA32SysNameToHandleAt             IA32Syscall = 341
	IA32CompatSysOpenByHandleAt       IA32Syscall = 342
	IA32SysClockAdjtime32             IA32Syscall = 343
	IA32SysSyncfs                     IA32Syscall = 344
	IA32CompatSysSendmmsg             IA32Syscall = 345
	IA32SysSetns                      IA32Syscall = 346
	IA32SysProcessVmReadv             IA32Syscall = 347
	IA32SysProcessVmWritev            IA32Syscall = 348
	IA32SysKcmp                       IA32Syscall = 349
	IA32SysFinitModule                IA32Syscall = 350
	IA32SysSchedSetattr               IA32Syscall = 351
	IA32SysSchedGetattr               IA32Syscall = 352
	IA32SysRenameat2                  IA32Syscall = 353
	IA32SysSeccomp                    IA32Syscall = 354
	IA32SysGetrandom                  IA32Syscall = 355
	IA32SysMemfdCreate                IA32Syscall = 356
	IA32SysBpf                        IA32Syscall = 357
	IA32CompatSysExecveat             IA32Syscall = 358
	IA32SysSocket                     IA32Syscall = 359
	IA32SysSocketpair                 IA32Syscall = 360
	IA32SysBind                       IA32Syscall = 361
	IA32SysConnect                    IA32Syscall = 362
	IA32SysListen                     IA32Syscall = 363
	IA32SysAccept4                    IA32Syscall = 364
	IA32SysGetsockopt                 IA32Syscall = 365
	IA32SysSetsockopt                 IA32Syscall = 366
	IA32SysGetsockname                IA32Syscall = 367
	IA32SysGetpeername                IA32Syscall = 368
	IA32SysSendto                     IA32Syscall = 369
	IA32CompatSysSendmsg              IA32Syscall = 370
	IA32CompatSysRecvfrom             IA32Syscall = 371
	IA32CompatSysRecvmsg              IA32Syscall = 372
	IA32SysShutdown                   IA32Syscall = 373
	IA32SysUserfaultfd                IA32Syscall = 374
	IA32SysMembarrier                 IA32Syscall = 375
	IA32SysMlock2                     IA32Syscall = 376
	IA32SysCopyFileRange              IA32Syscall = 377
	IA32CompatSysPreadv2              IA32Syscall = 378
	IA32CompatSysPwritev2             IA32Syscall = 379
	IA32SysPkeyMprotect               IA32Syscall = 380
	IA32SysPkeyAlloc                  IA32Syscall = 381
	IA32SysPkeyFree                   IA32Syscall = 382
	IA32SysStatx                      IA32Syscall = 383
	IA32CompatSysArchPrctl            IA32Syscall = 384
	IA32CompatSysIoPgetevents         IA32Syscall = 385
	IA32SysRseq                       IA32Syscall = 386
	IA32SysSemget                     IA32Syscall = 393
	IA32CompatSysSemctl               IA32Syscall = 394
	IA32SysShmget                     IA32Syscall = 395
	IA32CompatSysShmctl               IA32Syscall = 396
	IA32CompatSysShmat                IA32Syscall = 397
	IA32SysShmdt                      IA32Syscall = 398
	IA32SysMsgget                     IA32Syscall = 399
	IA32CompatSysMsgsnd               IA32Syscall = 400
	IA32CompatSysMsgrcv               IA32Syscall = 401
	IA32CompatSysMsgctl               IA32Syscall = 402
	IA32SysClockGettime               IA32Syscall = 403
	IA32SysClockSettime               IA32Syscall = 404
	IA32SysClockAdjtime               IA32Syscall = 405
	IA32SysClockGetres                IA32Syscall = 406
	IA32SysClockNanosleep             IA32Syscall = 407
	IA32SysTimerGettime               IA32Syscall = 408
	IA32SysTimerSettime               IA32Syscall = 409
	IA32SysTimerfdGettime             IA32Syscall = 410
	IA32SysTimerfdSettime             IA32Syscall = 411
	IA32SysUtimensat                  IA32Syscall = 412
	IA32CompatSysPselect6Time64       IA32Syscall = 413
	IA32CompatSysPpollTime64          IA32Syscall = 414
	IA32SysIoPgetevents               IA32Syscall = 416
	IA32CompatSysRecvmmsgTime64       IA32Syscall = 417
	IA32SysMqTimedsend                IA32Syscall = 418
	IA32SysMqTimedreceive             IA32Syscall = 419
	IA32SysSemtimedop                 IA32Syscall = 420
	IA32CompatSysRtSigtimedwaitTime64 IA32Syscall = 421
	IA32SysFutex                      IA32Syscall = 422
	IA32SysSchedRrGetInterval         IA32Syscall = 423
	IA32SysPidfdSendSignal            IA32Syscall = 424
	IA32SysIoUringSetup               IA32Syscall = 425
	IA32SysIoUringEnter               IA32Syscall = 426
	IA32SysIoUringRegister            IA32Syscall = 427
	IA32SysOpenTree                   IA32Syscall = 428
	IA32SysMoveMount                  IA32Syscall = 429
	IA32SysFsopen                     IA32Syscall = 430
	IA32SysFsconfig                   IA32Syscall = 431
	IA32SysFsmount                    IA32Syscall = 432
	IA32SysFspick                     IA32Syscall = 433
	IA32SysPidfdOpen                  IA32Syscall = 434
	IA32SysClone3                     IA32Syscall = 435
	IA32SysCloseRange                 IA32Syscall = 436
	IA32SysOpenat2                    IA32Syscall = 437
	IA32SysPidfdGetfd                 IA32Syscall = 438
	IA32SysFaccessat2                 IA32Syscall = 439
	IA32SysProcessMadvise             IA32Syscall = 440
	IA32CompatSysEpollPwait2          IA32Syscall = 441
	IA32SysMountSetattr               IA32Syscall = 442
	IA32SysQuotactlFd                 IA32Syscall = 443
	IA32SysLandlockCreateRuleset      IA32Syscall = 444
	IA32SysLandlockAddRule            IA32Syscall = 445
	IA32SysLandlockRestrictSelf       IA32Syscall = 446
	IA32SysMemfdSecret                IA32Syscall = 447
	IA32SysProcessMrelease            IA32Syscall = 448
	IA32SysFutexWaitv                 IA32Syscall = 449
	IA32SysSetMempolicyHomeNode       IA32Syscall = 450
)

// MarshalText maps the IA32Syscall identifier to UTF-8-encoded text and returns the result
func (i IA32Syscall) MarshalText() ([]byte, error) {
	return []byte(strings.ToLower(strings.TrimPrefix(i.String(), "Sys"))), nil
}

// ParseIA32SyscallName returns the IA32Syscall number of the provided IA32Syscall name
func ParseIA32SyscallName(name string) IA32Syscall {
	switch name {
	case "ia32_restartcall":
		return IA32SysRestartSyscall
	case "ia32_exit":
		return IA32SysExit
	case "ia32_fork":
		return IA32SysFork
	case "ia32_read":
		return IA32SysRead
	case "ia32_write":
		return IA32SysWrite
	case "ia32_compat_open":
		return IA32CompatSysOpen
	case "ia32_close":
		return IA32SysClose
	case "ia32_waitpid":
		return IA32SysWaitpid
	case "ia32_creat":
		return IA32SysCreat
	case "ia32_link":
		return IA32SysLink
	case "ia32_unlink":
		return IA32SysUnlink
	case "ia32_compat_execve":
		return IA32CompatSysExecve
	case "ia32_chdir":
		return IA32SysChdir
	case "ia32_time32":
		return IA32SysTime32
	case "ia32_mknod":
		return IA32SysMknod
	case "ia32_chmod":
		return IA32SysChmod
	case "ia32_lchown16":
		return IA32SysLchown16
	case "ia32_break":
		return IA32Break
	case "ia32_stat":
		return IA32SysStat
	case "ia32_compat_lseek":
		return IA32CompatSysLseek
	case "ia32_getpid":
		return IA32SysGetpid
	case "ia32_mount":
		return IA32SysMount
	case "ia32_oldumount":
		return IA32SysOldumount
	case "ia32_setuid16":
		return IA32SysSetuid16
	case "ia32_getuid16":
		return IA32SysGetuid16
	case "ia32_stime32":
		return IA32SysStime32
	case "ia32_compat_ptrace":
		return IA32CompatSysPtrace
	case "ia32_alarm":
		return IA32SysAlarm
	case "ia32_fstat":
		return IA32SysFstat
	case "ia32_pause":
		return IA32SysPause
	case "ia32_utime32":
		return IA32SysUtime32
	case "ia32_stty":
		return IA32Stty
	case "ia32_gtty":
		return IA32Gtty
	case "ia32_access":
		return IA32SysAccess
	case "ia32_nice":
		return IA32SysNice
	case "ia32_ftime":
		return IA32Ftime
	case "ia32_sync":
		return IA32SysSync
	case "ia32_kill":
		return IA32SysKill
	case "ia32_rename":
		return IA32SysRename
	case "ia32_mkdir":
		return IA32SysMkdir
	case "ia32_rmdir":
		return IA32SysRmdir
	case "ia32_dup":
		return IA32SysDup
	case "ia32_pipe":
		return IA32SysPipe
	case "ia32_compat_times":
		return IA32CompatSysTimes
	case "ia32_prof":
		return IA32Prof
	case "ia32_brk":
		return IA32SysBrk
	case "ia32_setgid16":
		return IA32SysSetgid16
	case "ia32_getgid16":
		return IA32SysGetgid16
	case "ia32_signal":
		return IA32SysSignal
	case "ia32_geteuid16":
		return IA32SysGeteuid16
	case "ia32_getegid16":
		return IA32SysGetegid16
	case "ia32_acct":
		return IA32SysAcct
	case "ia32_umount":
		return IA32SysUmount
	case "ia32_lock":
		return IA32Lock
	case "ia32_compat_ioctl":
		return IA32CompatSysIoctl
	case "ia32_compat_fcntl64":
		return IA32CompatSysFcntl64
	case "ia32_mpx":
		return IA32Mpx
	case "ia32_setpgid":
		return IA32SysSetpgid
	case "ia32_ulimit":
		return IA32Ulimit
	case "ia32_olduname":
		return IA32SysOlduname
	case "ia32_umask":
		return IA32SysUmask
	case "ia32_chroot":
		return IA32SysChroot
	case "ia32_compat_ustat":
		return IA32CompatSysUstat
	case "ia32_dup2":
		return IA32SysDup2
	case "ia32_getppid":
		return IA32SysGetppid
	case "ia32_getpgrp":
		return IA32SysGetpgrp
	case "ia32_setsid":
		return IA32SysSetsid
	case "ia32_compat_sigaction":
		return IA32CompatSysSigaction
	case "ia32_sgetmask":
		return IA32SysSgetmask
	case "ia32_ssetmask":
		return IA32SysSsetmask
	case "ia32_setreuid16":
		return IA32SysSetreuid16
	case "ia32_setregid16":
		return IA32SysSetregid16
	case "ia32_sigsuspend":
		return IA32SysSigsuspend
	case "ia32_compat_sigpending":
		return IA32CompatSysSigpending
	case "ia32_sethostname":
		return IA32SysSethostname
	case "ia32_compat_setrlimit":
		return IA32CompatSysSetrlimit
	case "ia32_compat_old_getrlimit":
		return IA32CompatSysOldGetrlimit
	case "ia32_compat_getrusage":
		return IA32CompatSysGetrusage
	case "ia32_compat_gettimeofday":
		return IA32CompatSysGettimeofday
	case "ia32_compat_settimeofday":
		return IA32CompatSysSettimeofday
	case "ia32_getgroups16":
		return IA32SysGetgroups16
	case "ia32_setgroups16":
		return IA32SysSetgroups16
	case "ia32_compat_old_select":
		return IA32CompatSysOldSelect
	case "ia32_symlink":
		return IA32SysSymlink
	case "ia32_lstat":
		return IA32SysLstat
	case "ia32_readlink":
		return IA32SysReadlink
	case "ia32_uselib":
		return IA32SysUselib
	case "ia32_swapon":
		return IA32SysSwapon
	case "ia32_reboot":
		return IA32SysReboot
	case "ia32_compat_old_readdir":
		return IA32CompatSysOldReaddir
	case "ia32_compat_ia32_mmap":
		return IA32CompatSysIa32Mmap
	case "ia32_munmap":
		return IA32SysMunmap
	case "ia32_compat_truncate":
		return IA32CompatSysTruncate
	case "ia32_compat_ftruncate":
		return IA32CompatSysFtruncate
	case "ia32_fchmod":
		return IA32SysFchmod
	case "ia32_fchown16":
		return IA32SysFchown16
	case "ia32_getpriority":
		return IA32SysGetpriority
	case "ia32_setpriority":
		return IA32SysSetpriority
	case "ia32_profil":
		return IA32Profil
	case "ia32_compat_statfs":
		return IA32CompatSysStatfs
	case "ia32_compat_fstatfs":
		return IA32CompatSysFstatfs
	case "ia32_ioperm":
		return IA32SysIoperm
	case "ia32_compat_socketcall":
		return IA32CompatSysSocketcall
	case "ia32log":
		return IA32SysSyslog
	case "ia32_compat_setitimer":
		return IA32CompatSysSetitimer
	case "ia32_compat_getitimer":
		return IA32CompatSysGetitimer
	case "ia32_compat_stat":
		return IA32CompatSysStat
	case "ia32_compat_lstat":
		return IA32CompatSysLstat
	case "ia32_compat_fstat":
		return IA32CompatSysFstat
	case "ia32_uname":
		return IA32SysUname
	case "ia32_iopl":
		return IA32SysIopl
	case "ia32_vhangup":
		return IA32SysVhangup
	case "ia32_idle":
		return IA32Idle
	case "ia32_compat_wait4":
		return IA32CompatSysWait4
	case "ia32_swapoff":
		return IA32SysSwapoff
	case "ia32_compatinfo":
		return IA32CompatSysSysinfo
	case "ia32_compat_ipc":
		return IA32CompatSysIpc
	case "ia32_fsync":
		return IA32SysFsync
	case "ia32_compat_sigreturn":
		return IA32CompatSysSigreturn
	case "ia32_compat_ia32_clone":
		return IA32CompatSysIa32Clone
	case "ia32_setdomainname":
		return IA32SysSetdomainname
	case "ia32_new_uname":
		return IA32SysNewUname
	case "ia32_modify_ldt":
		return IA32SysModifyLdt
	case "ia32_adjtimex_time32":
		return IA32SysAdjtimexTime32
	case "ia32_mprotect":
		return IA32SysMprotect
	case "ia32_compat_sigprocmask":
		return IA32CompatSysSigprocmask
	case "ia32_create_module":
		return IA32CreateModule
	case "ia32_init_module":
		return IA32SysInitModule
	case "ia32_delete_module":
		return IA32SysDeleteModule
	case "ia32_get_kernel_syms":
		return IA32GetKernelSyms
	case "ia32_quotactl":
		return IA32SysQuotactl
	case "ia32_getpgid":
		return IA32SysGetpgid
	case "ia32_fchdir":
		return IA32SysFchdir
	case "ia32fs":
		return IA32SysSysfs
	case "ia32_personality":
		return IA32SysPersonality
	case "ia32_afscall":
		return IA32AfsSyscall
	case "ia32_setfsuid16":
		return IA32SysSetfsuid16
	case "ia32_setfsgid16":
		return IA32SysSetfsgid16
	case "ia32_llseek":
		return IA32SysLlseek
	case "ia32_compat_getdents":
		return IA32CompatSysGetdents
	case "ia32_compat_select":
		return IA32CompatSysSelect
	case "ia32_flock":
		return IA32SysFlock
	case "ia32_msync":
		return IA32SysMsync
	case "ia32_readv":
		return IA32SysReadv
	case "ia32_writev":
		return IA32SysWritev
	case "ia32_getsid":
		return IA32SysGetsid
	case "ia32_fdatasync":
		return IA32SysFdatasync
	case "ia32_mlock":
		return IA32SysMlock
	case "ia32_munlock":
		return IA32SysMunlock
	case "ia32_mlockall":
		return IA32SysMlockall
	case "ia32_munlockall":
		return IA32SysMunlockall
	case "ia32_sched_setparam":
		return IA32SysSchedSetparam
	case "ia32_sched_getparam":
		return IA32SysSchedGetparam
	case "ia32_sched_setscheduler":
		return IA32SysSchedSetscheduler
	case "ia32_sched_getscheduler":
		return IA32SysSchedGetscheduler
	case "ia32_sched_yield":
		return IA32SysSchedYield
	case "ia32_sched_get_priority_max":
		return IA32SysSchedGetPriorityMax
	case "ia32_sched_get_priority_min":
		return IA32SysSchedGetPriorityMin
	case "ia32_sched_rr_get_interval_time32":
		return IA32SysSchedRrGetIntervalTime32
	case "ia32_nanosleep_time32":
		return IA32SysNanosleepTime32
	case "ia32_mremap":
		return IA32SysMremap
	case "ia32_setresuid16":
		return IA32SysSetresuid16
	case "ia32_getresuid16":
		return IA32SysGetresuid16
	case "ia32_query_module":
		return IA32QueryModule
	case "ia32_poll":
		return IA32SysPoll
	case "ia32_nfsservctl":
		return IA32Nfsservctl
	case "ia32_setresgid16":
		return IA32SysSetresgid16
	case "ia32_getresgid16":
		return IA32SysGetresgid16
	case "ia32_prctl":
		return IA32SysPrctl
	case "ia32_compat_rt_sigreturn":
		return IA32CompatSysRtSigreturn
	case "ia32_compat_rt_sigaction":
		return IA32CompatSysRtSigaction
	case "ia32_compat_rt_sigprocmask":
		return IA32CompatSysRtSigprocmask
	case "ia32_compat_rt_sigpending":
		return IA32CompatSysRtSigpending
	case "ia32_compat_rt_sigtimedwait_time32":
		return IA32CompatSysRtSigtimedwaitTime32
	case "ia32_compat_rt_sigqueueinfo":
		return IA32CompatSysRtSigqueueinfo
	case "ia32_compat_rt_sigsuspend":
		return IA32CompatSysRtSigsuspend
	case "ia32_ia32_pread64":
		return IA32SysIa32Pread64
	case "ia32_ia32_pwrite64":
		return IA32SysIa32Pwrite64
	case "ia32_chown16":
		return IA32SysChown16
	case "ia32_getcwd":
		return IA32SysGetcwd
	case "ia32_capget":
		return IA32SysCapget
	case "ia32_capset":
		return IA32SysCapset
	case "ia32_compat_sigaltstack":
		return IA32CompatSysSigaltstack
	case "ia32_compat_sendfile":
		return IA32CompatSysSendfile
	case "ia32_getpmsg":
		return IA32Getpmsg
	case "ia32_putpmsg":
		return IA32Putpmsg
	case "ia32_vfork":
		return IA32SysVfork
	case "ia32_compat_getrlimit":
		return IA32CompatSysGetrlimit
	case "ia32_mmap_pgoff":
		return IA32SysMmapPgoff
	case "ia32_ia32_truncate64":
		return IA32SysIa32Truncate64
	case "ia32_ia32_ftruncate64":
		return IA32SysIa32Ftruncate64
	case "ia32_compat_ia32_stat64":
		return IA32CompatSysIa32Stat64
	case "ia32_compat_ia32_lstat64":
		return IA32CompatSysIa32Lstat64
	case "ia32_compat_ia32_fstat64":
		return IA32CompatSysIa32Fstat64
	case "ia32_lchown":
		return IA32SysLchown
	case "ia32_getuid":
		return IA32SysGetuid
	case "ia32_getgid":
		return IA32SysGetgid
	case "ia32_geteuid":
		return IA32SysGeteuid
	case "ia32_getegid":
		return IA32SysGetegid
	case "ia32_setreuid":
		return IA32SysSetreuid
	case "ia32_setregid":
		return IA32SysSetregid
	case "ia32_getgroups":
		return IA32SysGetgroups
	case "ia32_setgroups":
		return IA32SysSetgroups
	case "ia32_fchown":
		return IA32SysFchown
	case "ia32_setresuid":
		return IA32SysSetresuid
	case "ia32_getresuid":
		return IA32SysGetresuid
	case "ia32_setresgid":
		return IA32SysSetresgid
	case "ia32_getresgid":
		return IA32SysGetresgid
	case "ia32_chown":
		return IA32SysChown
	case "ia32_setuid":
		return IA32SysSetuid
	case "ia32_setgid":
		return IA32SysSetgid
	case "ia32_setfsuid":
		return IA32SysSetfsuid
	case "ia32_setfsgid":
		return IA32SysSetfsgid
	case "ia32_pivot_root":
		return IA32SysPivotRoot
	case "ia32_mincore":
		return IA32SysMincore
	case "ia32_madvise":
		return IA32SysMadvise
	case "ia32_getdents64":
		return IA32SysGetdents64
	case "ia32_compat_fcntl642":
		return IA32CompatSysFcntl642
	case "ia32_gettid":
		return IA32SysGettid
	case "ia32_ia32_readahead":
		return IA32SysIa32Readahead
	case "ia32_setxattr":
		return IA32SysSetxattr
	case "ia32_lsetxattr":
		return IA32SysLsetxattr
	case "ia32_fsetxattr":
		return IA32SysFsetxattr
	case "ia32_getxattr":
		return IA32SysGetxattr
	case "ia32_lgetxattr":
		return IA32SysLgetxattr
	case "ia32_fgetxattr":
		return IA32SysFgetxattr
	case "ia32_listxattr":
		return IA32SysListxattr
	case "ia32_llistxattr":
		return IA32SysLlistxattr
	case "ia32_flistxattr":
		return IA32SysFlistxattr
	case "ia32_removexattr":
		return IA32SysRemovexattr
	case "ia32_lremovexattr":
		return IA32SysLremovexattr
	case "ia32_fremovexattr":
		return IA32SysFremovexattr
	case "ia32_tkill":
		return IA32SysTkill
	case "ia32_sendfile64":
		return IA32SysSendfile64
	case "ia32_futex_time32":
		return IA32SysFutexTime32
	case "ia32_compat_sched_setaffinity":
		return IA32CompatSysSchedSetaffinity
	case "ia32_compat_sched_getaffinity":
		return IA32CompatSysSchedGetaffinity
	case "ia32_set_thread_area":
		return IA32SysSetThreadArea
	case "ia32_get_thread_area":
		return IA32SysGetThreadArea
	case "ia32_compat_io_setup":
		return IA32CompatSysIoSetup
	case "ia32_io_destroy":
		return IA32SysIoDestroy
	case "ia32_io_getevents_time32":
		return IA32SysIoGeteventsTime32
	case "ia32_compat_io_submit":
		return IA32CompatSysIoSubmit
	case "ia32_io_cancel":
		return IA32SysIoCancel
	case "ia32_ia32_fadvise64":
		return IA32SysIa32Fadvise64
	case "ia32_exit_group":
		return IA32SysExitGroup
	case "ia32_compat_lookup_dcookie":
		return IA32CompatSysLookupDcookie
	case "ia32_epoll_create":
		return IA32SysEpollCreate
	case "ia32_epoll_ctl":
		return IA32SysEpollCtl
	case "ia32_epoll_wait":
		return IA32SysEpollWait
	case "ia32_remap_file_pages":
		return IA32SysRemapFilePages
	case "ia32_set_tid_address":
		return IA32SysSetTidAddress
	case "ia32_compat_timer_create":
		return IA32CompatSysTimerCreate
	case "ia32_timer_settime32":
		return IA32SysTimerSettime32
	case "ia32_timer_gettime32":
		return IA32SysTimerGettime32
	case "ia32_timer_getoverrun":
		return IA32SysTimerGetoverrun
	case "ia32_timer_delete":
		return IA32SysTimerDelete
	case "ia32_clock_settime32":
		return IA32SysClockSettime32
	case "ia32_clock_gettime32":
		return IA32SysClockGettime32
	case "ia32_clock_getres_time32":
		return IA32SysClockGetresTime32
	case "ia32_clock_nanosleep_time32":
		return IA32SysClockNanosleepTime32
	case "ia32_compat_statfs64":
		return IA32CompatSysStatfs64
	case "ia32_compat_fstatfs64":
		return IA32CompatSysFstatfs64
	case "ia32_tgkill":
		return IA32SysTgkill
	case "ia32_utimes_time32":
		return IA32SysUtimesTime32
	case "ia32_ia32_fadvise64_64":
		return IA32SysIa32Fadvise6464
	case "ia32_vserver":
		return IA32Vserver
	case "ia32_mbind":
		return IA32SysMbind
	case "ia32_get_mempolicy":
		return IA32SysGetMempolicy
	case "ia32_set_mempolicy":
		return IA32SysSetMempolicy
	case "ia32_compat_mq_open":
		return IA32CompatSysMqOpen
	case "ia32_mq_unlink":
		return IA32SysMqUnlink
	case "ia32_mq_timedsend_time32":
		return IA32SysMqTimedsendTime32
	case "ia32_mq_timedreceive_time32":
		return IA32SysMqTimedreceiveTime32
	case "ia32_compat_mq_notify":
		return IA32CompatSysMqNotify
	case "ia32_compat_mq_getsetattr":
		return IA32CompatSysMqGetsetattr
	case "ia32_compat_kexec_load":
		return IA32CompatSysKexecLoad
	case "ia32_compat_waitid":
		return IA32CompatSysWaitid
	case "ia32_add_key":
		return IA32SysAddKey
	case "ia32_request_key":
		return IA32SysRequestKey
	case "ia32_compat_keyctl":
		return IA32CompatSysKeyctl
	case "ia32_ioprio_set":
		return IA32SysIoprioSet
	case "ia32_ioprio_get":
		return IA32SysIoprioGet
	case "ia32_inotify_init":
		return IA32SysInotifyInit
	case "ia32_inotify_add_watch":
		return IA32SysInotifyAddWatch
	case "ia32_inotify_rm_watch":
		return IA32SysInotifyRmWatch
	case "ia32_migrate_pages":
		return IA32SysMigratePages
	case "ia32_compat_openat":
		return IA32CompatSysOpenat
	case "ia32_mkdirat":
		return IA32SysMkdirat
	case "ia32_mknodat":
		return IA32SysMknodat
	case "ia32_fchownat":
		return IA32SysFchownat
	case "ia32_futimesat_time32":
		return IA32SysFutimesatTime32
	case "ia32_compat_ia32_fstatat64":
		return IA32CompatSysIa32Fstatat64
	case "ia32_unlinkat":
		return IA32SysUnlinkat
	case "ia32_renameat":
		return IA32SysRenameat
	case "ia32_linkat":
		return IA32SysLinkat
	case "ia32_symlinkat":
		return IA32SysSymlinkat
	case "ia32_readlinkat":
		return IA32SysReadlinkat
	case "ia32_fchmodat":
		return IA32SysFchmodat
	case "ia32_faccessat":
		return IA32SysFaccessat
	case "ia32_compat_pselect6_time32":
		return IA32CompatSysPselect6Time32
	case "ia32_compat_ppoll_time32":
		return IA32CompatSysPpollTime32
	case "ia32_unshare":
		return IA32SysUnshare
	case "ia32_compat_set_robust_list":
		return IA32CompatSysSetRobustList
	case "ia32_compat_get_robust_list":
		return IA32CompatSysGetRobustList
	case "ia32_splice":
		return IA32SysSplice
	case "ia32_ia32_sync_file_range":
		return IA32SysIa32SyncFileRange
	case "ia32_tee":
		return IA32SysTee
	case "ia32_vmsplice":
		return IA32SysVmsplice
	case "ia32_move_pages":
		return IA32SysMovePages
	case "ia32_getcpu":
		return IA32SysGetcpu
	case "ia32_epoll_pwait":
		return IA32SysEpollPwait
	case "ia32_utimensat_time32":
		return IA32SysUtimensatTime32
	case "ia32_compat_signalfd":
		return IA32CompatSysSignalfd
	case "ia32_timerfd_create":
		return IA32SysTimerfdCreate
	case "ia32_eventfd":
		return IA32SysEventfd
	case "ia32_ia32_fallocate":
		return IA32SysIa32Fallocate
	case "ia32_timerfd_settime32":
		return IA32SysTimerfdSettime32
	case "ia32_timerfd_gettime32":
		return IA32SysTimerfdGettime32
	case "ia32_compat_signalfd4":
		return IA32CompatSysSignalfd4
	case "ia32_eventfd2":
		return IA32SysEventfd2
	case "ia32_epoll_create1":
		return IA32SysEpollCreate1
	case "ia32_dup3":
		return IA32SysDup3
	case "ia32_pipe2":
		return IA32SysPipe2
	case "ia32_inotify_init1":
		return IA32SysInotifyInit1
	case "ia32_compat_preadv":
		return IA32CompatSysPreadv
	case "ia32_compat_pwritev":
		return IA32CompatSysPwritev
	case "ia32_compat_rt_tgsigqueueinfo":
		return IA32CompatSysRtTgsigqueueinfo
	case "ia32_perf_event_open":
		return IA32SysPerfEventOpen
	case "ia32_compat_recvmmsg_time32":
		return IA32CompatSysRecvmmsgTime32
	case "ia32_fanotify_init":
		return IA32SysFanotifyInit
	case "ia32_compat_fanotify_mark":
		return IA32CompatSysFanotifyMark
	case "ia32_prlimit64":
		return IA32SysPrlimit64
	case "ia32_name_to_handle_at":
		return IA32SysNameToHandleAt
	case "ia32_compat_open_by_handle_at":
		return IA32CompatSysOpenByHandleAt
	case "ia32_clock_adjtime32":
		return IA32SysClockAdjtime32
	case "ia32_syncfs":
		return IA32SysSyncfs
	case "ia32_compat_sendmmsg":
		return IA32CompatSysSendmmsg
	case "ia32_setns":
		return IA32SysSetns
	case "ia32_process_vm_readv":
		return IA32SysProcessVmReadv
	case "ia32_process_vm_writev":
		return IA32SysProcessVmWritev
	case "ia32_kcmp":
		return IA32SysKcmp
	case "ia32_finit_module":
		return IA32SysFinitModule
	case "ia32_sched_setattr":
		return IA32SysSchedSetattr
	case "ia32_sched_getattr":
		return IA32SysSchedGetattr
	case "ia32_renameat2":
		return IA32SysRenameat2
	case "ia32_seccomp":
		return IA32SysSeccomp
	case "ia32_getrandom":
		return IA32SysGetrandom
	case "ia32_memfd_create":
		return IA32SysMemfdCreate
	case "ia32_bpf":
		return IA32SysBpf
	case "ia32_compat_execveat":
		return IA32CompatSysExecveat
	case "ia32_socket":
		return IA32SysSocket
	case "ia32_socketpair":
		return IA32SysSocketpair
	case "ia32_bind":
		return IA32SysBind
	case "ia32_connect":
		return IA32SysConnect
	case "ia32_listen":
		return IA32SysListen
	case "ia32_accept4":
		return IA32SysAccept4
	case "ia32_getsockopt":
		return IA32SysGetsockopt
	case "ia32_setsockopt":
		return IA32SysSetsockopt
	case "ia32_getsockname":
		return IA32SysGetsockname
	case "ia32_getpeername":
		return IA32SysGetpeername
	case "ia32_sendto":
		return IA32SysSendto
	case "ia32_compat_sendmsg":
		return IA32CompatSysSendmsg
	case "ia32_compat_recvfrom":
		return IA32CompatSysRecvfrom
	case "ia32_compat_recvmsg":
		return IA32CompatSysRecvmsg
	case "ia32_shutdown":
		return IA32SysShutdown
	case "ia32_userfaultfd":
		return IA32SysUserfaultfd
	case "ia32_membarrier":
		return IA32SysMembarrier
	case "ia32_mlock2":
		return IA32SysMlock2
	case "ia32_copy_file_range":
		return IA32SysCopyFileRange
	case "ia32_compat_preadv2":
		return IA32CompatSysPreadv2
	case "ia32_compat_pwritev2":
		return IA32CompatSysPwritev2
	case "ia32_pkey_mprotect":
		return IA32SysPkeyMprotect
	case "ia32_pkey_alloc":
		return IA32SysPkeyAlloc
	case "ia32_pkey_free":
		return IA32SysPkeyFree
	case "ia32_statx":
		return IA32SysStatx
	case "ia32_compat_arch_prctl":
		return IA32CompatSysArchPrctl
	case "ia32_compat_io_pgetevents":
		return IA32CompatSysIoPgetevents
	case "ia32_rseq":
		return IA32SysRseq
	case "ia32_semget":
		return IA32SysSemget
	case "ia32_compat_semctl":
		return IA32CompatSysSemctl
	case "ia32_shmget":
		return IA32SysShmget
	case "ia32_compat_shmctl":
		return IA32CompatSysShmctl
	case "ia32_compat_shmat":
		return IA32CompatSysShmat
	case "ia32_shmdt":
		return IA32SysShmdt
	case "ia32_msgget":
		return IA32SysMsgget
	case "ia32_compat_msgsnd":
		return IA32CompatSysMsgsnd
	case "ia32_compat_msgrcv":
		return IA32CompatSysMsgrcv
	case "ia32_compat_msgctl":
		return IA32CompatSysMsgctl
	case "ia32_clock_gettime":
		return IA32SysClockGettime
	case "ia32_clock_settime":
		return IA32SysClockSettime
	case "ia32_clock_adjtime":
		return IA32SysClockAdjtime
	case "ia32_clock_getres":
		return IA32SysClockGetres
	case "ia32_clock_nanosleep":
		return IA32SysClockNanosleep
	case "ia32_timer_gettime":
		return IA32SysTimerGettime
	case "ia32_timer_settime":
		return IA32SysTimerSettime
	case "ia32_timerfd_gettime":
		return IA32SysTimerfdGettime
	case "ia32_timerfd_settime":
		return IA32SysTimerfdSettime
	case "ia32_utimensat":
		return IA32SysUtimensat
	case "ia32_compat_pselect6_time64":
		return IA32CompatSysPselect6Time64
	case "ia32_compat_ppoll_time64":
		return IA32CompatSysPpollTime64
	case "ia32_io_pgetevents":
		return IA32SysIoPgetevents
	case "ia32_compat_recvmmsg_time64":
		return IA32CompatSysRecvmmsgTime64
	case "ia32_mq_timedsend":
		return IA32SysMqTimedsend
	case "ia32_mq_timedreceive":
		return IA32SysMqTimedreceive
	case "ia32_semtimedop":
		return IA32SysSemtimedop
	case "ia32_compat_rt_sigtimedwait_time64":
		return IA32CompatSysRtSigtimedwaitTime64
	case "ia32_futex":
		return IA32SysFutex
	case "ia32_sched_rr_get_interval":
		return IA32SysSchedRrGetInterval
	case "ia32_pidfd_send_signal":
		return IA32SysPidfdSendSignal
	case "ia32_io_uring_setup":
		return IA32SysIoUringSetup
	case "ia32_io_uring_enter":
		return IA32SysIoUringEnter
	case "ia32_io_uring_register":
		return IA32SysIoUringRegister
	case "ia32_open_tree":
		return IA32SysOpenTree
	case "ia32_move_mount":
		return IA32SysMoveMount
	case "ia32_fsopen":
		return IA32SysFsopen
	case "ia32_fsconfig":
		return IA32SysFsconfig
	case "ia32_fsmount":
		return IA32SysFsmount
	case "ia32_fspick":
		return IA32SysFspick
	case "ia32_pidfd_open":
		return IA32SysPidfdOpen
	case "ia32_clone3":
		return IA32SysClone3
	case "ia32_close_range":
		return IA32SysCloseRange
	case "ia32_openat2":
		return IA32SysOpenat2
	case "ia32_pidfd_getfd":
		return IA32SysPidfdGetfd
	case "ia32_faccessat2":
		return IA32SysFaccessat2
	case "ia32_process_madvise":
		return IA32SysProcessMadvise
	case "ia32_compat_epoll_pwait2":
		return IA32CompatSysEpollPwait2
	case "ia32_mount_setattr":
		return IA32SysMountSetattr
	case "ia32_quotactl_fd":
		return IA32SysQuotactlFd
	case "ia32_landlock_create_ruleset":
		return IA32SysLandlockCreateRuleset
	case "ia32_landlock_add_rule":
		return IA32SysLandlockAddRule
	case "ia32_landlock_restrict_self":
		return IA32SysLandlockRestrictSelf
	case "ia32_memfd_secret":
		return IA32SysMemfdSecret
	case "ia32_process_mrelease":
		return IA32SysProcessMrelease
	case "ia32_futex_waitv":
		return IA32SysFutexWaitv
	case "ia32_set_mempolicy_home_node":
		return IA32SysSetMempolicyHomeNode
	default:
		if strings.HasPrefix(name, "new") {
			return ParseIA32SyscallName(strings.TrimPrefix(name, "new"))
		}
		if strings.HasSuffix(name, "64") {
			return ParseIA32SyscallName(strings.TrimSuffix(name, "64"))
		}
		return -1
	}
}
