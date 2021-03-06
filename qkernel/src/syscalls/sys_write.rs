// Copyright (c) 2021 QuarkSoft LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.


use super::super::kernel::waiter::*;
use super::super::kernel::timer::*;
use super::super::kernel::time::*;
use super::super::fs::file::*;
use super::super::task::*;
use super::super::qlib::common::*;
use super::super::qlib::linux_def::*;
use super::super::syscalls::syscalls::*;
use super::super::perflog::*;

pub fn SysWrite(task: &mut Task, args: &SyscallArguments) -> Result<i64> {
    let fd = args.arg0 as i32;
    let addr = args.arg1 as u64;
    let size = args.arg2 as i64;

    let n = Write(task, fd, addr, size)?;
    task.ioUsage.AccountWriteSyscall(n);
    return Ok(n);
}

pub fn Write(task: &Task, fd: i32, addr: u64, size: i64) -> Result<i64> {
    //task.PerfGoto(PerfType::Write);
    //defer!(task.PerfGofrom(PerfType::Write));

    if fd == 2 {
         use alloc::string::ToString;
         use super::super::util::cstring::*;

         let str = CString::ToStringWithLen(task, addr, size as usize)?.to_string();
         info!("(Data) Write: {}", str);
    }

    let file = task.GetFile(fd)?;

    if !file.Flags().Write {
        return Err(Error::SysError(SysErr::EBADF))
    }

    if size < 0 {
        return Err(Error::SysError(SysErr::EINVAL))
    }

    if size == 0 {
        return Ok(0)
    }

    let iov = IoVec::NewFromAddr(addr, size as usize);
    let iovs: [IoVec; 1] = [iov];

    return writev(task, &file, &iovs);
}

pub fn SysPwrite64(task: &mut Task, args: &SyscallArguments) -> Result<i64> {
    let fd = args.arg0 as i32;
    let addr = args.arg1 as u64;
    let size = args.arg2 as i64;
    let offset = args.arg3 as i64;

    let n = Pwrite64(task, fd, addr, size, offset)?;
    task.ioUsage.AccountWriteSyscall(n);
    return Ok(n);
}

pub fn Pwrite64(task: &Task, fd: i32, addr: u64, size: i64, offset: i64) -> Result<i64> {
    task.PerfGoto(PerfType::Write);
    defer!(task.PerfGofrom(PerfType::Write));

    let file = task.GetFile(fd)?;

    if offset < 0 {
        return Err(Error::SysError(SysErr::EINVAL))
    }

    if !file.Flags().PWrite {
        return Err(Error::SysError(SysErr::ESPIPE))
    }

    if !file.Flags().Write {
        return Err(Error::SysError(SysErr::EBADF))
    }

    if size < 0 {
        return Err(Error::SysError(SysErr::EINVAL))
    }

    if size == 0 {
        return Ok(0)
    }

    let iov = IoVec::NewFromAddr(addr, size as usize);
    let iovs: [IoVec; 1] = [iov];

    return pwritev(task, &file, &iovs, offset);
}

pub fn SysWritev(task: &mut Task, args: &SyscallArguments) -> Result<i64> {
    let fd = args.arg0 as i32;
    let addr = args.arg1 as u64;
    let iovcnt = args.arg2 as i32;

    if fd < 3 {
        use alloc::string::ToString;
        use super::super::util::cstring::*;

        let srcs = task.IovsFromAddr(addr, iovcnt as usize)?;

        for i in 0..srcs.len() {
            let str = CString::ToStringWithLen(task, srcs[i].start, srcs[i].len as usize)?.to_string();
            info!("Write: {}", str);
        }
    }

    let n = Writev(task, fd, addr, iovcnt)?;
    task.ioUsage.AccountWriteSyscall(n);
    return Ok(n);
}

pub fn Writev(task: &Task, fd: i32, addr: u64, iovcnt: i32) -> Result<i64> {
    let file = task.GetFile(fd)?;


    if !file.Flags().Write {
        return Err(Error::SysError(SysErr::EBADF))
    }

    if iovcnt < 0 {
        return Err(Error::SysError(SysErr::EINVAL))
    }

    if iovcnt == 0 {
        return Ok(0)
    }

    let srcs = task.IovsFromAddr(addr, iovcnt as usize)?;
    return writev(task, &file, srcs);
}

pub fn SysPwritev(task: &mut Task, args: &SyscallArguments) -> Result<i64> {
    let fd = args.arg0 as i32;
    let addr = args.arg1 as u64;
    let iovcnt = args.arg2 as i32;
    let offset = args.arg3 as i64;

    let n = Pwritev(task, fd, addr, iovcnt, offset)?;
    task.ioUsage.AccountWriteSyscall(n);
    return Ok(n);
}

pub fn Pwritev(task: &Task, fd: i32, addr: u64, iovcnt: i32, offset: i64) -> Result<i64> {
    let file = task.GetFile(fd)?;

    if offset < 0 {
        return Err(Error::SysError(SysErr::EINVAL))
    }

    if !file.Flags().PWrite {
        return Err(Error::SysError(SysErr::ESPIPE))
    }

    if !file.Flags().Write {
        return Err(Error::SysError(SysErr::EBADF))
    }

    if iovcnt < 0 {
        return Err(Error::SysError(SysErr::EINVAL))
    }

    if iovcnt == 0 {
        return Ok(0)
    }

    let srcs = task.IovsFromAddr(addr, iovcnt as usize)?;
    return pwritev(task, &file, srcs, offset);
}

fn writev(task: &Task, f: &File, srcs: &[IoVec]) -> Result<i64> {
    task.CheckIOVecPermission(srcs, false)?;
    match f.Writev(task, srcs) {
        Err(e) => {
            if e != Error::SysError(SysErr::EWOULDBLOCK) || f.Flags().NonBlocking {
                return Err(e);
            }
        }
        Ok(n) => {
            return Ok(n)
        }
    };

    let mut deadline = None;

    let dl = f.FileOp.SendTimeout();
    if dl < 0 {
        return Err(Error::SysError(SysErr::EWOULDBLOCK));
    }

    if dl > 0 {
        let now = MonotonicNow();
        deadline = Some(Time(now + dl));
    }

    let general = task.blocker.generalEntry.clone();

    f.EventRegister(task, &general, EVENT_WRITE);
    defer!(f.EventUnregister(task, &general));

    loop {
        match f.Writev(task, srcs) {
            Err(Error::SysError(SysErr::EWOULDBLOCK)) => (),
            Err(e) => {
                return Err(e);
            }
            Ok(n) => {
                return Ok(n);
            }
        }

        match task.blocker.BlockWithMonoTimer(true, deadline) {
            Err(e) => {
                return Err(e);
            }
            _ => ()
        }
    }
}

fn pwritev(task: &Task, f: &File, srcs: &[IoVec], offset: i64) -> Result<i64> {
    task.CheckIOVecPermission(srcs, false)?;
    match f.Pwritev(task, srcs, offset) {
        Err(e) => {
            if e != Error::SysError(SysErr::EWOULDBLOCK) || f.Flags().NonBlocking {
                return Err(e);
            }
        }
        Ok(n) => {
            return Ok(n)
        }
    };

    let general = task.blocker.generalEntry.clone();

    f.EventRegister(task, &general, EVENT_WRITE);
    defer!(f.EventUnregister(task, &general));

    loop {
        match f.Pwritev(task, srcs, offset) {
            Err(Error::SysError(SysErr::EWOULDBLOCK)) => (),
            Err(e) => {
                return Err(e);
            }
            Ok(n) => {
                return Ok(n);
            }
        }

        match task.blocker.BlockWithMonoTimer(true, None) {
            Err(e) => {
                return Err(e);
            }
            _ => ()
        }
    }
}