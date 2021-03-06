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

use alloc::vec::Vec;
use alloc::collections::vec_deque::VecDeque;
use core::marker::Send;
use spin::Mutex;
use core::ops::Deref;

use super::super::qlib::linux_def::*;
use super::super::fs::file::*;
use super::super::qlib::uring::squeue;
use super::super::qlib::uring::opcode::*;
use super::super::qlib::uring::opcode;
use super::super::BUF_MGR;
use super::super::socket::hostinet::socket::*;
use super::super::IOURING;
use super::super::kernel::timer;

#[repr(align(128))]
pub enum AsyncOps {
    AsyncTimeout(AsyncTimeout),
    AsyncTTTYWrite(AsyncTTTYWrite),
    AsyncWrite(AsyncWritev),
    AsyncEventfdWrite(AsyncEventfdWrite),
    AsycnSendMsg(AsycnSendMsg),
    AsycnRecvMsg(AsycnRecvMsg),
    AsyncSocketSend(AsyncSocketSend),
    AsyncSocketRecv(AsyncSocketRecv),
    None,
}

impl AsyncOps {
    pub fn SEntry(&self) -> squeue::Entry {
        match self {
            AsyncOps::AsyncTimeout(ref msg) => return msg.SEntry(),
            AsyncOps::AsyncTTTYWrite(ref msg) => return msg.SEntry(),
            AsyncOps::AsyncWrite(ref msg) => return msg.SEntry(),
            AsyncOps::AsyncEventfdWrite(ref msg) => return msg.SEntry(),
            AsyncOps::AsycnSendMsg(ref msg) => return msg.SEntry(),
            AsyncOps::AsycnRecvMsg(ref msg) => return msg.SEntry(),
            AsyncOps::AsyncSocketSend(ref msg) => return msg.SEntry(),
            AsyncOps::AsyncSocketRecv(ref msg) => return msg.SEntry(),
            AsyncOps::None => ()
        };

        panic!("AsyncOps::None SEntry fail")
    }

    pub fn Process(mut self, result: i32) {
        let ret = match &mut self {
            AsyncOps::AsyncTimeout(ref mut msg) => msg.Process(result),
            AsyncOps::AsyncTTTYWrite(ref mut msg) => msg.Process(result),
            AsyncOps::AsyncWrite(ref mut msg) => msg.Process(result),
            AsyncOps::AsyncEventfdWrite(ref mut msg) => msg.Process(result),
            AsyncOps::AsycnSendMsg(ref mut msg) => msg.Process(result),
            AsyncOps::AsycnRecvMsg(ref mut msg) => msg.Process(result),
            AsyncOps::AsyncSocketSend(ref mut msg) => msg.Process(result),
            AsyncOps::AsyncSocketRecv(ref mut msg) => msg.Process(result),
            AsyncOps::None => panic!("AsyncOps::None SEntry fail"),
        };

        if ret {
            IOURING.AUCall(self);
        }
    }

    pub fn Type(&self) -> usize {
        match self {
            AsyncOps::AsyncTimeout(_) => return 1,
            AsyncOps::AsyncTTTYWrite(_) => return 2,
            AsyncOps::AsyncWrite(_) => return 3,
            AsyncOps::AsyncEventfdWrite(_) => return 4,
            AsyncOps::AsycnSendMsg(_) => return 5,
            AsyncOps::AsycnRecvMsg(_) => return 6,
            AsyncOps::AsyncSocketSend(_) => return 7,
            AsyncOps::AsyncSocketRecv(_) => return 8,
            AsyncOps::None => ()
        };

        return 0;
    }
}

#[derive(Default)]
pub struct UringAsyncMgr {
    pub ops: Vec<Option<AsyncOps>>,
    pub ids: VecDeque<u16>,
}

unsafe impl Sync for UringAsyncMgr {}
unsafe impl Send for UringAsyncMgr {}

impl UringAsyncMgr {
    pub fn New(size: usize) -> Self {
        let mut ids = VecDeque::with_capacity(size);
        let mut ops = Vec::with_capacity(size);
        for i in 0..size {
            ids.push_back(i as u16);
            ops.push(None);
        }
        return Self {
            ops: ops,
            ids: ids,
        }
    }

    pub fn AllocSlot(&mut self) -> Option<usize> {
        match self.ids.pop_front() {
            None => None,
            Some(id) => Some(id as usize),
        }
    }

    pub fn SetOps(&mut self, id : usize, ops: AsyncOps) -> squeue::Entry {
        self.ops[id] = Some(ops);
        return self.ops[id]
            .as_ref().unwrap()
            .SEntry()
            .user_data(id as u64);
    }

    pub fn GetOps(&mut self, id: usize) -> AsyncOps {
        let ops = self.ops[id].take().expect("UringAsyncMgr::GetOps fail");
        self.ids.push_back(id as u16);
        return ops;
    }
}

pub struct AsyncEventfdWrite {
    pub fd: i32,
    pub addr: u64,
}

impl AsyncEventfdWrite {
    pub fn New(fd: i32, addr: u64) -> Self {
        return Self {
            fd: fd,
            addr: addr,
        }
    }

    pub fn SEntry(&self) -> squeue::Entry {
        let op = Write::new(types::Fd(self.fd), self.addr as * const u8, 8);
        return op.build()
            .flags(squeue::Flags::FIXED_FILE);
    }

    pub fn Process(&mut self, _result: i32) -> bool {
        return false
    }
}

#[derive(Debug)]
pub struct AsyncTimeout {
    pub timerId: u64,
    pub seqNo: u64,
    pub ts: types::Timespec,
}

impl AsyncTimeout {
    pub fn New(timerId: u64, seqNo: u64, ns: i64) -> Self {
        return Self {
            timerId: timerId,
            seqNo: seqNo,
            ts: types::Timespec {
                tv_sec: ns / 1000_000_000,
                tv_nsec: ns % 1000_000_000,
            },
        }
    }

    pub fn SEntry(&self) -> squeue::Entry {
        let op = Timeout::new(&self.ts);
        return op.build();
    }

    pub fn Process(&mut self, result: i32) -> bool {
        if result == -SysErr::ETIME {
            timer::FireTimer(self.timerId, self.seqNo);
        }

        return false
    }
}

pub struct AsyncTTTYWrite {
    pub file: File,
    pub fd: i32,
    pub addr: u64,
    pub len: usize,
}

impl AsyncTTTYWrite {
    pub fn New(file: &File, fd: i32, addr: u64, len: usize) -> Self {
        return Self {
            file: file.clone(),
            fd: fd,
            addr: addr,
            len: len,
        }
    }

    pub fn SEntry(&self) -> squeue::Entry {
        let op = Write::new(types::Fd(self.fd), self.addr as * const _, self.len as u32);

        return op.build()
            .flags(squeue::Flags::FIXED_FILE);
    }

    pub fn Process(&mut self, _result: i32) -> bool {
        //error!("AsyncWrite::Process result is {}", result);
        return false
    }
}

pub struct AsyncWritev {
    pub file: File,
    pub fd: i32,
    pub iov: IoVec,
    pub offset: i64,
}

impl AsyncWritev {
    pub fn New(file: &File, fd: i32, addr: u64, len: usize, offset: i64) -> Self {
        return Self {
            file: file.clone(),
            fd: fd,
            iov: IoVec::NewFromAddr(addr, len),
            offset: offset,
        }
    }

    pub fn SEntry(&self) -> squeue::Entry {
        let op = Writev::new(types::Fd(self.fd), &self.iov as * const _ as * const u64, 1)
            .offset(self.offset);

        return op.build()
            .flags(squeue::Flags::FIXED_FILE);
    }

    pub fn Process(&mut self, _result: i32) -> bool {
        BUF_MGR.Free(self.iov.start, self.iov.len as u64);
        return false
    }
}

pub struct AsyncSocketSend {
    pub fd : i32,
    pub ops: SocketOperations,
    pub addr: u64,
    pub len: usize,
}

impl AsyncSocketSend {
    pub fn SEntry(&self) -> squeue::Entry {
        //let op = Write::new(types::Fd(self.fd), self.addr as * const u8, self.len as u32);
        let op = opcode::Send::new(types::Fd(self.fd), self.addr as * const u8, self.len as u32); //.flags(MsgType::MSG_DONTWAIT);

        return op.build()
            .flags(squeue::Flags::FIXED_FILE);
    }

    pub fn Process(&mut self, result: i32) -> bool {
        let buf = self.ops.SocketBuf();
        if result < 0 {
            buf.SetErr(-result);
            self.ops.Notify(EVENT_ERR | EVENT_IN);
            return false;
            //return true;
        }

        let (trigger, addr, len) = buf.ConsumeAndGetAvailableWriteBuf(result as usize);
        if trigger {
            self.ops.Notify(EVENT_OUT);
        }

        if addr == 0 {
            return false;
        }

        self.addr = addr;
        self.len = len;

        return true
    }

    pub fn New(fd: i32, ops: SocketOperations, addr: u64, len: usize) -> Self {
        return Self {
            fd,
            ops,
            addr,
            len,
        }
    }
}

pub struct AsyncSocketRecv {
    pub fd : i32,
    pub ops: SocketOperations,
    pub addr: u64,
    pub len: usize,
}

impl AsyncSocketRecv {
    pub fn SEntry(&self) -> squeue::Entry {
        let op = Recv::new(types::Fd(self.fd), self.addr as * mut u8, self.len as u32);

        return op.build()
            .flags(squeue::Flags::FIXED_FILE);
    }

    pub fn Process(&mut self, result: i32) -> bool {
        let buf = self.ops.SocketBuf();
        if result < 0 {
            buf.SetErr(-result);
            self.ops.Notify(EVENT_ERR | EVENT_IN);
            return false;
        }

        // EOF
        if result == 0 {
            buf.SetClosed();
            if buf.ProduceReadBuf(0) {
                self.ops.Notify(EVENT_IN);
            } else {
                self.ops.Notify(EVENT_HUP);
            }
            return false
        }

        let (trigger, addr, len) = buf.ProduceAndGetFreeReadBuf(result as usize);
        if trigger {
            self.ops.Notify(EVENT_IN);
        }

        if len == 0 {
            return false;
        }

        self.addr = addr;
        self.len = len;
        return true;
    }

    pub fn New(fd: i32, ops: SocketOperations, addr: u64, len: usize) -> Self {
        return Self {
            fd,
            ops,
            addr,
            len,
        }
    }
}

pub struct AsycnSendMsgIntern {
    pub fd : i32,
    pub ops: SocketOperations,
    pub remoteAddr: Vec<u8>,
    pub msg: MsgHdr,
}

pub struct AsycnSendMsg(Mutex<AsycnSendMsgIntern>);

impl Deref for AsycnSendMsg {
    type Target = Mutex<AsycnSendMsgIntern>;

    fn deref(&self) -> &Mutex<AsycnSendMsgIntern> {
        &self.0
    }
}

impl AsycnSendMsg {
    pub fn SEntry(&self) -> squeue::Entry {
        let intern = self.lock();
        let op = SendMsg::new(types::Fd(intern.fd), &intern.msg as * const _ as * const u64);

        return op.build()
            .flags(squeue::Flags::FIXED_FILE);
    }

    pub fn Process(&mut self, result: i32) -> bool {
        let intern = self.lock();
        let buf = intern.ops.SocketBuf();
        if result < 0 {
            buf.SetErr(-result);
            intern.ops.Notify(EVENT_ERR | EVENT_IN);
            return false;
        }

        // EOF
        /*if result == 0 {
            buf.SetClosed();

            if buf.ConsumeWriteBuf(0) {
                intern.ops.Notify(EVENT_HUP);
            }
            return
        }*/

        if buf.ConsumeWriteBuf(result as usize) {
            intern.ops.Notify(EVENT_OUT);
        }

        let (addr, cnt) = intern.ops.SocketBuf().GetAvailableWriteIovs();
        if cnt == 0 {
            return false;
        }

        //let sendMsgOp = AsycnSendMsg::New(intern.fd, &intern.ops);
        self.lock().SetIovs(addr, cnt);

        return true
    }

    pub fn New(fd: i32, ops: &SocketOperations) -> Self {
        let intern = AsycnSendMsgIntern::New(fd, ops);
        return Self(Mutex::new(intern))
    }
}

impl AsycnSendMsgIntern {
    pub fn New(fd: i32, ops: &SocketOperations) -> Self {
        return Self {
            fd: fd,
            ops: ops.clone(),
            remoteAddr: ops.GetRemoteAddr().unwrap(),
            msg: MsgHdr::default(),
        }
    }

    pub fn SetIovs(&mut self, addr: u64, cnt: usize) {
        self.msg.iov = addr;
        self.msg.iovLen = cnt;
        self.msg.msgName =  &self.remoteAddr[0] as * const _ as u64;
        self.msg.nameLen =  self.remoteAddr.len() as u32;
    }
}

pub struct AsycnRecvMsgIntern {
    pub fd : i32,
    pub ops: SocketOperations,
    pub remoteAddr: Vec<u8>,
    pub msg: MsgHdr,
}

pub struct AsycnRecvMsg(Mutex<AsycnRecvMsgIntern>);

impl Deref for AsycnRecvMsg {
    type Target = Mutex<AsycnRecvMsgIntern>;

    fn deref(&self) -> &Mutex<AsycnRecvMsgIntern> {
        &self.0
    }
}

impl AsycnRecvMsg {
    pub fn SEntry(&self) -> squeue::Entry {
        let intern = self.lock();
        let op = RecvMsg::new(types::Fd(intern.fd), &intern.msg as * const _ as * const u64);

        return op.build()
            .flags(squeue::Flags::FIXED_FILE);
    }

    pub fn Process(&mut self, result: i32) -> bool {
        let intern = self.lock();
        let buf = intern.ops.SocketBuf();
        if result < 0 {
            buf.SetErr(-result);
            intern.ops.Notify(EVENT_ERR | EVENT_IN);
            return false;
        }

        // EOF
        if result == 0 {
            buf.SetClosed();
            if buf.ProduceReadBuf(0) {
                intern.ops.Notify(EVENT_IN);
            }
            return false
        }

        if buf.ProduceReadBuf(result as usize) {
            intern.ops.Notify(EVENT_IN);
        }

        //let recvMsgOp = AsycnRecvMsg::New(intern.fd, &intern.ops);
        let (addr, cnt) = intern.ops.SocketBuf().GetFreeReadIovs();
        self.lock().SetIovs(addr, cnt);

        return true
    }
}

impl AsycnRecvMsg {
    pub fn New(fd: i32, ops: &SocketOperations) -> Self {
        let intern = AsycnRecvMsgIntern::New(fd, ops);
        return Self(Mutex::new(intern))
    }
}

impl AsycnRecvMsgIntern {
    pub fn New(fd: i32, ops: &SocketOperations) -> Self {
        let ret = Self {
            fd: fd,
            remoteAddr: ops.GetRemoteAddr().unwrap(),
            ops: ops.clone(),
            msg: MsgHdr::default(),
        };

        return ret;
    }

    pub fn SetIovs(&mut self, addr: u64, cnt: usize) {
        self.msg.iov = addr;
        self.msg.iovLen = cnt;
        self.msg.msgName =  &self.remoteAddr[0] as * const _ as u64;
        self.msg.nameLen =  self.remoteAddr.len() as u32;
    }
}