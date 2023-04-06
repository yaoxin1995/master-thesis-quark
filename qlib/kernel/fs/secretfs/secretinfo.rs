// Copyright (c) 2021 Quark Container Authors / 2018 The gVisor Authors.
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

use crate::qlib::mutex::*;
use alloc::sync::Arc;

use super::super::attr::*;
use super::super::dirent::*;
use super::super::file::*;
use super::super::flags::*;
use super::super::inode::*;
use super::super::mount::*;
//use super::super::super::super::linux::time::*;
use super::super::super::super::auth::*;
use super::super::super::super::common::*;
use super::super::super::super::linux_def::*;
use super::super::super::task::*;
use super::super::super::Kernel::HostSpace;
use super::super::fsutil::file::readonly_file::*;
use super::super::fsutil::inode::simple_file_inode::*;
use super::inode::*;
use crate::shield::secret_injection::SECRET_KEEPER;

#[derive(Clone)]
pub struct SecretInfoFileNode {}

impl ReadonlyFileNodeTrait for SecretInfoFileNode {
    fn ReadAt(
        &self,
        task: &Task,
        f: &File,
        dsts: &mut [IoVec],
        offset: i64,
        _blocking: bool,
    ) -> Result<i64> {
        if offset < 0 {
            return Err(Error::SysError(SysErr::EINVAL));
        }

        info!("ReadonlyFileNodeTrait for SecretInfoFileNode inode id {:?}  file name {:?}", f.Dirent.inode.ID(), f.Dirent.Name());

        let mut info: LibcSysinfo = LibcSysinfo::default();

        let ret = HostSpace::Sysinfo(&mut info as *mut _ as u64);
        if ret < 0 {
            return Err(Error::SysError(-ret as i32));
        }


    

        let file_name = f.Dirent.Name();
        let secret_keeper = SECRET_KEEPER.read();
        let secret_content = secret_keeper.file_secrets.get(&file_name);
        if secret_content.is_none() {
            info!("ReadonlyFileNodeTrait read, failed to get secret file content for secret keeper");
            return Err(Error::NotSupport);
        }

        // let mut s = "".to_string();
        // this is just fake meminfo
        // todo: fix this.
        // s += &format!("secret template1:       {:>8} kB\n", info.totalram / 1024);
        // s += &format!("secret template2        {:>8} kB\n", info.freeram / 1024);
        // s += &format!("secret template3   {:>8} kB\n", info.totalram / 5 * 3 / 1024);
        // s += &format!("Buffers:        {:>8} kB\n", info.bufferram / 1024); // memory usage by block devices
        // s += &format!("Cached:         {:>8} kB\n", info.totalram / 100 / 1024);
        // // Emulate a system with no swap, which disables inactivation of anon pages.
        // s += &format!("SwapCache:             0 kB\n");
        // s += &format!("Active:         {:>8} kB\n", info.totalram / 100 / 1024);
        // s += &format!("Inactive:       {:>8} kB\n", info.totalram / 100 / 1024);
        // s += &format!("Active(anon):   {:>8} kB\n", info.totalram / 100 / 1024);
        // s += &format!("Inactive(anon):        0 kB\n");
        // s += &format!("Active(file):   {:>8} kB\n", info.totalram / 100 / 1024);
        // s += &format!("Inactive(file): {:>8} kB\n", info.totalram / 100 / 1024);
        // s += &format!("Unevictable:           0 kB\n");
        // s += &format!("Mlocked:               0 kB\n");
        // s += &format!("SwapTotal:             0 kB\n");
        // s += &format!("SwapFree:              0 kB\n");
        // s += &format!("Dirty:                 0 kB\n");
        // s += &format!("Writeback:             0 kB\n");
        // s += &format!("AnonPages:      {:>8} kB\n", info.totalram / 100 / 1024);
        // s += &format!("Mapped:         {:>8} kB\n", info.totalram / 100 / 1024);
        // s += &format!("Shmem:                 0 kB\n");

        let bytes = secret_content.unwrap().as_slice();
        if offset as usize > bytes.len() {
            return Ok(0);
        }

        let n = task.CopyDataOutToIovs(&bytes[offset as usize..], dsts, true)?;

        return Ok(n as i64);
    }
}

pub struct SecretinfoInode {}

impl SimpleFileTrait for SecretinfoInode {
    fn GetFile(
        &self,
        _task: &Task,
        _dir: &Inode,
        dirent: &Dirent,
        flags: FileFlags,
    ) -> Result<File> {
        let fops = ReadonlyFileOperations {
            node: SecretInfoFileNode {}.into(),
        };

        let file = File::New(dirent, &flags, fops.into());
        return Ok(file);
    }
}

pub fn NewSecinfo(task: &Task, msrc: &Arc<QMutex<MountSource>>) -> Inode {
    let node = SimpleFileInode::New(
        task,
        &ROOT_OWNER,
        &FilePermissions {
            User: PermMask {
                read: true,
                write: false,
                execute: false,
            },
            Group: PermMask {
                read: true,
                write: false,
                execute: false,
            },
            Other: PermMask {
                read: true,
                write: false,
                execute: false,
            },
            ..Default::default()
        },
        FSMagic::ANON_INODE_FS_MAGIC,
        false,
        SecretinfoInode {}.into(),
    );

    return NewSecretInode(node.into(), msrc, InodeType::SpecialFile, None);
}
