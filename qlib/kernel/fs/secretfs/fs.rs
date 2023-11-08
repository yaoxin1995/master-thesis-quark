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
use alloc::collections::btree_map::BTreeMap;
use alloc::string::String;
use alloc::string::ToString;
use alloc::sync::Arc;

use super::super::super::super::common::*;
use super::super::super::task::*;
use super::super::filesystems::*;
use super::super::host::fs::*;
use super::super::inode::*;
use super::super::mount::*;
use super::proc::*;

pub struct SecretFileSystem {}

impl Filesystem for SecretFileSystem {
    fn Name(&self) -> String {
        return "secret".to_string();
    }

    fn Flags(&self) -> FilesystemFlags {
        return 0;
    }

    fn Mount(
        &mut self,
        task: &Task,
        _device: &str,
        flags: &MountSourceFlags,
        data: &str,
    ) -> Result<Inode> {
        info!("secret file system mount ...");

        // Parse generic comma-separated key=value options, this file system expects them.
        let options = WhitelistFileSystem::GenericMountSourceOptions(data);

        // Proc options parsing checks for either a gid= or hidepid= and barfs on
        // anything else, see fs/proc/root.c:proc_parse_options. Since we don't know
        // what to do with gid= or hidepid=, we blow up if we get any options.
        if options.len() > 0 {
            return Err(Error::Common(format!(
                "unsupported mount options: {:?}",
                &options
            )));
        }

        let cgroups = BTreeMap::new();

        let msrc = MountSource::NewCachingMountSource(self, flags);
        let inode = NewSecret(task, &Arc::new(QMutex::new(msrc)), cgroups);
        return Ok(inode);
    }

    fn AllowUserMount(&self) -> bool {
        return true;
    }

    fn AllowUserList(&self) -> bool {
        return true;
    }
}
