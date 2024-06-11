// Copyright (c)  2021 The Enarx Authors.
// Original code source: https://github.com/enarx/enarx
// Code modifier: yaoxin jing
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

use spin::Mutex;
use crate::MemoryDef;



lazy_static! {
    pub static ref SECRETS: Mutex<SecretsHandle<'static>> = SecretsHandle::init();
}

/// The SEV-SNP secrets page OS area
///
/// The secrets page contains 96-bytes of reserved field that can be used by
/// the guest OS. The guest OS uses the area to save the message sequence
/// number for each VMPL level.
///
/// See the GHCB spec section Secret page layout for the format for this area.
#[repr(C)]
#[derive(Debug)]
pub struct SecretsOsArea {
    /// Message Sequence Number using
    /// Virtual Machine Private Communication Key 0
    pub msg_seqno_0: u32,
    /// Message Sequence Number using
    /// Virtual Machine Private Communication Key 1
    pub msg_seqno_1: u32,
    /// Message Sequence Number using
    /// Virtual Machine Private Communication Key 2
    pub msg_seqno_2: u32,
    /// Message Sequence Number using
    /// Virtual Machine Private Communication Key 3
    pub msg_seqno_3: u32,
    /// AP jump table in physical addresses
    pub ap_jump_table_pa: u64,
    rsvd: [u8; 40],
    /// Free for guest usage
    pub guest_usage: [u8; 32],
}

/// Virtual Machine Private Communication Key Length
pub const VMPCK_KEY_LEN: usize = 32;

/// The SEV-SNP secrets page
///
/// See the SNP spec secrets page layout section for the structure
#[derive(Debug)]
#[repr(C, align(4096))]
pub struct SnpSecretsPage {
    /// Version
    pub version: u32,
    /// Indicates that an IMI is used to migrate the guest
    pub imi_en: u32,
    /// Family, model, and stepping information as reported in CPUID Fn0000_0001_EAX
    pub fms: u32,
    reserved2: u32,
    /// Guest OS visible workarounds as provided by the HV in SNP_LAUNCH_START
    pub gosvw: [u8; 16],
    /// Virtual Machine Private Communication Key for VMPL 0
    pub vmpck0: [u8; VMPCK_KEY_LEN],
    /// Virtual Machine Private Communication Key for VMPL 1
    pub vmpck1: [u8; VMPCK_KEY_LEN],
    /// Virtual Machine Private Communication Key for VMPL 2
    pub vmpck2: [u8; VMPCK_KEY_LEN],
    /// Virtual Machine Private Communication Key for VMPL 3
    pub vmpck3: [u8; VMPCK_KEY_LEN],
    /// Area mutable for the Guest OS
    pub os_area: SecretsOsArea,
    reserved3: [u8; 3840],
}


/// A handle to the Secrets page
pub struct SecretsHandle<'a> {
    secrets: &'a mut SnpSecretsPage,
}


impl SecretsHandle<'_> {

    pub fn init() -> Mutex<SecretsHandle<'static>> {
        unsafe {
            let secrets = MemoryDef::SECRET_PAGE as *mut SnpSecretsPage;
            Mutex::<SecretsHandle<'_>>::new(SecretsHandle {
                secrets: &mut *secrets,
            })
        }
    }


    /// get VM private communication key for VMPL0
    pub fn get_vmpck0(&self) -> [u8; VMPCK_KEY_LEN] {

        info!("get_vmpck0 {:?}", self.secrets);
        self.secrets.vmpck0
    }

    /// get message sequence number for VM private communication key for VMPL0
    pub fn get_msg_seqno_0(&mut self) -> u32 {
        self.secrets.os_area.msg_seqno_0.checked_add(1).unwrap()
    }

    /// increase message sequence number for VM private communication key for VMPL0
    pub fn inc_msg_seqno_0(&mut self) {
        self.secrets.os_area.msg_seqno_0 = self.secrets.os_area.msg_seqno_0.checked_add(2).unwrap();
    }
}