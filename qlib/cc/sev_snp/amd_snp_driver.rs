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
use aes_gcm::{AeadInPlace, Aes256Gcm, KeyInit, Nonce, Tag};
use core::mem::size_of;
use crate::qlib::cc::sev_snp::ghcb::GhcbHandle;
use x86_64::{PhysAddr, VirtAddr};
use crate::qlib::linux_def::*;
use crate::qlib::kernel::Kernel_cc::LOG_AVAILABLE;
use crate::qlib::cc::sev_snp::ghcb::GHCB;
use bitflags::bitflags;
use crate::qlib::cc::sev_snp::snp_active;
use core::ffi::c_int;
use alloc::slice;
use core::mem::align_of;
use super::secret_page::*;
use super::racycell::*;
pub const TECH: usize = 1;


const SNP_GUEST_MSG_PAYLOAD_LEN: usize = 4000;
// Maximum length of an attestation report
pub const SNP_ATTESTATION_LEN_MAX: usize = SNP_GUEST_MSG_PAYLOAD_LEN;


#[derive(Copy, Clone, PartialEq)]
#[repr(u8)]
#[non_exhaustive]
enum SnpMsgType {
    /*
       TypeInvalid = 0,
       CpuidReq,
       CpuidRsp,
    */
    KeyReq = 3,
    KeyRsp = 4,
    ReportReq = 5,
    ReportRsp = 6,
    /*
       ExportReq,
       ExportRsp,
       ImportReq,
       ImportRsp,
       AbsorbReq,
       AbsorbRsp,
       VmrkReq,
       VmrkRsp,
    */
}

#[derive(Copy, Clone)]
#[repr(u8)]
#[non_exhaustive]
enum AeadAlgo {
    // SnpAeadInvalid = 0,
    SnpAeadAes256Gcm = 1,
}

const MSG_HDR_VER: u8 = 1;

const MAX_AUTHTAG_LEN: usize = 32;

// Header of a SnpGuestMsg
#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct SnpGuestMsgHdr {
    authtag: [u8; MAX_AUTHTAG_LEN],
    msg_seqno: u64,
    rsvd1: [u8; 8],
    pub algo: u8,
    hdr_version: u8,
    hdr_sz: u16,
    msg_type: u8,
    msg_version: u8,
    msg_sz: u16,
    rsvd2: u32,
    msg_vmpck: u8,
    rsvd3: [u8; 35],
}

impl Default for SnpGuestMsgHdr {
    fn default() -> Self {
        SnpGuestMsgHdr {
            authtag: [0u8; MAX_AUTHTAG_LEN],
            msg_seqno: 0u64,
            rsvd1: [0u8; 8],
            algo: 0u8,
            hdr_version: 0u8,
            hdr_sz: 0u16,
            msg_type: 0u8,
            msg_version: 0u8,
            msg_sz: 0u16,
            rsvd2: 0u32,
            msg_vmpck: 0u8,
            rsvd3: [0u8; 35],
        }
    }
}



// GHCB GUEST_REQUEST Message
#[derive(Debug, Copy, Clone)]
#[repr(C, align(4096))]
pub struct SnpGuestMsg {
    pub hdr: SnpGuestMsgHdr,
    payload: [u8; SNP_GUEST_MSG_PAYLOAD_LEN],
}


impl Default for SnpGuestMsg {
    fn default() -> Self {
        SnpGuestMsg {
            hdr: SnpGuestMsgHdr::default(),
            payload: [0u8; SNP_GUEST_MSG_PAYLOAD_LEN],
        }

    }
}

pub fn get_request(addr: u64) -> &'static mut SnpGuestMsg{

    let snpGuestMsgAddr = addr as *mut SnpGuestMsg; // as &mut qlib::Event;
    let msg = unsafe { &mut (*snpGuestMsgAddr) };

    msg
}

/// SnpReport Request
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct SnpReportRequest {
    /// Guest-provided data to be included into the attestation report
    pub report_data: [u8; 64],
    /// VMPL
    pub vmpl: u32,
    rsvd: [u8; 28],
}

impl Default for SnpReportRequest {
    fn default() -> Self {
        SnpReportRequest {
            report_data: [0u8; 64],
            vmpl: 0u32,
            rsvd: [0u8; 28],
        }

    }
}

/// Header of the SnpReport Response
#[repr(C)]
pub struct SnpReportResponseHeader {
    /// 0 if valid
    pub status: u32,
    /// size of the report after this header
    pub size: u32,
    rsvd: [u8; 24],
}


// SAFETY: SnpReportResponseHeader is a C struct with no UD states and pointers.
unsafe impl ByteSized for SnpReportResponseHeader {}

unsafe impl ByteSized for SnpReportRequest {}

pub unsafe trait ByteSized: Sized {
    /// The constant default value.
    const SIZE: usize = size_of::<Self>();

    /// Create Self from a byte slice.
    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != Self::SIZE {
            return None;
        }

        Some(unsafe { (bytes.as_ptr() as *const _ as *const Self).read_unaligned() })
    }

    /// Serialize Self to a byte slice.
    fn as_bytes(&self) -> &[u8] {
        // SAFETY: This is safe because we know that the pointer is non-null and the length is correct
        // and u8 does not need any alignment.
        unsafe { core::slice::from_raw_parts(self as *const _ as *const u8, Self::SIZE) }
    }
}

/// SNP derived key length in bytes
pub const SNP_KEY_LEN: usize = 32;

#[repr(C)]
struct KeyRsp {
    /// 0 if valid
    status: u32,
    _rsvd: [u8; 28],
    derived_key: [u8; SNP_KEY_LEN],
}

#[repr(C)]
struct KeyReq {
    root_key_select: u32,
    _rsvd: u32,
    guest_field_select: u64,
    vmpl: u32,
    guest_svn: u32,
    tcb_version: u64,
}

// SAFETY: KeyRsp is a C struct with no UD states and pointers.
unsafe impl ByteSized for KeyRsp {}
// SAFETY: KeyReq is a C struct with no UD states and pointers.
unsafe impl ByteSized for KeyReq {}


bitflags! {
    /// Indicates which guest-selectable fields will be mixed into the derived key
    #[derive(Default)]
    pub struct GuestFieldSelect: u64 {
        /// Guest policy will be mixed into the key
        const GUEST_POLICY = 1;

        /// Image ID of the guest will be mixed into the key
        const IMAGE_ID = 1 << 1;

        /// Family ID of the guest will be mixed into the key
        const FAMILY_ID = 1 << 2;

        /// Measurement of the guest during launch will be mixed into the key
        const MEASUREMENT = 1 << 3;

        /// Guest-provided SVN will be mixed into the key
        const GUEST_SVN = 1 << 4;

        /// Guest-provided TCB_VERSION will be mixed into the key
        const TCB_VERSION = 1 << 5;
    }
}


pub fn is_aligned_non_null<T>(ptr: usize) -> Option<usize> {
    if ptr == 0 || ptr % align_of::<T>() != 0 {
        return None;
    }
    Some(ptr)
}

pub struct UserMemScope;

impl  UserMemScope {
    #[inline]
    fn validate_mut<T>(&self, ptr: usize) -> Result<&mut T, c_int> {
        is_aligned_non_null::<T>(ptr).ok_or(SysErr::EINVAL)?;

        unsafe { (ptr as *mut T).as_mut().ok_or(SysErr::EINVAL) }
    }

    #[inline]
    fn validate<T>(&self, ptr: usize) -> Result<&T, c_int> {
        is_aligned_non_null::<T>(ptr).ok_or(SysErr::EINVAL)?;

        unsafe { (ptr as *const T).as_ref().ok_or(SysErr::EINVAL) }
    }


    #[inline]
    fn validate_slice_mut<T: Sized>(
        &self,
        ptr: usize,
        count: usize,
    ) -> Result<&mut [T], c_int>{
        is_aligned_non_null::<T>(ptr).ok_or(SysErr::EINVAL)?;

        unsafe { Ok(slice::from_raw_parts_mut(ptr as *mut T, count)) }
    }


    #[inline]
    fn validate_slice<T: Sized>(&self, ptr: usize, count: usize) -> Result<&[T], c_int> {
        is_aligned_non_null::<T>(ptr).ok_or(SysErr::EINVAL)?;
        unsafe { Ok(slice::from_raw_parts(ptr as *const T, count)) }
    }
}


lazy_static! {
    pub static ref SEV_SNP_DRIVER: Mutex<&'static mut SnpGuestDriver> = lazy_ghcb_ext();
}


#[cfg_attr(coverage, no_coverage)]
fn lazy_refcell() -> RacyCell<SnpGuestDriver> {
    RacyCell::new(SnpGuestDriver::default())
}



use spin::lazy::Lazy;

#[cfg_attr(coverage, no_coverage)]
fn lazy_ghcb_ext() -> Mutex<&'static mut SnpGuestDriver> {
    static DRIVER: Lazy<RacyCell<SnpGuestDriver>> =
        Lazy::new(lazy_refcell);

    let driver_mut = unsafe { &mut (*DRIVER.get()) };
    driver_mut.init();
    Mutex::<&mut SnpGuestDriver>::new(driver_mut)
}

#[derive(Debug, Default)]
pub struct SnpGuestDriver {
    request: SnpGuestMsg,
    response: SnpGuestMsg,
}

impl SnpGuestDriver {
    #[cfg_attr(coverage, no_coverage)]
    fn init(&mut self) {
        let request_virt = VirtAddr::from_ptr(&self.request);

        let response_virt = VirtAddr::from_ptr(&self.response);

        let log_available = LOG_AVAILABLE.load(core::sync::atomic::Ordering::Acquire);

        let mut vcpuid = 0;
        if log_available {
            vcpuid = crate::qlib::kernel::asm::GetVcpuId();
        }

        // use crate::qlib::perf_tunning::HyperCall64;
        // self.request.hdr.algo = 1;
        // info!("SnpGuestDriver default hypercall before 11 {:?}", self);
        // HyperCall64(qlib::HYPERCALL_TEST_SHARED, request_virt.as_u64(), response_virt.as_u64(), 0, 0);
        // info!("SnpGuestDriver default hypercall after {:?}", self);

        {
            let ghcb_option: &mut Option<GhcbHandle<'_>> = &mut *GHCB[vcpuid].lock();
            let ghcb = ghcb_option.as_mut().unwrap();



            ghcb.set_memory_shared_4kb(request_virt, 1);



            ghcb.set_memory_shared_4kb(response_virt, 1);

        }
    }

    #[cfg_attr(coverage, no_coverage)]
    fn guest_req(&mut self) -> Result<(), u64> {

        let req_gpa = PhysAddr::new(VirtAddr::from_ptr(&self.request).as_u64());
        let resp_gpa = PhysAddr::new(VirtAddr::from_ptr(&self.response).as_u64());   

        let log_available = LOG_AVAILABLE.load(core::sync::atomic::Ordering::Acquire);

        let mut vcpuid = 0;
        if log_available {
            vcpuid = crate::qlib::kernel::asm::GetVcpuId();
        }

        let ret = {
            let ghcb_option: &mut Option<GhcbHandle<'_>> = &mut *GHCB[vcpuid].lock();
            let ghcb = ghcb_option.as_mut().unwrap();


            // prevent earlier writes from being moved beyond this point
            core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::Release);

            // SAFETY: request and response are valid and mapped to shared memory

            let ret = unsafe { ghcb.guest_req(req_gpa, resp_gpa) };


            // prevent later reads from being moved before this point
            core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::Acquire);

            ret
        };

        if ret.is_err() {
            info!("GhcbExtHandle guest_req 1 ret {:?}, error bym {:x}", ret, ret.err().unwrap());
        }

        if ret.is_ok() {
            SECRETS.lock().inc_msg_seqno_0();
        }

        ret
    }

    fn enc_payload(
        &mut self,
        version: u8,
        msg_type: SnpMsgType,
        plaintext: &mut [u8],
    ) -> Result<(), ()> {
        let plaintext_size = plaintext.len();

        let request = &mut self.request;
        request.hdr.algo = AeadAlgo::SnpAeadAes256Gcm as _;
        request.hdr.hdr_version = MSG_HDR_VER;
        request.hdr.hdr_sz = size_of::<SnpGuestMsgHdr>() as _;
        request.hdr.msg_type = msg_type as _;
        request.hdr.msg_version = version;
        request.hdr.msg_seqno = SECRETS.lock().get_msg_seqno_0() as _;
        request.hdr.msg_vmpck = 0;
        request.hdr.msg_sz = plaintext_size as _;

        let vmpck0 = SECRETS.lock().get_vmpck0();

        let cipher = Aes256Gcm::new_from_slice(&vmpck0).unwrap();

        let mut seqno_nonce = [0u8; 12];
        seqno_nonce[0..8].copy_from_slice(unsafe {
            core::slice::from_raw_parts(&request.hdr.msg_seqno as *const _ as *const u8, 8)
        });

        let nonce = Nonce::from_slice(&seqno_nonce); // 96-bits; unique per message

        let asssoc_data = unsafe {
            core::slice::from_raw_parts(&request.hdr.algo as *const _ as *const u8, 48)
        };

        let tag = cipher
            .encrypt_in_place_detached(nonce, asssoc_data, plaintext)
            .map_err(|_| ())?;

        request.payload[0..plaintext_size].copy_from_slice(plaintext);

        request.hdr.authtag[0..16].copy_from_slice(&tag.as_slice()[0..16]);

        Ok(())
    }

    fn dec_payload(
        &mut self,
        plaintext: &mut [u8],
        expected_msg_type: SnpMsgType,
    ) -> Result<(), ()> {
        let payload_size = plaintext.len();

        let request = &mut self.request;
        let response = &mut self.response;

        let next_seqno = request.hdr.msg_seqno.checked_add(1).ok_or(())?;
        if next_seqno != response.hdr.msg_seqno {
            return Err(());
        }

        if expected_msg_type as u8 != response.hdr.msg_type {
            return Err(());
        }

        if request.hdr.msg_version != response.hdr.msg_version {
            return Err(());
        }

        if response.hdr.algo != AeadAlgo::SnpAeadAes256Gcm as u8 {
            return Err(());
        }

        if response.hdr.hdr_sz != size_of::<SnpGuestMsgHdr>() as u16 {
            return Err(());
        }

        if response.hdr.msg_vmpck != 0 {
            return Err(());
        }

        if response.hdr.msg_sz as usize > payload_size {
            return Err(());
        }


        let vmpck0 = SECRETS.lock().get_vmpck0();
        let cipher = Aes256Gcm::new_from_slice(&vmpck0).unwrap();

        let mut seqno_nonce = [0u8; 12];
        seqno_nonce[0..8].copy_from_slice(unsafe {
            core::slice::from_raw_parts(&response.hdr.msg_seqno as *const _ as *const u8, 8)
        });

        let nonce = Nonce::from_slice(&seqno_nonce); // 96-bits; unique per message

        let asssoc_data = unsafe {
            core::slice::from_raw_parts(&response.hdr.algo as *const _ as *const u8, 48)
        };

        let tag = Tag::from_slice(&response.hdr.authtag[0..16]);

        plaintext[0..response.hdr.msg_sz as usize]
            .copy_from_slice(&response.payload[0..response.hdr.msg_sz as usize]);

        cipher
            .decrypt_in_place_detached(
                nonce,
                asssoc_data,
                &mut plaintext[0..response.hdr.msg_sz as usize],
                tag,
            )
            .expect("decrypt failed!");

        Ok(())
    }

    pub fn get_attestation(
        &mut self,
        platform: UserMemScope,
        nonce: usize,
        nonce_len: usize,
        buf: usize,
        buf_len: usize,
    ) -> Result<[usize; 2], c_int> {
        if !snp_active() {
            return Ok([0, 0]);
        }

        if buf == 0 {
            // if the unwrap panics, it is totally worthy
            let len = SNP_ATTESTATION_LEN_MAX;
            return Ok([len, TECH]);
        }

        if buf_len > isize::MAX as usize {
            return Err(SysErr::EINVAL);
        }

        if buf_len < SNP_ATTESTATION_LEN_MAX {
            return Err(SysErr::EMSGSIZE);
        }

        if nonce_len != 64 {
            return Err(SysErr::EINVAL);
        }
        let nonce = platform.validate_slice::<u8>(nonce, nonce_len)?;

        let user_buf = platform.validate_slice_mut::<u8>(buf, buf_len)?;

        let mut report_buf = [0u8; SNP_ATTESTATION_LEN_MAX];

        self.request = SnpGuestMsg::default();
        self.response = SnpGuestMsg::default();

        let (skip, report_len) = self.get_report(1, nonce, &mut report_buf)?;

        let report_data = &report_buf[skip..][..report_len];

        debug!("response {:?}", self.response);

        user_buf[..report_data.len()].copy_from_slice(report_data);  // only contains report



        Ok([report_data.len(), TECH])
    }


    /// Request a derived key
    pub fn get_key(&mut self, version: u8, guest_svn: u32) -> Result<[u8; 32], i32> {

        let key_req = KeyReq {
            root_key_select: 0,
            _rsvd: 0,
            guest_field_select: GuestFieldSelect::GUEST_SVN.bits
                | GuestFieldSelect::GUEST_POLICY.bits,
            vmpl: 0,
            guest_svn,
            tcb_version: 0,
        };

        let key_rsp = {
            let mut request = [0u8; KeyReq::SIZE];
            let mut response = [0u8; KeyRsp::SIZE];

            request.copy_from_slice(key_req.as_bytes());

            self.enc_payload(version, SnpMsgType::KeyReq, &mut request)
            .expect("encryption failed");

            self.guest_req().expect("request failed");

            self.dec_payload(&mut response, SnpMsgType::KeyRsp)
                .expect("decryption failed");
            KeyRsp::from_bytes(&response).ok_or(SysErr::EIO)?

        };

        match key_rsp.status {
            0 => Ok(key_rsp.derived_key),
            0x16 => Err(SysErr::EIO),
            _ => panic!("invalid MSG_KEY_RSP error value {}", key_rsp.status),
        }
    }


    /// Get an attestation report via the GHCB shared page protocol
    fn get_report(
        &mut self,
        version: u8,
        nonce: &[u8],
        response: &mut [u8],
    ) -> Result<(usize, usize), i32> {
        if nonce.len() != 64 {
            return Err(SysErr::EINVAL as _);
        }

        if response.len() < SNP_ATTESTATION_LEN_MAX {
            return Err(SysErr::EINVAL as _);
        }

        let mut report_request = SnpReportRequest::default();
        report_request.report_data.copy_from_slice(nonce);

        let mut request = [0u8; SnpReportRequest::SIZE];
        request.copy_from_slice(report_request.as_bytes());

        self.enc_payload(version, SnpMsgType::ReportReq, &mut request)
            .expect("encryption failed");
        self.guest_req().expect("request failed");

        self.dec_payload(response, SnpMsgType::ReportRsp)
            .expect("decryption failed");

        if (self.response.hdr.msg_sz as usize) < size_of::<SnpReportResponseHeader>() {
            error!("invalid report response size  {}", self.response.hdr.msg_sz);
            return Err(SysErr::EIO);
        }

        let report =
            SnpReportResponseHeader::from_bytes(&response[..size_of::<SnpReportResponseHeader>()])
                .ok_or_else(|| {
                    error!("invalid report response size from bytes");
                    SysErr::EIO
                })?;

        match report.status {
            0 => Ok((size_of::<SnpReportResponseHeader>(), report.size as _)),
            0x16 => {
                error!("report request status 0x16");
                Err(SysErr::EIO)
            }
            _ => panic!("invalid MSG_REPORT_RSP error value {}", report.status),
        }
    }

}