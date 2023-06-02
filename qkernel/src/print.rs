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

use super::qlib::kernel::Timestamp;
use super::qlib::vcpu_mgr::*;
use super::task::*;
use alloc::string::String;

pub fn PrintPrefix() -> String {
    let now = if super::SHARESPACE.config.read().PerfDebug {
        Timestamp()
    } else {
        0
    };

    return format!(
        "[{}/{:x}|{}]",
        CPULocal::CpuId(),
        Task::TaskId().Addr(),
        now
    );
}

#[macro_export]
macro_rules! raw {
    // macth like arm for macro
    ($a:expr,$b:expr,$c:expr,$d:expr) => {{
        $crate::Kernel::HostSpace::KernelMsg($a, $b, $c, $d);
    }};
}

#[macro_export]
macro_rules! raw_print {
    ($($arg:tt)*) => ({
        if $crate::SHARESPACE.config.read().DebugLevel >= $crate::qlib::config::DebugLevel::Error {
            //$crate::qlib::perf_tunning::PerfGoto($crate::qlib::perf_tunning::PerfType::Print);
            let s = &format!($($arg)*);
            let str = format!("Qkernel Log [Print] {}", s);

            $crate::Kernel::HostSpace::SyncPrint($crate::qlib::config::DebugLevel::Error, &str);
            //$crate::qlib::perf_tunning::PerfGofrom($crate::qlib::perf_tunning::PerfType::Print);
        }
    });
}

#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => ({
        if $crate::SHARESPACE.config.read().DebugLevel >= $crate::qlib::config::DebugLevel::Error {
            //$crate::qlib::perf_tunning::PerfGoto($crate::qlib::perf_tunning::PerfType::Print);
            let prefix = $crate::print::PrintPrefix();
            let s = &format!($($arg)*);
            let str = format!("Qkernel Log [Print] {} {}", prefix, s);

            $crate::Kernel::HostSpace::SyncPrint($crate::qlib::config::DebugLevel::Error, &str);
            //$crate::qlib::perf_tunning::PerfGofrom($crate::qlib::perf_tunning::PerfType::Print);
        }
    });
}

#[macro_export]
macro_rules! error {
    ($($arg:tt)*) => ({
        if $crate::SHARESPACE.config.read().DebugLevel >= $crate::qlib::config::DebugLevel::Error {
            //$crate::qlib::perf_tunning::PerfGoto($crate::qlib::perf_tunning::PerfType::Print);
            let prefix = $crate::print::PrintPrefix();
            let s = &format!($($arg)*);

            if $crate::SHARESPACE.config.read().SyncPrint() {
                let str = format!("Qkernel Log [ERROR] {} {}", prefix, s);
                $crate::Kernel::HostSpace::SyncPrint($crate::qlib::config::DebugLevel::Error, &str);
            } else {
                let str = format!("Qkernel Log  [ERROR] {} {}\n", prefix, s);
                $crate::Kernel::HostSpace::Kprint(&str);
            }

            //$crate::qlib::perf_tunning::PerfGofrom($crate::qlib::perf_tunning::PerfType::Print);
        }
    });
}

#[macro_export]
macro_rules! info {
    ($($arg:tt)*) => ({
        if $crate::SHARESPACE.config.read().DebugLevel >= $crate::qlib::config::DebugLevel::Info {
            //$crate::qlib::perf_tunning::PerfGoto($crate::qlib::perf_tunning::PerfType::Print);
            let prefix = $crate::print::PrintPrefix();
            let s = &format!($($arg)*);

            if $crate::SHARESPACE.config.read().SyncPrint() {
                let str = format!("Qkernel Log  [INFO] {} {}", prefix, s);
                $crate::Kernel::HostSpace::SyncPrint($crate::qlib::config::DebugLevel::Error, &str);
            } else {
                 let str = format!("Qkernel Log  [INFO] {} {}\n", prefix, s);
                 $crate::Kernel::HostSpace::Kprint(&str);
            }
            //$crate::qlib::perf_tunning::PerfGofrom($crate::qlib::perf_tunning::PerfType::Print);
        }
    });
}

#[macro_export]
macro_rules! warn {
    ($($arg:tt)*) => ({
        if $crate::SHARESPACE.config.read().DebugLevel >= $crate::qlib::config::DebugLevel::Info {
            //$crate::qlib::perf_tunning::PerfGoto($crate::qlib::perf_tunning::PerfType::Print);
            let prefix = $crate::print::PrintPrefix();
            let s = &format!($($arg)*);

            if $crate::SHARESPACE.config.read().SyncPrint() {
                let str = format!("Qkernel Log  [WARN] {} {}", prefix, s);
                $crate::Kernel::HostSpace::SyncPrint($crate::qlib::config::DebugLevel::Error, &str);
            } else {
                 let str = format!("Qkernel Log  [WARN] {} {}\n", prefix, s);
                 $crate::Kernel::HostSpace::Kprint(&str);
            }
            //$crate::qlib::perf_tunning::PerfGofrom($crate::qlib::perf_tunning::PerfType::Print);
        }
    });
}

#[macro_export]
macro_rules! debug {
    ($($arg:tt)*) => ({
        if $crate::SHARESPACE.config.read().DebugLevel >= $crate::qlib::config::DebugLevel::Debug {
            //$crate::qlib::perf_tunning::PerfGoto($crate::qlib::perf_tunning::PerfType::Print);
            let prefix = $crate::print::PrintPrefix();
            let s = &format!($($arg)*);

            if $crate::SHARESPACE.config.read().SyncPrint() {
                let str = format!("Qkernel Log  [DEBUG] {} {}", prefix, s);
                $crate::Kernel::HostSpace::SyncPrint($crate::qlib::config::DebugLevel::Error, &str);
            } else {
                let str = format!("Qkernel Log  [DEBUG] {} {}\n", prefix, s);
                $crate::Kernel::HostSpace::Kprint(&str);
            }
            //$crate::qlib::perf_tunning::PerfGofrom($crate::qlib::perf_tunning::PerfType::Print);
        }
    });
}
