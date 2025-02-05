use alloc::string::{String};
use alloc::vec::Vec;
use crate::shield::exec_shield::*;

#[derive(Serialize, Deserialize, Debug, Default, Clone, PartialEq)]
pub struct PolicyUpdateResult {
    pub result: bool,
    pub session_id: u32,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone, PartialEq)]
pub enum StdioType {
    #[default]
    SandboxStdio, // the stdio of root conainer, i.e., "pause" container
    ContaienrStdio,  // the stio of subcontainers
    ExecProcessStdio,   // the stdio of exec process
    SessionAllocationStdio (ExecSession), // tue stdio of session allocation req
    PolicyUpdate(PolicyUpdateResult),  // indicate if update is succeed
}

#[derive(Serialize, Deserialize, Debug, Default, Clone, PartialEq)]
pub struct StdioArgs {
    pub exec_id: Option<String>,
    pub exec_user_type: Option<UserType>,
    pub stdio_type : StdioType
}

#[derive(Serialize, Deserialize, Debug, Default, Clone, PartialEq)]
pub struct TtyArgs {
    pub exec_id: Option<String>,
    pub exec_user_type: Option<UserType>,
    pub tty_slave : i32,
    pub stdio_type : StdioType
}

#[derive(Serialize, Deserialize, Debug, Default, Clone, PartialEq)]
pub enum TrackInodeType {
    Stdin(StdioArgs),
    Stdout(StdioArgs), 
    Stderro(StdioArgs),
    TTY(TtyArgs),
    #[default]
    Normal,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone, PartialEq)]
pub enum Role {
    #[default]
    Privileged,  // define a white list
    Unprivileged,  // define a black list
}

#[derive(Serialize, Deserialize, Debug, Default, Clone, PartialEq)]
pub struct PrivilegedUserConfig {
    pub allowed_cmd: Vec<String>,
    pub allowed_dir: Vec<String>,
    pub no_interactive_process_stdout_err_encryption:bool,
    pub interactive_porcess_stdout_err_encryption:bool,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone, PartialEq)]
pub struct UnprivilegedUserConfig {
    pub allowed_cmd: Vec<String>,
    pub allowed_dir: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone, PartialEq)]
pub struct SingleShotCommandLineModeConfig {
    pub allowed_cmd: Vec<String>,
    pub allowed_dir: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct ConfigFile {
    pub file_path: String,
    pub base64_file_content: String,
}


#[derive(Clone, Serialize, Deserialize, Debug, Default)]
pub struct Secret {
    pub env_variables: Vec<String>,
    pub cmd_arg: Vec<String>,
    pub config_fils: Vec<ConfigFile>,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct Policy {
    pub enable_policy_updata: bool,
    pub privileged_user_config: PrivilegedUserConfig,
    pub unprivileged_user_config:  UnprivilegedUserConfig,
    pub privileged_user_key_slice: String,
    pub secret: Secret,
}


#[derive(Clone, Serialize, Deserialize, Debug, Default)]
pub struct EnvCmdBasedSecrets {
    pub env_variables: Vec<String>,
    pub cmd_arg: Vec<String>,
}

#[derive(Clone, Serialize, Deserialize, Debug, Default)]
pub struct KbsSecrets {
    pub env_cmd_secrets: Option<EnvCmdBasedSecrets>,
    pub config_fils: Option<Vec<ConfigFile>>,
}


#[derive(Debug, Default, Serialize, Deserialize, Clone)]
pub enum ExecRequestType {
    #[default]
    Terminal,  // define a white list
    SingleShotCmdMode,  // define a black list
    SessionAllocationReq(ExecSession),
    PolicyUpdate(PolicyUpdate),   // indicate if the pilicy update succed  
}


#[derive(Serialize, Deserialize, Debug, Default, Clone, PartialEq)]
pub enum DefaultAction {
#[warn(non_camel_case_types)]
    #[default]  
    ScmpActErrno,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone, PartialEq)]
pub enum SystemCallInterceptorMode {
#[warn(non_camel_case_types)]
    #[default]  
    Global,  // the interceptor works globaly
    ContextBased, // the interceptor only works for application process
}


#[derive(Clone, Serialize, Deserialize, Debug, Default, PartialEq)]
pub struct BackEndSyscallInterceptorConfig {
    pub enable: bool,
    pub mode: SystemCallInterceptorMode,
    pub default_action: DefaultAction,
    pub syscalls: [u64; 8]
}

#[derive(Default, Clone, Copy, Debug, PartialOrd, Ord, Eq, PartialEq, Serialize, Deserialize)]
pub enum QkernelDebugLevel {
    Off,
    Error,
    Warn,
    Info,
    #[default]
    Debug,
    Trace,
}

#[derive(Default, Clone, Copy, Debug, PartialOrd, Ord, Eq, PartialEq, Serialize, Deserialize)]
pub struct QlogPolicy {
    pub enable: bool,
    pub allowed_max_log_level: QkernelDebugLevel
}


#[derive(Default, Clone, Copy, Debug, PartialOrd, Ord, Eq, PartialEq, Serialize, Deserialize)]
pub enum EnclaveMode {
    #[default]
    Development,
    Production
}


#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeReferenceMeasurement {
    #[serde(rename = "binary_name")]
    pub binary_name: String,
    #[serde(rename = "reference_measurement")]
    pub reference_measurement: String,
}


#[derive(Serialize, Deserialize, Debug, Default, Clone, PartialEq)]
pub struct KbsPolicy {
    #[serde(rename = "app_launch_ref_measurement")]
    pub app_launch_ref_measurement: String,
    #[serde(rename = "runtime_reference_measurements")]
    pub runtime_reference_measurements: Vec<RuntimeReferenceMeasurement>,
    pub enclave_mode: EnclaveMode,
    pub enable_policy_updata: bool,
    pub privileged_user_config: PrivilegedUserConfig,
    pub unprivileged_user_config:  UnprivilegedUserConfig,
    pub privileged_user_key_slice: String,
    pub qkernel_log_config: QlogPolicy,
    pub syscall_interceptor_config: BackEndSyscallInterceptorConfig,
}
