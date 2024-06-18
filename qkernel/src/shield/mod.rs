pub mod qkernel_log_magager;


use crate::aes_gcm::{ Aes256Gcm, Key};
use alloc::{vec::Vec, string::String};
use crate::qlib::common::*;
use spin::rwlock::RwLock;
use alloc::string::ToString;
use core::convert::TryInto;
use qlib::shield_policy::KbsPolicy;

lazy_static! {
    pub static ref APPLICATION_INFO_KEEPER:  RwLock<ApplicationInfoKeeper> = RwLock::new(ApplicationInfoKeeper::default());
}

const APP_NMAE: &str = "APPLICATION_NAME";
const SECRET_MANAGER_IP: &str = "SECRET_MANAGER_IP"; 
const CMD_ENV_BASED_SECRETS_PATH: &str = "CMD_ENV_BASED_SECRETS_PATH"; 
const FILE_BASED_SECRETS_PATH: &str = "FILE_BASED_SECRETS_PATH"; 
const SHILED_POLICY_PATH: &str = "SHILED_POLICY_PATH"; 


#[derive(Default)]
pub struct ApplicationInfoKeeper {
    app_name: String,
    is_launched: bool,
    kbs_ip:  [u8;4],  // key: file name, value: secret
    kbs_port: u16,
    kbs_cmd_env_based_secret_path: Option<String>,
    kbs_file_based_secret_paths: Vec<String>,
    kbs_policy_path: Option<String>,
    cid: String,
}


fn vec_to_array<T, const N: usize>(v: Vec<T>) -> [T; N] {
    v.try_into()
        .unwrap_or_else(|v: Vec<T>| panic!("Expected a Vec of length {} but it was {}", N, v.len()))
}


impl ApplicationInfoKeeper {
    // ip pattern: ip:port, i.e., 10.206.133.76:8080"
    fn parse_ip(&self, ip_port : &str) -> Result<(Vec<u8>, u16)> {

        
        let key_value: Vec<&str> = ip_port.split(':').collect();

        let ip_string = key_value[0];
        let port_string = key_value[1];
            
        
        let ip_splite: Vec<_> = ip_string.split(".").collect();
        let ip: Vec<u8> = match ip_splite.iter().map(|x| x.parse()).collect() {
            Ok(i) => i,
            Err(e) => {
                info!("ip_splite.iter().map(|x| x.parse()).collect() {:?}", e);
                return Err(Error::Common("ip_splite.iter().map(|x| x.parse()).collect()".to_string()));
            }
        };

        assert!(ip.len() == 4);
        
        let port: u16 = match port_string.parse() {
            Ok(i) => i,
            Err(e) => {
                info!("port_string.parse got error {:?}", e);
                return Err(Error::Common("port_string.parse got error".to_string()));
            }
        };

        Ok((ip, port))
    }


    pub fn init(&mut self, envs : &Vec<String>, cid: String) -> Result<()>{

        if envs.len() == 0 {
            return  Err(Error::Common("parse_envs, envs.len() == 0".to_string()));
        }


        self.cid = cid;

        let mut found_app_name = false;
        let mut found_ip_port = false;

        for env in envs {

            let key_value:  Vec<&str> = env.split('=').collect();

            assert!(key_value.len() == 2);
            if key_value[0].eq(APP_NMAE) {
                self.app_name =  key_value[1].to_string();
                found_app_name = true;
            } else if key_value[0].eq(SECRET_MANAGER_IP) {
                let (ip, port) = self.parse_ip(key_value[1])?;

                self.kbs_ip = vec_to_array(ip);
                self.kbs_port = port;
                found_ip_port = true;
            } else if key_value[0].eq(CMD_ENV_BASED_SECRETS_PATH) {

                self.kbs_cmd_env_based_secret_path = Some(key_value[1].to_string());
                
            } else if key_value[0].eq(FILE_BASED_SECRETS_PATH) {

                let pathes: Vec<&str> = key_value[1].split(',').collect();

                let mut new_path = Vec::new();
                for path in pathes {
                    new_path.push(path.to_string());
                }
                self.kbs_file_based_secret_paths = new_path;                
            } else if key_value[0].eq(SHILED_POLICY_PATH) {

                self.kbs_policy_path = Some(key_value[1].to_string());
            } 
        }
        assert!(found_app_name == true && found_ip_port == true);
        Ok(())
    }


    pub fn get_kbs_ip(&self) -> Result<[u8;4]> {

        Ok(self.kbs_ip)
    }


    pub fn get_kbs_port(&self) -> Result<u16> {

        Ok(self.kbs_port)
    }

    pub fn is_application_loaded (&self) -> Result<bool> {
        return Ok(self.is_launched);
    }

    pub fn set_application_loaded (&mut self) -> Result<()> {
        self.is_launched = true;
        return Ok(());
    }

    pub fn get_application_name (&self) -> Result<&str> {
        return Ok(&self.app_name);
    }
}



pub fn init_shielding_layer () ->() {

    const KEY_SLICE: &[u8; 32] = b"a very simple secret key to use!";
    const DEDAULT_VMPK: u32 = 0;

    let default_policy = KbsPolicy::default();

    let encryption_key = Key::<Aes256Gcm>::from_slice(KEY_SLICE).clone();
    info!("init_shielding_layer init shielding layer use default policy:{:?}" ,default_policy);

    qkernel_log_magager::qlog_magager_init().unwrap();
}



pub fn policy_provisioning (policy: &KbsPolicy) -> Result<()> {

    info!("policy_provisioning init shielding layer use  policy:{:?} from kbs" ,policy);
    let key_slice = policy.privileged_user_key_slice.as_bytes();
    let encryption_key = Key::<Aes256Gcm>::from_slice(key_slice).clone();

    qkernel_log_magager::qlog_magager_update(&policy.qkernel_log_config).unwrap();
    info!("policy_provisioning init shielding layer");
    Ok(())
}