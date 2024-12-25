use std::{
    collections::HashMap, ops::{BitOr, BitOrAssign}, path::PathBuf, rc::Weak, str::FromStr
};

use bitflags::bitflags;
use log::warn;
use rootasrole_core::{database::structs::{IdTask, SActorType, SCapabilities, SGroups, STask, SetBehavior}, util::parse_capset_iter};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::Digest;

use crate::deploy::{self, enforce_policy, remove_policy};

pub(crate) struct Capable {
    command: Vec<String>,
    ran: bool,
    failed: bool,
    tmp_file: PathBuf,
    pub last_stdout: String,
    pub last_stderr: String,
}

bitflags! {
    #[derive(Clone, Copy, PartialEq, Eq)]
    pub struct Access: u8 {
        const R   = 0b100;
        const W   = 0b010;
        const X   = 0b001;
        const RW  = 0b110;
        const RX  = 0b101;
        const WX  = 0b011;
        const RWX = 0b111;
    }
}

impl std::fmt::Display for Access {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut access = String::new();
        if self.contains(Access::R) {
            access.push('R');
        }
        if self.contains(Access::W) {
            access.push('W');
        }
        if self.contains(Access::X) {
            access.push('X');
        }
        write!(f, "{}", access)
    }
}

pub struct AccessParseError;

impl std::fmt::Display for AccessParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Invalid access string")
    }
}

impl FromStr for Access {
    type Err = AccessParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut access = Access::empty();
        for c in s.chars() {
            match c {
                'R' => access |= Access::R,
                'W' => access |= Access::W,
                'X' => access |= Access::X,
                _ => return Err(AccessParseError),
            }
        }
        Ok(access)
    }
}

impl Serialize for Access {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.to_string().as_str())
    }
}

impl<'de> Deserialize<'de> for Access {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

#[derive(Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct Policy {
    pub(crate) capabilities: Vec<String>,
    pub(crate) files: HashMap<String, Access>,
    pub(crate) dbus: Vec<String>,
}



impl Default for Policy {
    fn default() -> Self {
        Policy {
            capabilities: Vec::new(),
            files: HashMap::new(),
            dbus: Vec::new(),
        }
    }
}

impl BitOr for Policy {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        let mut capabilities = self.capabilities.clone();
        capabilities.extend(rhs.capabilities);
        let mut files = self.files.clone();

        let intersection = self.files.keys().filter(|k| rhs.files.contains_key(*k));
        for key in intersection {
            let access = self.files[key] | rhs.files[key];
            files.insert(key.clone(), access);
        }

        files.extend(rhs.files);
        let mut dbus = self.dbus;
        dbus.extend(rhs.dbus);
        Policy {
            capabilities,
            files,
            dbus,
        }
    }
}

impl BitOrAssign for Policy {
    fn bitor_assign(&mut self, rhs: Self) {
        self.capabilities.extend(rhs.capabilities);

        let intersection: Vec<String> = self
            .files
            .keys()
            .filter(|k| rhs.files.contains_key(*k))
            .cloned()
            .collect();
        for key in &intersection {
            let access = self.files[key] | rhs.files[key];
            self.files.insert(key.clone(), access);
        }

        self.files.extend(rhs.files);
        self.dbus.extend(rhs.dbus);
    }
}

impl Policy {

    pub fn get_username(playbook: &str, task: &str) -> String {
        let mut hasher = sha2::Sha224::new();
        hasher.update(playbook.as_bytes());
        hasher.update(task.as_bytes());
        let hash = hasher.finalize();
        // transform to string
        format!("rar_{}",hex::encode(hash))
    }



    pub(crate) fn apply(&self, playbook: &str, task :&str) -> anyhow::Result<()> {
        //TODO: apply the policy

        //hash playbook+task in sha224
        
        enforce_policy(&Self::get_username(playbook, task), self)
    }

    pub(crate) fn remove(&self, playbook: &str, task :&str) -> anyhow::Result<()> {
        remove_policy(&Self::get_username(playbook, task), self)
    }
    
    pub(crate) fn is_default(&self) -> bool {
        self.capabilities.is_empty() && self.files.is_empty() && self.dbus.is_empty()
    }

    pub fn to_stask(&self, playbook: &str, task: &str) -> STask {
        let mut stask = STask::new(IdTask::Name(task.to_string()), Weak::new());
        let username = Self::get_username(playbook, task);
        stask.cred.setuid = Some(SActorType::Name(username.clone()));
        stask.cred.setgid = Some(SGroups::Single(SActorType::Name(username.clone())));
        stask.cred.capabilities = self.to_scapabilities();
        stask.cred._extra_fields.insert("files".to_string(), self.to_sfiles());
        stask.cred._extra_fields.insert("dbus".to_string(), self.to_sdbus());
        stask.commands.default_behavior = Some(SetBehavior::All);
        stask
    }

    fn to_scapabilities(&self) -> Option<SCapabilities> {
        if self.capabilities.is_empty() {
            None
        } else {
            let mut scapabilities = SCapabilities::default();
            scapabilities.default_behavior = SetBehavior::None;
            let res = parse_capset_iter(self.capabilities.iter().map(|c| c.as_str()));
            if let Ok(capset) = res {
                scapabilities.add = capset;
                Some(scapabilities)
            } else {
                warn!("Failed to parse capabilities: {}", res.unwrap_err());
                None
            }
        }
    }

    fn to_sfiles(&self) -> Value {
        let mut files = Map::new();
        for (f, a) in &self.files {
            files.insert(f.clone(), Value::String(a.to_string()));
        }
        Value::Object(files)
    }

    fn to_sdbus(&self) -> Value {
        Value::Array(self.dbus.iter().map(|d| Value::String(d.clone())).collect())
    }

}

impl Capable {
    pub(crate) fn new(mut command: Vec<String>) -> Self {
        let tmp_file = tempfile::tempdir().expect("Failed to create temporary file").into_path().join("gensr");
        command.splice(0..0, vec![
            "-l".to_string(),
            "error".to_string(),
            "-o".to_string(),
            tmp_file.to_str().expect("Failed to convert path to string").to_string(),
        ]);
        Capable {
            command,
            ran: false,
            failed: false,
            tmp_file,
            last_stdout: String::new(),
            last_stderr: String::new(),
        }
    }
    pub(crate) fn has_ran(&self) -> bool {
        self.ran
    }
    pub(crate) fn is_failed(&self) -> bool {
        self.failed
    }
    pub(crate) fn run(&mut self) -> Result<Policy, anyhow::Error> {
        let cmd = std::process::Command::new("capable")
            .args(&self.command)
            .stdin(std::process::Stdio::inherit())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .output()?;
        self.failed = !cmd.status.success();
        if !self.is_failed() {
            print!("{}", cmd.stdout.iter().map(|b| *b as char).collect::<String>());
            eprint!("{}", cmd.stderr.iter().map(|b| *b as char).collect::<String>());
        }
        // open the file and parse the policy
        let policy: Policy = serde_json::de::from_reader(std::fs::File::open(&self.tmp_file)?)?;
        self.ran = true;
        Ok(policy)
    }
}
