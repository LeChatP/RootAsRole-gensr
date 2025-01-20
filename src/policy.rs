use std::{collections::HashMap, ops::{BitOr, BitOrAssign}, rc::Weak, str::FromStr};

use bitflags::bitflags;
use log::warn;
use nix::unistd::{getgroups, getuid, Gid, Group, Uid, User};
use rootasrole_core::{database::{options::SAuthentication, structs::{IdTask, SActorType, SCapabilities, SGroups, STask, SetBehavior}}, util::parse_capset_iter};
use serde::{ser::SerializeMap, Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::{capable::Capable, deploy::{enforce_policy, remove_policy}};


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

#[derive(Deserialize, PartialEq, Eq)]
pub(crate) struct Policy {
    pub(crate) setuid: Option<u32>,
    pub(crate) setgid: Option<Vec<u32>>,
    pub(crate) capabilities: Vec<String>,
    pub(crate) files: HashMap<String, Access>,
    pub(crate) dbus: Vec<String>,
    pub(crate) env_vars: HashMap<String, String>,
    #[serde(default)]
    pub(crate) password_prompt: SAuthentication,
}

impl Serialize for Policy {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer {
        let mut map = serializer.serialize_map(Some(5))?;
        if let Some(setuid) = self.setuid {
            let uid = Uid::from_raw(setuid);
            if let Ok(Some(user)) = User::from_uid(uid) {
                map.serialize_entry("setuid", &user.name)?;
            } else {
                map.serialize_entry("setuid", &setuid)?;
            }
        }
        if let Some(setgid) = &self.setgid {
            let groups: Vec<SActorType> = setgid.iter().map(|g| {
                let gid = Gid::from_raw(*g);
                if let Ok(Some(group)) = Group::from_gid(gid) {
                    SActorType::Name(group.name)
                } else {
                    SActorType::Id(*g)
                }
            }).collect();
            map.serialize_entry("setgid", &groups)?;
        }
        map.serialize_entry("capabilities", &self.capabilities)?;
        map.serialize_entry("files", &self.files)?;
        map.serialize_entry("dbus", &self.dbus)?;
        map.end()
    }
}


impl Default for Policy {
    fn default() -> Self {
        Policy {
            capabilities: Vec::new(),
            files: HashMap::new(),
            dbus: Vec::new(),
            setuid: None,
            setgid: None,
            env_vars: HashMap::new(),
            password_prompt: SAuthentication::Perform,
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

        let mut env = self.env_vars;
        env.extend(rhs.env_vars);

        if self.password_prompt != rhs.password_prompt {
            warn!("Password prompt mismatch: {:?} vs {:?}", self.password_prompt, rhs.password_prompt);
        }

        Policy {
            capabilities,
            files,
            dbus,
            setuid: self.setuid.or(rhs.setuid),
            setgid: self.setgid.or(rhs.setgid),
            env_vars: env,
            password_prompt: self.password_prompt,
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



    pub(crate) fn apply(&self, username :&str, capable: &mut Capable) -> anyhow::Result<()> {
        //TODO: apply the policy

        //hash playbook+task in sha224
        capable.add_caps(&parse_capset_iter(self.capabilities.iter().map(|c| c.as_str()))?);
        enforce_policy(username, self)
    }

    pub(crate) fn remove(&self, username :&str) -> anyhow::Result<()> {
        remove_policy(&username, self)
    }

    pub fn to_stask(&self, username: &str, task: Option<&str>) -> STask {
        let mut stask = STask::new(IdTask::Name(task.unwrap_or(username).to_string()), Weak::new());
        stask.cred.setuid = Some(SActorType::Name(username.to_string()));
        stask.cred.setgid = Some(SGroups::Single(SActorType::Name(username.to_string())));
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

    pub(crate) fn current_user_creds(&mut self) {
        self.setuid = Some(getuid().as_raw());
        self.setgid = Some(getgroups().unwrap().iter().map(|g| g.as_raw()).collect());
    }

}