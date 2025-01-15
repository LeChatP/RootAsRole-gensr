use std::
    path::PathBuf
;

use bon::bon;
use capctl::CapSet;
use nix::unistd::{getgroups, getuid};
use tempfile::{Builder, NamedTempFile};

use crate::policy::Policy;


pub(crate) struct Capable {
    path: Option<PathBuf>,
    command: Vec<String>,
    previous_caps: CapSet,
    caps: CapSet,
    ran: bool,
    failed: bool,
    tmp_file: NamedTempFile,
    pub last_stdout: String,
    pub last_stderr: String,
}


impl Default for Capable {
    fn default() -> Self {
        let tmp_file = Builder::new().keep(true).tempfile().unwrap();
        Capable {
            path : which::which("capable").ok(),
            previous_caps: CapSet::empty(),
            caps: capctl::bounding::probe(),
            command: vec![
                "-l".to_string(),
                "error".to_string(),
                "-o".to_string(),
                tmp_file.path().to_str().expect("Failed to convert path to string").to_string(),
            ],
            ran: false,
            failed: false,
            tmp_file,
            last_stdout: String::new(),
            last_stderr: String::new(),
        }
    }
}

#[bon]
impl Capable {
    #[builder]
    pub(crate) fn new(path: Option<PathBuf>, command: Vec<String>,
        fail_then_add : bool) -> anyhow::Result<Self> {
        let mut default = Self::default();
        let tmp_file = Builder::new().keep(true).tempfile().unwrap();
        default.command.extend(command);
        default.tmp_file = tmp_file;
        if let Some(path) = path {
            default.path = Some(path);
        } else if default.path.is_none() {
            return Err(anyhow::anyhow!("capable not found in PATH"));
        }
        if fail_then_add {
            default.caps = CapSet::empty();
        }
        Ok(default)
    }
    pub(crate) fn add_caps(&mut self, caps: &CapSet) {
        self.previous_caps = self.caps;
        self.caps |= *caps;
    }
    pub(crate) fn has_ran(&self) -> bool {
        self.ran
    }
    pub(crate) fn is_failed(&self) -> bool {
        self.failed
    }
    pub(crate) fn run(&mut self) -> Result<Policy, anyhow::Error> {
        let mut binding = self.command.clone();
        let command = binding.splice(0..0, vec![
            "-c".to_string(),
            self.caps.iter().map(|c| c.to_string()).fold(String::new(), |s, c| {
                if s.is_empty() {
                    c.to_string()
                } else {
                    format!("{},{}", s, c)
                }
            })
        ]);
        let cmd = std::process::Command::new(self.path.as_ref().unwrap().as_os_str())
            .args(command)
            .stdin(std::process::Stdio::inherit())
            .stdout(std::process::Stdio::inherit())
            .stderr(std::process::Stdio::inherit())
            .output()?;
        self.failed = !cmd.status.success();
        if !self.is_failed() {
            print!("{}", cmd.stdout.iter().map(|b| *b as char).collect::<String>());
            eprint!("{}", cmd.stderr.iter().map(|b| *b as char).collect::<String>());
        }
        // open the file and parse the policy
        let mut policy: Policy = serde_json::de::from_reader(self.tmp_file.as_file())?;
        policy.setuid = Some(getuid().as_raw());
        policy.setgid = Some(getgroups().unwrap().iter().map(|g| g.as_raw()).collect());
        self.ran = true;
        Ok(policy)
    }
}