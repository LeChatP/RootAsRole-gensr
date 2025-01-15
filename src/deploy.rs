use std::{
    cell::RefCell,
    collections::{HashMap, HashSet},
    env,
    fs::{self, File},
    io::{self, BufWriter, Error, Read, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    rc::Rc,
};

use log::debug;
use nix::unistd::{Uid, User};
use posix_acl::{PosixACL, ACL_EXECUTE, ACL_READ, ACL_WRITE};
use rootasrole_core::database::structs::{SActorType, SConfig, SCredentials};
use sxd_document::writer::format_document;

use crate::policy::Policy;

struct DBusPolicyBuilder {
    system_config: PathBuf,
    rootasrole_folder: PathBuf,
}

fn mkdirs<P: AsRef<Path>>(path: P) -> io::Result<()> {
    fs::create_dir_all(path)
}

impl DBusPolicyBuilder {
    pub(crate) fn new() -> Self {
        let datadir = Self::find_datadir().unwrap();
        let rootasrole_folder = datadir.join("system.d/rootasrole");
        mkdirs(&rootasrole_folder).unwrap();
        DBusPolicyBuilder {
            system_config: datadir.join("system.conf"),
            rootasrole_folder,
        }
    }

    fn find_datadir() -> io::Result<PathBuf> {
        resolve_config_dir(
            "DBUS_CONF_DIR",
            "/usr/share/dbus-1".into(),
            "/etc/dbus-1".into(),
        )
    }

    fn rootasrole_folder(&self) -> PathBuf {
        self.rootasrole_folder.clone()
    }

    fn insert_new_dbus_config_folder(&self) -> io::Result<()> {
        // read self.system_config and add <includedir>/etc/dbus-1/system.d/rootasrole</includedir> at the end of xml file (if not already present)
        //use sxd_document
        debug!(
            "Inserting new dbus config folder at {:?}",
            self.system_config
        );
        let mut file = File::open(&self.system_config)?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;
        //split header until <busconfig> tag
        let (header, contents) = contents.split_at(contents.find("<busconfig>").unwrap());
        debug!("Contents: {}", contents);
        let package = sxd_document::parser::parse(&contents).unwrap();
        let doc = package.as_document();
        let root = &doc.root();
        //check if there is already an includedir tag for
        let includedir_exists = root.children().first().unwrap().element().unwrap().children().into_iter().any(|node| {
            node.element()
                .and_then(|element| {
                    if element.name().local_part() == "includedir" {
                        element.children().first().and_then(|child| child.text())
                    } else {
                        None
                    }
                })
                .map_or(false, |text| {
                    text.text() == self.rootasrole_folder.to_str().unwrap()
                })
        });

        if !includedir_exists {
            let new_includedir = doc.create_element("includedir");
            new_includedir.append_child(doc.create_text(&self.rootasrole_folder.to_str().unwrap()));
            root.children().first().unwrap().element().unwrap().append_child(new_includedir);
            debug!("New includedir added");
            let mut writer = BufWriter::new(Vec::new());
            format_document(&doc, &mut writer).unwrap();
            let mut contents = String::from_utf8(writer.into_inner().unwrap()).unwrap();
            //remove the <?xml version="1.0" encoding="UTF-8"?> line
            contents = contents.split_once("?>").unwrap().1.to_string();
            let mut writer = File::create(&self.system_config)?;
            writer.write_all(header.as_bytes())?;
            writer.write_all(contents.as_bytes())?;
            writer.flush()?;
        }
        Ok(())
    }

    fn indent(level: usize) -> String {
        "    ".repeat(level)
    }

    pub fn add_policy(&mut self, user: &str, dbus_permissions: &[&str]) -> io::Result<()> {
        debug!(
            "Adding dbus policy for user {} at {:?}",
            user,
            self.rootasrole_folder.join(format!("{}.conf", user))
        );
        let mut writer = File::create(self.rootasrole_folder.join(format!("{}.conf", user)))?;
        writer.write_all(DBusPolicyBuilder::header().as_bytes())?;
        writer.write_all(b"<busconfig>\n")?;
        let mut policy = format!("{}<policy user=\"{}\">", Self::indent(1), user);
        for permission in dbus_permissions {
            policy.push_str(&format!(
                "{}<allow send_destination=\"{}\"/>",
                Self::indent(2),
                permission
            ));
        }
        policy.push_str(&format!("{}</policy>\n</busconfig>", Self::indent(1)));
        writer.write_all(policy.as_bytes())?;
        writer.flush()?;
        Ok(())
    }

    fn header() -> &'static str {
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE busconfig PUBLIC
 "-//freedesktop//DTD D-BUS Bus Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
"#
    }

    pub(crate) fn build(&self) -> io::Result<()> {
        self.insert_new_dbus_config_folder()?;
        Ok(())
    }

    fn reload_dbus() -> io::Result<()> {
        Command::new("systemctl")
            .arg("reload")
            .arg("dbus")
            .status()?;
        Ok(())
    }

    #[allow(
        dead_code,
        reason = "Dbus already enforce the policy when the file is written"
    )]
    pub(crate) fn enforce(&self) -> io::Result<()> {
        Self::reload_dbus()
    }
}

fn resolve_config_dir(
    env_key: &str,
    first_dir: PathBuf,
    second_dir: PathBuf,
) -> Result<PathBuf, Error> {
    match env::var(env_key) {
        Ok(dir) => {
            let dbus_dir = Path::new(&dir);
            if dbus_dir.is_dir() {
                return Ok(dbus_dir.into());
            } else {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "Cannot find dbus policy folder location",
                ));
            }
        }
        Err(_) => {
            if first_dir.is_dir() {
                return Ok(first_dir);
            }
            if second_dir.is_dir() {
                return Ok(second_dir);
            }
            return Err(io::Error::new(io::ErrorKind::NotFound, "Cannot find dbus policy folder location, please use DBUS_CONF_DIR env variable to specify the location"));
        }
    }
}

type PolkitPolicy = HashMap<String, PolkitActionSet>;

type PolkitActionSet = HashSet<String>;

struct PolkitPolicyWorker {
    rules_folder: PathBuf,
}

impl PolkitPolicyWorker {
    pub(crate) fn new() -> Self {
        let datadir = resolve_config_dir(
            "POLKIT_DATA_DIR",
            "/usr/share/polkit-1".into(),
            "/etc/polkit-1".into(),
        )
        .unwrap();
        PolkitPolicyWorker {
            rules_folder: datadir.join("rules.d"),
        }
    }

    pub(crate) fn add_policy(&self, user: &str, dbus_permissions: &[&str]) -> io::Result<()> {
        //if file exists 
        let mut policy: PolkitPolicy = if self.get_policy_file_path().exists() {
            serde_json::from_reader(File::open(self.get_policy_file_path())?)?
        } else {
            PolkitPolicy::new()
        };
        let permissions: HashSet<String> = dbus_permissions.iter().map(|s| s.to_string()).collect();
        policy
            .get_mut(user)
            .get_or_insert(&mut HashSet::new())
            .extend(permissions);
        let writer = File::create(self.get_policy_file_path())?;
        serde_json::to_writer(writer, &policy)?;
        Ok(())
    }

    pub(crate) fn get_policy_file_path(&self) -> PathBuf {
        self.rules_folder.join("rootasrole.json")
    }
    
    pub(crate) fn check_policy(&self, user: &str, action: &str) -> anyhow::Result<bool> {
        let policy: PolkitPolicy = self.polkit_policy()?;
        if let Some(actions) = policy.get(user) {
            return Ok(actions.contains(action));
        }
        Ok(false)
    }

    fn polkit_policy(&self) -> anyhow::Result<HashMap<String, HashSet<String>>> {
        Ok(serde_json::from_reader(File::open(
            self.get_policy_file_path(),
        )?)?)
    }

    pub(crate) fn build(&self) -> anyhow::Result<()> {
        let mut rule_file = File::create(self.rules_folder.join("rootasrole.js"))?;
        let template = include_str!("./rootasrole_polkit.js");
        //format the template with the current binary path
        let formatted = template.replace("{{BINARY_PATH}}", env::current_exe()?.to_str().unwrap());
        rule_file.write_all(formatted.as_bytes())?;
        Ok(())
    }

    fn del_policy(&self, username: &str) -> anyhow::Result<()> {
        let mut policy: PolkitPolicy = self.polkit_policy()?;
        policy.remove(username);
        let writer = File::create(self.get_policy_file_path())?;
        serde_json::to_writer(writer, &policy)?;
        Ok(())
    }
}

fn str_to_permission(perm: &str) -> anyhow::Result<u32> {
    let mut perms = 0;
    for c in perm.chars() {
        match c {
            'r' | 'R' => perms |= ACL_READ,
            'w' | 'W' => perms |= ACL_WRITE,
            'x' | 'X' => perms |= ACL_EXECUTE,
            _ => return Err(anyhow::anyhow!("Invalid permission")),
        }
    }
    return Ok(perms);
}

fn set_acl<P: AsRef<Path>>(user: &Uid, path: P, permissions: &str) -> anyhow::Result<()> {
    debug!(
        "Setting {} ACL for user {} on path {}",
        permissions,
        user,
        path.as_ref().display()
    );
    let mut acl = PosixACL::read_acl(&path)?;
    let current = acl
        .get(posix_acl::Qualifier::User(user.as_raw()))
        .unwrap_or(0);
    acl.set(
        posix_acl::Qualifier::User(user.as_raw()),
        current | str_to_permission(permissions)?,
    );
    acl.write_acl(&path)?;
    Ok(())
}

fn del_acl<P: AsRef<Path>>(user: &Uid, path: P) -> anyhow::Result<()> {
    let mut acl = PosixACL::read_acl(&path)?;
    acl.remove(posix_acl::Qualifier::User(user.as_raw()));
    acl.write_acl(&path)?;
    Ok(())
}

pub(crate) fn setup_role_based_access(config: &Rc<RefCell<SConfig>>) -> io::Result<()> {
    let mut builder = DBusPolicyBuilder::new();
    for role in &config.as_ref().borrow().roles {
        let role = role.as_ref().borrow();
        let r_name = &role.name;
        for task in &role.tasks {
            let task = task.as_ref().borrow();
            let username = format!("{}-{}", r_name, &task.name);
            let user = useradd(&username)?;
            let cred = &task.cred;
            deploy_acl(cred, user)?;
            deploy_dbus(cred, &mut builder, &username)?;
            deploy_polkit(cred, &username)?;
        }
    }
    builder.build()?;
    builder.enforce()?;
    Ok(())
}

pub(crate) fn remove_role_based_access(config: &Rc<RefCell<SConfig>>) -> io::Result<()> {
    let dbus_policy_file = DBusPolicyBuilder::new().rootasrole_folder();
    fs::remove_dir_all(dbus_policy_file)?;
    let polkit_policy = PolkitPolicyWorker::new();
    for role in &config.as_ref().borrow().roles {
        let role = role.as_ref().borrow();
        for task in &role.tasks {
            let task = task.as_ref().borrow();
            let creds = &task.cred;
            match creds.setuid.as_ref() {
                Some(SActorType::Name(username)) => {
                    if username.starts_with("rar_") || username.starts_with("gsr_") {
                        let user = User::from_name(username).unwrap().unwrap();
                        polkit_policy.del_policy(username).map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
                        remove_acl(creds, user)?;
                        userdel(username)?;
                    }
                }
                _ => {}
            }
        }
    }
    Ok(())
}
//
pub(crate) fn enforce_policy(username: &str, policy: &Policy) -> anyhow::Result<()> {
    let user = useradd(username)?;
    for (path, permission) in &policy.files {
        set_acl(&user.uid, path, &permission.to_string())?;
    }
    let dbus_vec = policy
        .dbus
        .iter()
        .map(|s| s.as_str())
        .collect::<Vec<&str>>();
    let mut builder = DBusPolicyBuilder::new();
    builder.add_policy(username, &dbus_vec)?;
    //polkit for loop
    builder.build()?;
    let worker = PolkitPolicyWorker::new();
    worker.add_policy(username, &dbus_vec)?;
    worker.build()?;
    Ok(())
}

pub(crate) fn remove_policy(username: &str, policy: &Policy) -> anyhow::Result<()> {
    let user = User::from_name(username)?
        .expect(format!("User {} wasn't created correctly", username).as_str());
    for (path, _) in &policy.files {
        del_acl(&user.uid, path)?;
    }
    userdel(username)?;
    let dbus_policy_file = DBusPolicyBuilder::new().rootasrole_folder();
    if dbus_policy_file.join(format!("{}.conf", username)).exists() {
        fs::remove_file(dbus_policy_file.join(format!("{}.conf", username)))?;
    }
    let worker = PolkitPolicyWorker::new();
    worker.del_policy(username)?;
    Ok(())
}

fn userdel(username: &str) -> Result<(), Error> {
    Command::new("userdel").arg("-r").arg(username).status()?;
    Ok(())
}

fn useradd(username: &str) -> Result<User, Error> {
    if let Some(user) = User::from_name(username)? {
        debug!("User {} already exists", username);
        Ok(user)
    } else {
        let mut binding = Command::new("/usr/bin/useradd");
        let c = binding
            .arg("-r")
            .arg("-M")
            .arg("-s")
            .arg("/bin/sh")
            .arg(username)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let output = c.output()?;
        if !output.status.success() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!(
                    "Failed to create user {}: {}",
                    username,
                    String::from_utf8_lossy(&output.stderr)
                ),
            ));
        }
        debug!("Creating user5 {}", username);
        Ok(User::from_name(username)?
            .expect(format!("User {} wasn't created correctly", username).as_str()))
    }
}

fn deploy_dbus(
    cred: &SCredentials,
    builder: &mut DBusPolicyBuilder,
    username: &str,
) -> io::Result<()> {
    if let Some(dbus) = cred
        ._extra_fields
        .get("dbus")
        .map(|value| value.as_array())
        .flatten()
    {
        for object in dbus {
            let permissions: Vec<&str> = object
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_str().unwrap())
                .collect();
            builder.add_policy(&username, &permissions)?;
        }
    }
    Ok(())
}

fn deploy_polkit(cred: &SCredentials, username: &str) -> io::Result<()> {
    let worker = PolkitPolicyWorker::new();
    if let Some(dbus) = cred
        ._extra_fields
        .get("dbus")
        .map(|value| value.as_array())
        .flatten()
    {
        for object in dbus {
            let permissions: Vec<&str> = object
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_str().unwrap())
                .collect();
            worker.add_policy(&username, &permissions)?;
        }
    }
    Ok(())
}

fn deploy_acl(cred: &SCredentials, user: User) -> Result<(), Error> {
    if let Some(files) = cred
        ._extra_fields
        .get("files")
        .map(|value| value.as_object())
        .flatten()
    {
        for (path, permission) in files {
            let file_path = path.as_str();
            let permission = permission.as_str().unwrap();
            set_acl(&user.uid, file_path, permission)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
        }
    }
    Ok(())
}

fn remove_acl(cred: &SCredentials, user: User) -> Result<(), Error> {
    if let Some(files) = cred
        ._extra_fields
        .get("files")
        .map(|value| value.as_object())
        .flatten()
    {
        for (path, _) in files {
            let file_path = path.as_str();
            del_acl(&user.uid, file_path)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
        }
    }
    Ok(())
}

pub(crate) fn check_polkit(user: &str, action: &str) -> io::Result<()> {
    let worker = PolkitPolicyWorker::new();
    match worker.check_policy(user, action) {
        Ok(true) => Ok(()),
        Err(e) => Err(io::Error::new(io::ErrorKind::Other, e.to_string())),
        Ok(false) => Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Permission denied",
        )),
    }
}
