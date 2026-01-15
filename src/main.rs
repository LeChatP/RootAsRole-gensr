use std::{
    cell::RefCell,
    io,
    path::{Path, PathBuf},
    rc::Rc,
};

use bon::builder;
use clap::{Parser, Subcommand, ValueEnum};
use log::{warn, LevelFilter};
use nix::unistd::{setgid, setgroups, setuid, Gid, Uid};
use policy::Policy;
use rootasrole_core::{
    database::{
        options::{EnvBehavior, SAuthentication, SEnvOptions},
        structs::{SConfig, SRole},
        versionning::Versioning,
    },
    FullSettings, RemoteStorageSettings, SettingsContent, StorageMethod,
};
use serde_json::json;
use sha2::Digest;

mod capable;
mod deploy;
mod policy;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Clone, ValueEnum)]
enum Mode {
    Auto,
    Manual,
}

#[derive(Subcommand)]
enum Commands {
    /// Test if a user can perform an action
    Polkit {
        /// The user to perform the action for
        #[arg(short, long)]
        user: String,
        /// The action to perform
        #[arg(short, long)]
        action: String,
    },
    /// Generate a policy for a task
    Generate {
        ///TODO: --mode auto|manual
        #[arg(short, long, default_value = "auto")]
        mode: Mode,
        /// capable path location
        #[arg(long)]
        capable: Option<PathBuf>,
        /// Fail-then-add: Start with an empty privilege set, add privileges as the command fails, re-execute the command until it succeeds
        /// If not set, the command will be executed with the full privilege set directly, respecting the Replace-then-record approach
        #[arg(short, long, default_value = "false")]
        fail_then_add: bool,

        /// Loop until the command succeed
        #[arg(short, long, default_value = "false")]
        no_loop: bool,

        /// Path to the rootasrole configuration file
        #[arg(short, long)]
        config: Option<String>,
        /// Role name to assign the task to
        #[arg(short, long)]
        role: Option<String>,
        /// Name of the task to generate
        #[arg(short, long)]
        task: Option<String>,
        /// UUID to assign to the task
        #[arg(short, long)]
        uuid: Option<String>,
        /// Whether the password should be supplied.
        #[clap(default_value = "skip")]
        password_policy: String,

        /// Additional ansible commands
        #[arg(last = true)]
        command: Vec<String>,
    },
    /// Deploy rootasrole to the system
    Deploy {
        /// Path to the rootasrole configuration file
        #[arg(short, long, default_value = "/etc/security/rootasrole.json")]
        config: String,

        /// Skip the confirmation prompt
        #[arg(short, long)]
        yes: bool,
    },
    /// Undeploy rootasrole from the system
    Undeploy {
        /// Path to the rootasrole configuration file
        #[arg(short, long, default_value = "/etc/security/rootasrole.json")]
        config: String,

        /// Skip the confirmation prompt
        #[arg(short, long)]
        yes: bool,
    },
}

fn parse_sauthentication(auth: &str) -> anyhow::Result<SAuthentication> {
    Ok(match auth {
        "skip" => SAuthentication::Skip,
        "perform" => SAuthentication::Perform,
        _ => {
            return Err(anyhow::anyhow!(
                "Only 'skip' and 'perform' are allowed for password_policy"
            ))
        }
    })
}

fn main() -> io::Result<()> {
    #[cfg(debug_assertions)]
    env_logger::builder()
        .default_format()
        .filter_level(LevelFilter::Debug)
        .init();
    #[cfg(not(debug_assertions))]
    env_logger::builder()
        .default_format()
        .filter_level(LevelFilter::Info)
        .init();
    let args = Cli::parse();
    match args.command {
        Commands::Polkit { user, action } => deploy::check_polkit(&action, &user),
        Commands::Generate {
            mode,
            config,
            role,
            task,
            uuid,
            command,
            fail_then_add,
            capable,
            no_loop,
            password_policy,
        } => {
            // TODO: --mode auto|manual
            let username = match (&role, &task) {
                (Some(role), Some(task)) => get_username_ansible(role, task),
                _ => get_username_gensr(&command),
            };
            let mut capable = capable::Capable::builder()
                .fail_then_add(fail_then_add)
                .command(command)
                .maybe_path(capable)
                .build()
                .unwrap();
            let mut policy = Policy::default();
            policy.password_prompt = parse_sauthentication(&password_policy)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
            if fail_then_add && !no_loop {
                fail_then_add_loop(role.clone(), &task, &username, capable, &mut policy).unwrap();
            } else {
                policy = capable.run().unwrap();
            }
            output_policy()
                .mode(mode)
                .username(&username)
                .policy(policy)
                .maybe_uuid(uuid)
                .maybe_config(config)
                .maybe_role(role)
                .maybe_task(task)
                .call()
        }
        Commands::Deploy { yes, config } => {
            prompt_for_confirmation(yes, &config)?;
            let config = load_configuration(config)?;
            deploy::setup_role_based_access(&config)
        }
        Commands::Undeploy { yes, config } => {
            prompt_for_confirmation(yes, &config)?;
            let config = load_configuration(config)?;
            deploy::remove_role_based_access(&config)
        }
    }
}

fn load_configuration(config: String) -> Result<Rc<RefCell<SConfig>>, io::Error> {
    let config = if config.ends_with("json") {
        rootasrole_core::retrieve_sconfig(
            &rootasrole_core::StorageMethod::JSON,
            &Path::new(&config).to_path_buf(),
        )
    } else {
        rootasrole_core::retrieve_sconfig(
            &rootasrole_core::StorageMethod::CBOR,
            &Path::new(&config).to_path_buf(),
        )
    }
    .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
    Ok(config)
}

#[builder]
fn output_policy(
    mode: Mode,
    config: Option<String>,
    uuid: Option<String>,
    role: Option<String>,
    task: Option<String>,
    username: &str,
    policy: Policy,
) -> Result<(), io::Error> {
    Ok(match mode {
        Mode::Auto => {
            let role_name = role.unwrap_or(username.to_string());
            let stask = policy.to_stask(
                username,
                uuid.as_deref(),
                |f| {
                    f.authentication(SAuthentication::Skip)
                        .env(SEnvOptions::builder(EnvBehavior::Delete).build())
                        .build()
                },
                task.as_deref()
                    .map(|t| format!("{} (Generated by rootasrole)", t)),
            );
            if let Some(config_path) = config {
                let fullsettings =
                    if Path::new(&config_path).exists() && let Ok(fullsettings) = rootasrole_core::read_full_settings(&config_path) {
                            let fullsettings_ref = fullsettings.as_ref().borrow();
                            let config =
                                fullsettings_ref.config.as_ref().ok_or_else(
                                    || {
                                        io::Error::new(
                                            io::ErrorKind::Other,
                                            "No config found in settings",
                                        )
                                    },
                                )?;
                            let mut config_ref = config.as_ref().borrow_mut();
                            if let Some(role) = config_ref
                                .roles
                                .iter()
                                .find(|r| r.as_ref().borrow().name == role_name)
                            {
                                if role.as_ref().borrow_mut().tasks.iter().any(|t| {
                                    t.as_ref().borrow().name == stask.as_ref().borrow().name
                                }) {
                                    warn!(
                                        "Task '{}' already exists in role '{}'",
                                        stask.as_ref().borrow().name,
                                        username
                                    );
                                } else {
                                    stask.as_ref().borrow_mut()._role = Some(Rc::downgrade(role));
                                    role.as_ref().borrow_mut().tasks.push(stask.clone());
                                }
                            } else {
                                let role = SRole::builder(role_name.clone())
                                    .extra_fields(
                                        json!({"purpose" : role_name})
                                            .as_object()
                                            .cloned()
                                            .unwrap(),
                                    )
                                    .task(stask.clone())
                                    .build();
                                config_ref.roles.push(role);
                            }
                            fullsettings.clone()
                    } else {
                        Rc::new(RefCell::new(FullSettings::builder()
                            .storage(
                                SettingsContent::builder()
                                    .method(StorageMethod::JSON)
                                    .settings(
                                        RemoteStorageSettings::builder().path(&config_path).build(),
                                    )
                                    .build(),
                            )
                            .config(
                                SConfig::builder().role(
                                    SRole::builder(role_name.clone())
                                        .extra_fields(
                                            json!({"purpose" : role_name})
                                                .as_object()
                                                .cloned()
                                                .unwrap(),
                                        )
                                        .task(stask.clone())
                                        .build(),
                                ).build(),
                            )
                            .build()))
                    };

                // Create a file manually without save_settings
                let file = std::fs::File::create(&config_path)
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
                serde_json::to_writer_pretty(&file, &Versioning::new(fullsettings.clone()))
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
                file.sync_all()
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
                //println!("{}", serde_json::to_string_pretty(&settings).unwrap());
            } else {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&*stask.as_ref().borrow()).unwrap()
                )
            };
        }
        Mode::Manual => {
            println!("{}", serde_json::to_string_pretty(&policy).unwrap());
        }
    })
}

fn fail_then_add_loop(
    playbook: Option<String>,
    task: &Option<String>,
    username: &str,
    mut capable: capable::Capable,
    policy: &mut Policy,
) -> Result<(), io::Error> {
    let mut first = true;
    let mut looping = 0;
    // TODO: Fail-then-add don't add additionnal requested privileges if commannd succeed
    while !capable.has_ran() || capable.is_failed() {
        if looping > 0 {
            //test as root
            eprintln!("Failed to get policy, trying as root");
            setuid(Uid::from_raw(0)).unwrap(); //.map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
            setgid(Gid::from_raw(0)).unwrap();
            setgroups(&[Gid::from_raw(0)]).unwrap();
        }
        let p = capable.run().unwrap(); //.map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
        if looping > 0 && capable.is_failed() {
            policy.remove(username).unwrap();
            print!("{}", capable.last_stdout);
            eprint!("{}", capable.last_stderr);
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!(
                    "Failed to get policy for {}",
                    match (&playbook, &task) {
                        (Some(playbook), Some(task)) =>
                            format!("playbook : {} and task {}", playbook, task),
                        _ => format!("the input command"),
                    }
                ),
            ));
        } else if p == *policy {
            looping += 1;
        } else {
            looping = 0;
        }
        if !first {
            policy.remove(username).unwrap() //.map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
        }
        *policy = p;
        if capable.is_failed() {
            policy.apply(username, &mut capable).unwrap() //.map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
        }
        first = false;
    }
    Ok(())
}

fn prompt_for_confirmation(yes: bool, config: &str) -> Result<(), io::Error> {
    let path = Path::new(config);
    if !path.exists() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("Config file not found: {}", config),
        ));
    }
    let mut input = String::new();
    // If the user has passed the --yes flag, we don't need to prompt for confirmation
    if yes {
        return Ok(());
    }
    // Verify that user to continue, y or no input will continue the process and any other input will stop the process
    println!("This will deploy rootasrole config ({}) to the system, are you sure you want to continue? [Y/n]", path.canonicalize().unwrap().to_str().unwrap());
    io::stdin().read_line(&mut input)?;
    if input.trim().to_lowercase() != "y" || !input.trim().is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "User cancelled deployment",
        ));
    }
    Ok(())
}

fn get_username_ansible(playbook: &str, task: &str) -> String {
    let mut hasher = sha2::Sha224::new();
    hasher.update(playbook.as_bytes());
    hasher.update(task.as_bytes());
    let hash = hasher.finalize();
    // transform to string
    format!("rar_{}", hex::encode(hash))
}

fn get_username_gensr(command: &Vec<String>) -> String {
    let mut hasher = sha2::Sha224::new();
    for c in command {
        hasher.update(c.as_bytes());
    }
    let hash = hasher.finalize();
    // transform to string
    format!("gsr_{}", hex::encode(hash))
}
