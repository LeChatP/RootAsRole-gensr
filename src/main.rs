use std::{
    cell::RefCell,
    io,
    path::{Path, PathBuf},
    rc::Rc,
};

use clap::{Parser, Subcommand, ValueEnum};
use log::{warn, LevelFilter};
use nix::unistd::{setgid, setgroups, setuid, Gid, Uid};
use policy::Policy;
use rootasrole_core::{
    database::{
        options::{EnvBehavior, EnvKey, Level, Opt, SAuthentication, SEnvOptions},
        structs::{SConfig, SRole},
        versionning::Versioning,
    },
    rc_refcell,
};
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
        /// Path to the ansible playbook
        #[arg(short, long)]
        playbook: Option<String>,
        /// Name of the task to execute
        #[arg(short, long)]
        task: Option<String>,

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
            playbook,
            task,
            command,
            fail_then_add,
            capable,
            no_loop,
            password_policy,
        } => {
            // TODO: --mode auto|manual
            let username = match (&playbook, &task) {
                (Some(playbook), Some(task)) => get_username_ansible(playbook, task),
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
                fail_then_add_loop(playbook, &task, &username, capable, &mut policy).unwrap();
            } else {
                policy = capable.run().unwrap();
            }
            output_policy(mode, config, task, username, policy)
        }
        Commands::Deploy { yes, config } => {
            prompt_for_confirmation(yes, &config)?;
            let settings = rootasrole_core::get_settings(&config)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
            let config = &settings.as_ref().borrow().config;
            deploy::setup_role_based_access(config)
        }
        Commands::Undeploy { yes, config } => {
            prompt_for_confirmation(yes, &config)?;
            let settings = rootasrole_core::get_settings(&config)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
            let config = &settings.as_ref().borrow().config;
            deploy::remove_role_based_access(config)
        }
    }
}

fn output_policy(
    mode: Mode,
    config: Option<String>,
    task: Option<String>,
    username: String,
    policy: Policy,
) -> Result<(), io::Error> {
    Ok(match mode {
        Mode::Auto => {
            let task = Rc::new(RefCell::new(policy.to_stask(&username, task.as_deref())));
            let mut options = Opt::new(Level::Task);
            options.authentication = Some(SAuthentication::Skip);
            let mut envopt = SEnvOptions::new(EnvBehavior::Delete);
            envopt.keep = policy
                .env_vars
                .keys()
                .map(|k| EnvKey::new(k.clone()).unwrap())
                .collect();
            options.env = Some(envopt);
            task.as_ref().borrow_mut().options = Some(rc_refcell!(options));
            if let Some(config_path) = config {
                let settings = rootasrole_core::get_settings(&config_path)
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
                {
                    let config =
                        rootasrole_core::database::read_json_config(settings.clone(), &config_path)
                            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
                    let mut conf = config.as_ref().borrow_mut();
                    if let Some(role) = conf.role(&username) {
                        if role
                            .as_ref()
                            .borrow_mut()
                            .tasks
                            .iter()
                            .any(|t| t.as_ref().borrow().name == task.as_ref().borrow().name)
                        {
                            warn!(
                                "Task '{}' already exists in role '{}'",
                                task.as_ref().borrow().name,
                                username
                            );
                        } else {
                            task.as_ref().borrow_mut()._role = Some(Rc::downgrade(role));
                            role.as_ref().borrow_mut().tasks.push(task.clone());
                        }
                    } else {
                        let mut role = SRole::new(
                            username.clone(),
                            Rc::<RefCell<SConfig>>::downgrade(&config),
                        );
                        role.tasks.push(task.clone());
                        conf.roles.push(Rc::new(RefCell::new(role)));
                    }
                }
                // Create a file manually without save_settings
                let file = std::fs::File::create(&config_path)
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
                serde_json::to_writer_pretty(&file, &Versioning::new(settings))
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
                file.sync_all()
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
                //println!("{}", serde_json::to_string_pretty(&settings).unwrap());
            }
        }
        Mode::Manual => {
            println!("{}", serde_json::to_string_pretty(&policy).unwrap());
        }
    })
}

fn fail_then_add_loop(
    playbook: Option<String>,
    task: &Option<String>,
    username: &String,
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
