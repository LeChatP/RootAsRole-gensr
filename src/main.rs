use std::{cell::RefCell, collections::HashMap, io, rc::{Rc, Weak}};

use capable::Policy;
use clap::{Parser, Subcommand};
use log::{warn, LevelFilter};
use nix::unistd::{setuid, Uid};
use rootasrole_core::database::{structs::{IdTask, SActorType, SConfig, SGroups, SRole, STask}, wrapper::SRoleWrapper};
use serde_json::Value;

mod deploy;
mod capable;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Execute an action for a user using polkit
    Polkit {
        /// The user to perform the action for
        #[arg(short, long)]
        user: String,
        /// The action to perform
        #[arg(short, long)]
        action: String,
    },
    /// Run ansible with specified playbook and task
    Ansible {
        /// Path to the rootasrole configuration file
        #[arg(short, long)]
        config: Option<String>,
        /// Path to the ansible playbook
        #[arg(short, long)]
        playbook: String,
        /// Name of the task to execute
        #[arg(short, long)]
        task: String,
        /// Additional ansible commands
        #[arg(last = true)]
        command: Vec<String>,
    },
    /// Perform actions as root with a specified role
    Rootasrole {
        /// Auto-confirm actions without prompting
        #[arg(short, long)]
        yes: bool,
        /// Path to the configuration file
        #[clap(short, long, default_value = "/etc/security/rootasrole.json")]
        config: String,
    },
}


fn main() -> io::Result<()> {
    //init tracing at DEBUG level
    env_logger::builder().default_format().filter_level(LevelFilter::Debug).init();
    let args = Cli::parse();
    match args.command {
        Commands::Polkit { user, action } => {
            deploy::check_polkit(&action, &user)
        },
        Commands::Ansible { config,
                playbook, task, command } => {
            let mut capable = capable::Capable::new(command);
            let mut policy = Policy::default();
            let mut first = true;
            let mut looping = 0;
            while !capable.has_ran() || capable.is_failed() {
                if looping > 0 {
                    //test as root
                    eprintln!("Failed to get policy, trying as root");
                    setuid(Uid::from_raw(0)).unwrap();//.map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
                }
                let p = capable.run().unwrap();//.map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
                if looping > 0 && capable.is_failed() {
                    policy.remove(&playbook, &task).unwrap();
                    print!("{}", capable.last_stdout);
                    eprint!("{}", capable.last_stderr);
                    return Err(io::Error::new(io::ErrorKind::Other, format!("Failed to get policy for playbook '{}' and task '{}'", playbook, task)));
                } else if p == policy  {
                    looping += 1;
                } else {
                    looping = 0;
                }
                if !first {
                    policy.remove(&playbook, &task).unwrap()//.map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
                }
                policy = p;
                if capable.is_failed() { 
                    policy.apply(&playbook, &task).unwrap()//.map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
                }
                first = false;
                
            }
            let task = Rc::new(RefCell::new(policy.to_stask(&playbook, &task)));
            if let Some(config) = config {
                let settings = rootasrole_core::get_settings(&config).map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
                let config = &settings.as_ref().borrow().config;
                if let Some(role) = config.clone().as_ref().borrow_mut().role(&playbook) {
                    if role.as_ref().borrow_mut().tasks.iter().any(|t| {
                        *t == task
                    }) {
                        warn!("Task '{}' already exists in role '{}'", task.as_ref().borrow().name, playbook);
                    } else {
                        task.as_ref().borrow_mut()._role = Some(Rc::downgrade(role));
                        role.as_ref().borrow_mut().tasks.push(task.clone());
                    }
                } else {
                    let mut role = SRole::new(playbook.clone(), Rc::<RefCell<SConfig>>::downgrade(&config));
                    role.tasks.push(task.clone());
                    config.clone().as_ref().borrow_mut().roles.push(Rc::new(RefCell::new(role)));
                }
                
            }
            println!("{}", serde_json::to_string_pretty(&task).unwrap());
            Ok(())
        },
        Commands::Rootasrole { yes, config } => {
            //WIP
            panic!("Not implemented");
            prompt_for_confirmation(yes)?;
            let settings = rootasrole_core::get_settings(&config).map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
            let config = &settings.as_ref().borrow().config;
            deploy::setup_role_based_access(config)
        },
    }
}

fn prompt_for_confirmation(yes: bool) -> Result<(), io::Error> {
    let mut input = String::new();
    Ok(while !yes && input.trim().to_ascii_lowercase() != "y" {
        if input.trim().to_ascii_lowercase() == "n" {
            return Ok(());
        } else if !input.is_empty()  {
            println!("Invalid input. Please enter 'y' or 'n'");
        }
        println!("This will setup the roles and permissions for the system. Continue? [y/N]");
        io::stdin().read_line(&mut input)?;
    })
}


