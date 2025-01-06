# RootAsRole-gensr

## Overview

RootAsRole-gensr is a tool that generates a policy based on the commands executed by the user. The policy is generated using the RootAsRole model (more information (https://github.com/LeChatP/RootAsRole)[here]). The policy is generated based on the commands executed by the user and the files accessed by the commands.

## Installation

To install RootAsRole-gensr, clone the repository and build the project using Cargo:

```bash
git clone https://github.com/lechatp/RootAsRole-gensr.git
cd RootAsRole-gensr
cargo build --release
```

## Compilation & Execution

### Generate/Update a Policy based on a command

To generate a policy for a task, use the following command:

```bash
cargo run --release --config 'target."cfg(all())".runner="sr"' -- generate --mode <auto|manual> [--config <config_path>] [--playbook <playbook_path>] [--task <task_name>] -- [<The command to study>...]
```

### Deploy Policy Command

To deploy RootAsRole to the system, use the following command:

```bash
cargo run --release --config 'target."cfg(all())".runner="sr"' -- deploy [--config <config_path>] [--yes]
```

### Undeploy Policy Command

To undeploy RootAsRole from the system, use the following command:

```bash
cargo run --release --config 'target."cfg(all())".runner="sr"' -- undeploy [--config <config_path>] [--yes]
```

## Manual Mode

### Build the program

To build the program, use the following command:

```bash
cargo build --release
```

### Execute the program

```bash
sr ./target/release/gensr generate --config <config_path> --playbook <playbook_path> --task <task_name> -- <The command to study>...
```