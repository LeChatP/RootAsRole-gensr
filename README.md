# RootAsRole-utils

## Overview

RootAsRole-utils is a collection of utilities designed to manage and interact with root roles in a secure and efficient manner. These tools help administrators to handle permissions and roles with ease.

## Features

- Manage root roles and permissions
- Secure role-based access control
- Easy integration with existing systems
- Comprehensive logging and auditing

## Installation

To install RootAsRole-utils, clone the repository and build the project using Cargo:

```bash
git clone https://github.com/lechatp/RootAsRole-utils.git
cd RootAsRole-utils
cargo build --release
```

## Usage

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
