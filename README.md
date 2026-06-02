# Home Security Operations Center (SOC) Lab

A home lab project that automates the deployment of a complete security operations environment using Ansible. One command configures a hardened Linux server, deploys a Wazuh security monitoring agent, and prepares the environment for simulated attacks from a Kali Linux machine.

## Overview

This project demonstrates end-to-end security automation across three areas:

- **Infrastructure automation** — Ansible playbooks deploy and configure all components
- **Defensive security** — A Linux server is hardened against common attack vectors
- **Threat detection** — Wazuh monitors the target in real time and alerts on suspicious activity

## Lab Architecture

| Role | OS | Notes |
|---|---|---|
| Control Node | Fedora Linux | Ansible runs from here |
| Target / Agent | Ubuntu Server | Hardened target with Wazuh agent |
| Monitoring / Manager | Ubuntu Server | Wazuh manager and dashboard |
| Attacker | Kali Linux | Used to simulate attacks |

## Project Structure

```
home-soc-lab/
├── master.yaml                  # Single entry point — runs all playbooks
├── inventory.yml                # Target hosts (not tracked in git)
├── playbook.yml                 # Nginx web server deployment
├── files/
│   └── index.html               # Custom web page
├── serverHarding/
│   └── playbook.yaml            # Server hardening playbook
└── ansible-waxuh/
    └── wazuh-playbook.yaml      # Wazuh agent deployment playbook
```

## What Gets Automated

### Server Hardening (`serverHarding/playbook.yaml`)
- Firewall configuration with `ufw` — default deny, allow SSH and port 80 only
- SSH hardening via `lineinfile`:
  - Password authentication disabled
  - Root login disabled
  - `MaxAuthTries` reduced to 3
- SSH service restarts automatically via Ansible handlers when config changes

### Wazuh Agent Deployment (`ansible-waxuh/wazuh-playbook.yaml`)
- Downloads the Wazuh agent package directly from Wazuh's servers using `get_url`
- Installs the agent with the manager IP baked in at install time
- Starts the `wazuh-agent` service and enables it to persist across reboots

## Running the Lab

Deploy everything with a single command from the control node:

```bash
ansible-playbook -i inventory.yml master.yaml
```

## Simulated Attack

With the lab deployed, attacks are simulated from Kali Linux using Hydra:

```bash
hydra -l <user> -P /usr/share/wordlists/rockyou.txt <target-ip> ssh
```

The SSH hardening (`MaxAuthTries 3`) limits the attack surface, while Wazuh detects and alerts on the repeated failed authentication attempts in real time via its dashboard.

## Tools & Technologies

- **Ansible** — Infrastructure automation (modules: `ufw`, `lineinfile`, `get_url`, `shell`, `service`, `copy`, `apt`)
- **Wazuh** — Open source SIEM and security monitoring
- **Kali Linux / Hydra** — Attack simulation
- **ufw** — Linux firewall management
- **systemd** — Service persistence
- **SSH** — Key-based authentication with ed25519 keys
