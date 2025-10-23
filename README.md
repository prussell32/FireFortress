# Firewall Automation Environment

A Python-based, audit-ready firewall automation tool that detects the active Linux firewall (iptables, firewalld, or ufw), loads JSON-based rule templates, applies them safely, and logs every step for compliance and forensic traceability.

---

## Features

- Auto-detects active firewall: `iptables`, `firewalld`, or `ufw`
- Loads rules from a JSON template (auto-generates defaults if missing)
- Validates rule structure before application
- Applies rules with audit logging and error handling
- Logs firewall state post-application for traceability
- Supports dry-run simulation (optional extension)
- Designed for extensibility and compliance workflows

---

## Requirements

- Python 3.6+
- Linux system with at least one of:
  - `iptables`
  - `ufw`
  - `firewalld`
- Root privileges to apply firewall rules

---

## Usage

```bash
sudo python3 firewall_automation.py
