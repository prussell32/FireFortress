import os
import sys
import json
import logging
import subprocess
import shutil
from datetime import datetime
import getpass

class FirewallEnvironment:
    # Initialize with default paths for rules and logs
    def __init__(self, rule_path="rules/default_rules.json", log_path="logs/firewall_automation.log"):
        self.rule_path = rule_path
        self.log_path = log_path
        self.audit_path = f"logs/session_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        self.firewall_type = None
        self.rules = None
        self.user = getpass.getuser()
        self._init_logging()

    # Helper to get current timestamp
    def _timestamp(self):
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Initialize logging configuration
    def _init_logging(self):
        os.makedirs("logs", exist_ok=True)
        logging.basicConfig(
            filename=self.log_path,
            level=logging.INFO,
            format="%(asctime)s [%(levelname)s] %(message)s"
        )
        logging.info(f"{self._timestamp()} Logger initialized by user: {self.user}")
        with open(self.audit_path, "w") as audit:
            audit.write(f"Firewall Automation Session\nUser: {self.user}\nStart: {self._timestamp()}\n\n")
   
    # Audit log helper
    def _audit(self, message):
        with open(self.audit_path, "a") as audit:
            audit.write(f"[{self._timestamp()}] {message}\n")

    # Detect which firewall is active on the system
    def detect_firewall(self):
        logging.info(f"{self._timestamp()} Starting firewall detection...")

        if shutil.which("firewall-cmd"):
            try:
                subprocess.run(["firewall-cmd", "--state"], check=True, stdout=subprocess.DEVNULL)
                self.firewall_type = "firewalld"
                print(f"[{self._timestamp()}] Detected firewalld firewall.")
            except subprocess.CalledProcessError:
                self.firewall_type = "firewalld (inactive)"
                print(f"[{self._timestamp()}] Firewalld installed but inactive.")
        elif shutil.which("ufw"):
            try:
                subprocess.run(["ufw", "status"], check=True, stdout=subprocess.DEVNULL)
                self.firewall_type = "ufw"
                print(f"[{self._timestamp()}] Detected ufw firewall.")
            except subprocess.CalledProcessError:
                self.firewall_type = "ufw (inactive)"
                print(f"[{self._timestamp()}] UFW installed but inactive.")
        elif shutil.which("iptables"):
            try:
                subprocess.run(["iptables", "-L"], check=True, stdout=subprocess.DEVNULL)
                self.firewall_type = "iptables"
                print(f"[{self._timestamp()}] Detected iptables firewall.")
            except subprocess.CalledProcessError:
                self.firewall_type = "iptables (inactive)"
                print(f"[{self._timestamp()}] Iptables installed but inactive.")
        else:
            self.firewall_type = None
            print(f"[{self._timestamp()}] No supported firewall detected.")

        logging.info(f"{self._timestamp()} Detected firewall: {self.firewall_type}")
        self._audit(f"Detected firewall type: {self.firewall_type}")
        return self.firewall_type

    # Prepare environment: detect firewall and load rules
    def prepare(self):
        try:
            self.detect_firewall()
            if not self.firewall_type or "inactive" in self.firewall_type:
                logging.error(f"{self._timestamp()} No active firewall detected.")
                self._audit("ERROR: No active firewall detected.")
                return False

            rules = self.load_rules()
            if not rules:
                logging.error(f"{self._timestamp()} Failed to load firewall rules.")
                self._audit("ERROR: Failed to load firewall rules.")
                return False

            logging.info(f"{self._timestamp()} Environment preparation complete.")
            self._audit("Environment preparation complete.")
            return True

        except Exception as e:
            logging.error(f"{self._timestamp()} Exception during environment preparation: {e}")
            self._audit(f"ERROR: Exception during environment preparation: {e}")
            return False
        
    # Load rules from JSON file, create default if not present
    def load_rules(self):
        logging.info(f"{self._timestamp()} Attempting to load rule template: {self.rule_path}")
        if not os.path.exists(self.rule_path):
            logging.warning(f"{self._timestamp()} Rule file not found: {self.rule_path}")
            self._audit(f"WARNING: Rule file not found. Creating default rule template.")
            os.makedirs(os.path.dirname(self.rule_path), exist_ok=True)
            default_rules = [
                {
                    "action": "ALLOW",
                    "protocol": "tcp",
                    "port": 22,
                    "direction": "INPUT"
                },
                {
                    "action": "DENY",
                    "protocol": "udp",
                    "port": 53,
                    "direction": "INPUT"
                },
                {
                    "action": "ALLOW",
                    "protocol": "tcp",
                    "port": 80,
                    "direction": "INPUT"
                },
                {
                    "action": "ALLOW",
                    "protocol": "tcp",
                    "port": 443,
                    "direction": "INPUT"
                }
            ]
            try:
                with open(self.rule_path, "w") as f:
                    json.dump(default_rules, f, indent=4)
                logging.info(f"{self._timestamp()} Default rule template created.")
                self._audit("Default rule template created.")
            except Exception as e:
                logging.error(f"{self._timestamp()} Failed to create default rule file: {e}")
                self._audit(f"ERROR: Failed to create default rule file: {e}")
                return None

        try:
            with open(self.rule_path, "r") as f:
                self.rules = json.load(f)
            logging.info(f"{self._timestamp()} Successfully loaded rules.")
            self._audit(f"Loaded {len(self.rules)} rules from template.")
            return self.rules
        except json.JSONDecodeError as e:
            logging.error(f"{self._timestamp()} Failed to parse rule file: {e}")
            self._audit(f"ERROR: Failed to parse rule file: {e}")
            return None
        
    # Validate individual rule structure
    def validate_rule(self, rule):
        required_keys = {"action", "protocol", "port", "direction"}
        if not all(key in rule for key in required_keys):
            logging.warning(f"{self._timestamp()} Invalid rule format: {rule}")
            self._audit(f"WARNING: Invalid rule skipped: {rule}")
            return False
        return True
    
    # Apply loaded rules to the detected firewall
    def apply_rules(self):
        if not self.rules or not self.firewall_type:
            logging.error(f"{self._timestamp()} Cannot apply rules: missing rules or firewall type.")
            self._audit("ERROR: Cannot apply rules due to missing context.")
            return False

        logging.info(f"{self._timestamp()} Applying rules...")
        self._audit("Beginning rule application...")

        for rule in self.rules:
            if not self.validate_rule(rule):
                continue

            action = rule["action"].lower()
            protocol = rule["protocol"]
            port = str(rule["port"])
            direction = rule["direction"].lower()

            try:
                if self.firewall_type == "iptables":
                    cmd = ["iptables", "-A", direction, "-p", protocol, "--dport", port, "-j", action.upper()]
                elif self.firewall_type == "firewalld":
                    cmd = ["firewall-cmd", "--permanent", "--add-port=" + port + "/" + protocol]
                elif self.firewall_type == "ufw":
                    if action not in {"allow", "deny", "reject", "limit"}:
                        logging.warning(f"{self._timestamp()} Unsupported UFW action: {action}")
                        self._audit(f"WARNING: Unsupported UFW action: {action}")
                        continue
                    cmd = ["ufw", action, port + "/" + protocol]
                else:
                    logging.error(f"{self._timestamp()} Unsupported firewall type.")
                    self._audit("ERROR: Unsupported firewall type.")
                    return False

                subprocess.run(cmd, check=True)
                logging.info(f"{self._timestamp()} Applied rule: {rule}")
                self._audit(f"Applied rule: {rule}")
            except subprocess.CalledProcessError as e:
                logging.error(f"{self._timestamp()} Failed to apply rule {rule}: {e}")
                self._audit(f"ERROR: Failed to apply rule: {rule} — {e}")
                return False

        if self.firewall_type == "firewalld":
            try:
                subprocess.run(["firewall-cmd", "--reload"], check=True)
                logging.info(f"{self._timestamp()} Reloaded firewalld.")
                self._audit("Reloaded firewalld after rule application.")
            except subprocess.CalledProcessError as e:
                logging.error(f"{self._timestamp()} Failed to reload firewalld: {e}")
                self._audit(f"ERROR: Failed to reload firewalld: {e}")
                return False

        print(f"[{self._timestamp()}] All rules applied successfully.")
        self._audit("All rules applied successfully.")

        if self.firewall_type == "ufw":
            self.log_firewall_state()

        return True

    # Log current firewall state (for ufw)
    def log_firewall_state(self):
        try:
            result = subprocess.run(["ufw", "status", "verbose"], check=True, capture_output=True, text=True)
            state_output = result.stdout.strip()
            logging.info(f"{self._timestamp()} Current UFW state:\n{state_output}")
            self._audit("Current UFW state:\n" + state_output)
            print(f"[{self._timestamp()}] Logged current UFW state.")
        except subprocess.CalledProcessError as e:
            logging.error(f"{self._timestamp()} Failed to retrieve UFW state: {e}")
            self._audit(f"ERROR: Failed to retrieve UFW state: {e}")

    # Print current firewall settings
    def print_firewall_settings(self):
        print(f"[{self._timestamp()}] Printing current firewall settings...")
        if self.firewall_type == "ufw":
            subprocess.run(["ufw", "status", "verbose"])
        elif self.firewall_type == "firewalld":
            try:
                subprocess.run(["firewall-cmd", "--list-all"], check=True)
            except subprocess.CalledProcessError as e:
                logging.error(f"{self._timestamp()} Failed to list firewalld settings: {e}")
                self._audit(f"ERROR: Failed to list firewalld settings: {e}")
                print("Failed to list firewalld settings. Firewalld may be inactive or misconfigured.")
        elif self.firewall_type == "iptables":
            subprocess.run(["iptables", "-L"])
        else:
            print(f"[{self._timestamp()}] No supported firewall detected or firewall inactive.")

# Main execution
if __name__ == "__main__":
    if os.geteuid() != 0:
        print("ERROR: You need to be root to run this script")
        sys.exit(1)

    env = FirewallEnvironment()
    if env.prepare():
        success = env.apply_rules()
        if success:
            print("Firewall rules applied successfully.")
            env.print_firewall_settings()  
        else:
            print("Failed to apply firewall rules.")
    else:
        print("Failed to set up the firewall environment.")