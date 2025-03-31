"""
LFI to RCE techniques for the Elle-Est-Fit framework.
"""

# Import techniques for easy access
from .php_filters import PHPFilterTechnique
from .php_session import PHPSessionTechnique

# List available techniques
available_techniques = [
    "php_filters",
    "php_session"
]