__version__ = "0.1.0"
__author__ = "ElleEstFit Contributors"

from .core import LFI, exploit, info, shell
from .exceptions import ElleEstFitError, TechniqueError, ValidationError

__all__ = [
    "LFI",
    "exploit", 
    "info",
    "shell",
    "ElleEstFitError",
    "TechniqueError",
    "ValidationError"
]
# Set up Rich logging for the package
import logging
from rich.logging import RichHandler
from rich.console import Console
from rich.theme import Theme

# Create a custom theme for Rich
custom_theme = Theme({
    "info": "cyan",
    "warning": "yellow",
    "error": "bold red",
    "success": "bold green",
})

# Create a console with the custom theme
console = Console(theme=custom_theme)

# Configure the root logger to use Rich
logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    datefmt="[%X]",
    handlers=[RichHandler(rich_tracebacks=True, console=console)]
)