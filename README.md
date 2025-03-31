# Elle-Est-Fit: LFI to RCE Framework

A Local File Inclusion to Remote Code Execution framework that works both as a Python library and a command-line tool.


## Features

- 🔍 Exploit LFI vulnerabilities to achieve RCE
- - PHP Filter Chain
- - Log file poisoning
- - PHP Session poisoning
- - Nginx/Apache Temporary Files
- - ...
- 🛠️ Multiple exploitation techniques
- 🧩 Modular architecture for easy extension
- 🚀 Easy to use API

## Installation

```bash
pip install elle-est-fit
```

# Quick Start

```python
from elle_est_fit import LFI

lfi = LFI(target="http://vulnerable.com/?page={}")
if lfi.exploit():
    output = lfi.shell("id")
    print(output)
```