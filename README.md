# taint-with-frida

A Frida-based dynamic taint analysis tool for x86_64 binaries. This is a proof-of-concept implementation focused on tracking data flow and detecting when tainted (user-controlled) data reaches dangerous functions.

## Limitations

 + byte-level taint tracking
 + flags register not tainted
 + support only a restricted subset of x86_64 instructions
 + requires Frida 16.0+

## Features

### Phase 1: Dangerous Function Detection ✅

Automatically tracks and alerts when tainted data flows into dangerous functions:

- **Memory Operations**: `strcpy`, `strcat`, `sprintf`, `gets`, `memcpy`, etc.
- **Format String**: `printf`, `fprintf`, `snprintf`, etc.
- **Command Execution**: `system`, `popen`, `execve`, `execl`, etc.
- **File Operations**: `fopen`, `open`, `fread`, `fwrite`, etc.
- **Network Operations**: `send`, `recv`, `write`, `read`, etc.

Functions are categorized by risk level (Critical, High, Medium, Low) and can be configured via YAML.

## Quick Start

### 1. Setup

```bash
# Convert YAML config to JSON (required for Frida)
python3 config-converter.py
```

### 2. Run Example Test

```bash
# Compile and run all tests
python3 run-test.py

# Run specific test mode
python3 run-test.py 1 "my_malicious_input"
```

### 3. Use in Your Own Scripts

```javascript
var tracker = require("./taint/tracker.js");

// Initialize dangerous function tracking
tracker.initDangerousFunctions();

// Start taint tracking
tracker.startTracing(true);

// Mark some memory as tainted (user input)
tracker.memory.taint(userInputPtr, inputLength);

// The tracker will automatically alert when tainted data
// reaches dangerous functions like strcpy, system, etc.
```

## Configuration

Edit `dangerous-functions.yaml` to customize which functions to track:

```yaml
memory_operations:
  strcpy:
    enabled: true
    risk: critical
    description: "Unbounded string copy - classic buffer overflow"
    arg_checks:
      - index: 0
        type: "dest"
        description: "destination buffer"
      - index: 1
        type: "source"
        description: "source string"
```

After editing, run:
```bash
python3 config-converter.py
```

### Check Types

- `source`: Argument is a source of tainted data (pointer to data)
- `dest`: Destination buffer (checked for overflow when writing tainted data)
- `format`: Format string argument (critical if tainted - format string vuln)
- `exec`: Execution command (critical if tainted - command injection)

## Examples

### Original Use Cases

+ **foo** (`foo.js`): A simple memory copy routine to test taint tracking
+ **bof** (`bof.js`): Buffer overflow detection by checking if return address is tainted

### New: Dangerous Function Tracking

+ **example-dangerous.js**: Comprehensive example showing automatic detection of:
  - Buffer overflows (`strcpy`, `sprintf`, `gets`)
  - Format string vulnerabilities (`printf` with tainted format)
  - Command injection (`system` with tainted command)
  - And more...

+ **example-vuln.c**: Test program with various vulnerabilities

### Running Examples

```bash
# Test strcpy overflow detection
frida -l example-dangerous.js ./example-vuln 1 "AAAA_long_input"

# Test format string vulnerability
frida -l example-dangerous.js ./example-vuln 3 "%x_%x_%x"

# Test all vulnerabilities
frida -l example-dangerous.js ./example-vuln 7 "test_input"
```

## Output Example

When tainted data reaches a dangerous function, you'll see:

```
════════════════════════════════════════════════════════════════════════════════
🔴 TAINTED DATA IN DANGEROUS FUNCTION
════════════════════════════════════════════════════════════════════════════════
Function: strcpy()
Risk:     CRITICAL
Reason:   Unbounded string copy - classic buffer overflow

Tainted Arguments:
  [1] source string (source)
      Address: 0x7ffc12345678
      Size:    64 bytes
      Data:    "AAAA_long_input"

Call Stack:
  vulnerable_strcpy+0x12
  main+0x45
  __libc_start_main+0x123
════════════════════════════════════════════════════════════════════════════════
```

## Architecture

```
taint/
├── core.js              - Core taint tracking (Memory, Registers)
├── bitmap.js            - Bitmap implementation for register tainting
├── interval-tree.js     - Interval tree for memory taint tracking
├── amd64.js             - x86_64 architecture definitions
├── index.js             - Original taint tracking (legacy)
├── tracker.js           - High-level API with dangerous function tracking
└── dangerous-functions.js - Dangerous function detection engine
```

## Roadmap

- [x] **Phase 1**: Dangerous function detection
- [ ] **Phase 2**: Taint source tracking (track origin of tainted data)
- [ ] **Phase 3**: Path constraints and symbolic execution
- [ ] **Phase 4**: Automated exploit generation
- [ ] **Phase 5**: Support for more architectures (ARM, AArch64)

## Contributing

To add new dangerous functions:

1. Edit `dangerous-functions.yaml`
2. Add the function with appropriate risk level and arg_checks
3. Run `python3 config-converter.py`
4. Test with your target binary

## License

PoC/Educational purposes only.
