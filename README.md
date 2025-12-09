# idalib-dump

A headless IDA Pro tool for extracting assembly, microcode, and Hex-Rays pseudocode from binaries. Built on top of `idalib`, it runs without a GUI and produces clean, formatted output suitable for analysis pipelines, plugin testing, and reverse engineering workflows.

## Features

- **Multi-format output**: Assembly disassembly, Hex-Rays microcode, and decompiled pseudocode
- **Pseudocode formatting**: Automatic C-style formatting via AStyle (Google style, 4-space indent)
- **Syntax highlighting**: ANSI color output for terminal display via Kat
- **Flexible filtering**: Filter functions by name (regex) or address
- **Error detection**: Find decompilation failures across a binary
- **Quiet mode**: Suppress IDA's verbose output for clean pipelines
- **Summary statistics**: Decompilation success rates and error reports

## Requirements

- IDA Pro 9.x with Hex-Rays decompiler
- IDA SDK (`IDASDK` environment variable or CMake flag)
- CMake >= 3.10
- Ninja (recommended) or Make

## Building

Set the IDA SDK path and build:

```bash
export IDASDK=/path/to/idasdk

# Using Make wrapper
make

# Or directly with CMake
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

The executable `ida_dump` will be created in the `build/` directory.

## Usage

```
ida_dump [options] <binary_file>
```

### Output Selection

By default, assembly and pseudocode are shown. Use these flags to customize:

| Flag | Description |
|------|-------------|
| `--asm` | Include assembly output |
| `--mc` | Include microcode output |
| `--pseudo` | Include pseudocode output |
| `--asm-only` | Show only assembly |
| `--mc-only` | Show only microcode |
| `--pseudo-only` | Show only pseudocode |

### Filtering

| Flag | Description |
|------|-------------|
| `-f, --filter <pattern>` | Filter functions by name (supports regex) |
| `-a, --address <hex>` | Show only the function at a specific address |
| `-e, --errors` | Show only functions that fail to decompile |
| `-l, --list` | List function names without decompilation |

### Output Control

| Flag | Description |
|------|-------------|
| `-q, --quiet` | Suppress IDA messages and binary info |
| `-v, --verbose` | Show extra metadata (size, flags, segments) |
| `--no-format-pseudo` | Disable AStyle formatting of pseudocode |
| `--no-color` | Disable ANSI color output |
| `--no-summary` | Don't show summary statistics |
| `--no-plugins` | Don't load plugins (except Hex-Rays decompiler) |

## Examples

```bash
# Dump all functions (assembly + pseudocode)
ida_dump program.exe

# Decompile only the main function
ida_dump -f main program.exe

# Find all functions matching a pattern
ida_dump -f 'parse_.*' program.exe

# Dump function at specific address
ida_dump -a 0x140001000 program.exe

# Find decompilation errors
ida_dump -e program.exe

# List all functions without decompiling
ida_dump -l program.exe

# Quiet mode, pseudocode only, no formatting
ida_dump -q --pseudo-only --no-format-pseudo program.exe

# Full verbose output with microcode
ida_dump -v --mc program.exe
```

## Output Format

For each function, the tool displays:

1. **Header**: Function name, segment, address, and decompilation status
2. **Assembly**: Disassembled instructions with addresses (if enabled)
3. **Microcode**: Hex-Rays intermediate representation (if enabled)
4. **Pseudocode**: Formatted and syntax-highlighted C code (if enabled)

A summary at the end shows total functions processed, success/failure counts, and any errors encountered.

## Exit Codes

- `0`: All processed functions decompiled successfully
- `1`: One or more decompilation failures occurred

## License

See vendor directories for third-party licenses (AStyle, Kat).
