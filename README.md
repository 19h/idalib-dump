# idalib-dump

A headless IDA Pro toolset for binary analysis. Built on top of `idalib`, it runs without a GUI and provides:

1. **ida_dump** - Extracts assembly, microcode, and Hex-Rays pseudocode from binaries
2. **ida_lumina** - Pushes function metadata to Hex-Rays' Lumina server
3. **ida_lumina_debug** - Dumps per-function Lumina hashes and metadata summaries
4. **lumina_bot** - Telegram bot for crowdsourced Lumina symbol submission (optional)

## Features

- **Multi-format output**: Assembly disassembly, Hex-Rays microcode, and decompiled pseudocode
- **Pseudocode formatting**: Automatic C-style formatting via AStyle (Google style, 4-space indent)
- **Syntax highlighting**: ANSI color output for terminal display via Kat
- **Flexible filtering**: Filter functions by name (regex), address, or explicit list
- **File output**: Write to file with real-time progress display
- **Error detection**: Find decompilation failures across a binary
- **Plugin control**: Disable user plugins or selectively enable specific ones
- **Lumina integration**: Push function metadata to Hex-Rays' Lumina server or inspect the local metadata that would be hashed

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

Outputs: `build/ida_dump`, `build/ida_lumina`, and `build/ida_lumina_debug`

### Building the Telegram Bot (optional, Linux only)

```bash
# Build TDLib first (see https://github.com/tdlib/td)
# Then build with bot support:
cmake -S . -B build -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_LUMINA_BOT=ON \
    -DTd_DIR=/path/to/td/lib/cmake/Td
cmake --build build
```

Outputs: `build/lumina_bot`

## ida_dump Usage

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
| `-F, --functions <list>` | Comma or pipe-separated list of function names/addresses |
| `-a, --address <hex>` | Show only the function at a specific address |
| `-e, --errors` | Show only functions that fail to decompile |
| `-l, --list` | List function names without decompilation |

### Output Control

| Flag | Description |
|------|-------------|
| `-o, --output <file>` | Write output to file (shows progress on stderr) |
| `-q, --quiet` | Suppress IDA messages and binary info |
| `-v, --verbose` | Show extra metadata (size, flags, segments) |
| `--no-format-pseudo` | Disable AStyle formatting of pseudocode |
| `--no-color` | Disable ANSI color output |
| `--no-summary` | Don't show summary statistics |

### Plugin Control

| Flag | Description |
|------|-------------|
| `--no-plugins` | Don't load user plugins (Hex-Rays decompiler still loads) |
| `--plugin <pattern>` | Load plugins matching pattern (implies `--no-plugins`) |

The `--plugin` option can be specified multiple times. It matches plugin files or folders containing the pattern in their name (e.g., `--plugin dazhbog` matches `dazhbog.so`, `dazhbog64.dylib`, `dazhbog/`, etc.).

### Examples

```bash
# Dump all functions (assembly + pseudocode)
ida_dump program.exe

# Decompile only the main function
ida_dump -f main program.exe

# Decompile specific functions by name
ida_dump -F "main,parse_config,init" program.exe

# Export pseudocode to file with progress bar
ida_dump -o output.c --pseudo-only program.exe

# Find all functions matching a pattern
ida_dump -f 'parse_.*' program.exe

# Dump function at specific address
ida_dump -a 0x140001000 program.exe

# Find decompilation errors
ida_dump -e program.exe

# List all functions without decompiling
ida_dump -l program.exe

# Use only Hex-Rays + a specific plugin
ida_dump --plugin dazhbog program.exe

# Quiet mode, pseudocode only, no formatting
ida_dump -q --pseudo-only --no-format-pseudo program.exe

# Full verbose output with microcode
ida_dump -v --mc program.exe
```

## ida_lumina Usage

```
ida_lumina [options] <binary_file>
```

Analyzes a binary and pushes all function metadata to the Hex-Rays Lumina server.

### Options

| Flag | Description |
|------|-------------|
| `-q, --quiet` | Suppress IDA's verbose messages |
| `-v, --verbose` | Show extra debug output |
| `--no-color` | Disable colored output |
| `--no-plugins` | Don't load user plugins (Hex-Rays still loads) |
| `--plugin <pattern>` | Load plugins matching pattern (implies `--no-plugins`) |

### Examples

```bash
# Analyze and push to Lumina
ida_lumina program.exe

# Quiet mode
ida_lumina -q program.exe

# With specific plugin enabled
ida_lumina --plugin dazhbog program.exe
```

**Note**: Lumina credentials must be configured in IDA Pro settings. The tool uses IDA's existing Lumina configuration.

## ida_lumina_debug Usage

```
ida_lumina_debug [options] <binary_file>
```

Analyzes a binary and dumps per-function Lumina-relevant metadata such as the calculated function MD5, EA/RVA, names, and a metadata-key/presence summary.

### Options

| Flag | Description |
|------|-------------|
| `--csv` | Emit CSV instead of human-readable text |
| `--bytes` | Include hex-encoded function bytes, total byte length, and chunk ranges from IDA |
| `-o, --output <file>` | Write output to a file |
| `-f, --filter <pattern>` | Filter functions by name (regex or substring) |
| `-F, --functions <list>` | Comma or pipe-separated list of function names/addresses |
| `-a, --address <hex>` | Dump only the function at a specific address |
| `-q, --quiet` | Suppress IDA's verbose messages |
| `-v, --verbose` | Show extra name detail in text mode |
| `--no-color` | Disable colored output |
| `--no-plugins` | Don't load user plugins |
| `--plugin <pattern>` | Load plugins matching pattern (implies `--no-plugins`) |

### Examples

```bash
# Human-readable Lumina metadata dump
ida_lumina_debug program.exe

# CSV to stdout
ida_lumina_debug --csv program.exe

# Include function bytes in the output
ida_lumina_debug --bytes program.exe

# CSV to a file
ida_lumina_debug --csv -o lumina.csv program.exe

# Focus on one function by name
ida_lumina_debug -f main program.exe

# Focus on explicit names/addresses
ida_lumina_debug -F "main,parse_config,0x140001000" program.exe
```

## Output Format

For each function, ida_dump displays:

1. **Header**: Function name, segment, address, and decompilation status
2. **Assembly**: Disassembled instructions with addresses (if enabled)
3. **Microcode**: Hex-Rays intermediate representation (if enabled)
4. **Pseudocode**: Formatted and syntax-highlighted C code (if enabled)

A summary at the end shows total functions processed, success/failure counts, and any errors encountered.

## Environment Variables

- `IDASDK` - Path to IDA SDK (required for build)
- `IDADIR` - Path to IDA Pro installation (runtime)
- `IDAUSR` - User plugin directory (manipulated by `--no-plugins`)

## Exit Codes

- `0`: All processed functions decompiled successfully
- `1`: One or more decompilation failures occurred

## License

See vendor directories for third-party licenses (AStyle, Kat).
