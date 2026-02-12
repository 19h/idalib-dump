# idalib-dump — Agent Reference

> Comprehensive project documentation for LLM coding agents.
> Last updated from codebase analysis of `git@github.com:19h/idalib-dump`.

---

## 1. Project Identity

**Name:** idalib-dump  
**Repository:** `git@github.com:19h/idalib-dump`  
**Language:** C++ (C++17), with vendored C libraries  
**Build System:** CMake (≥ 3.10) + Ninja, with a GNU Make wrapper  
**License:** MIT (vendored dependencies); project license per repository  
**IDA SDK Version:** 9.2+ (`IDASDK_VER=92`)  
**Platforms:** macOS (x86_64, arm64), Linux (x86_64), Windows (x64)

### What This Project Is

idalib-dump is a **headless IDA Pro toolset** built on top of Hex-Rays' `idalib` (the non-GUI IDA library). It provides three command-line executables:

1. **`ida_dump` / `idump`** — Extracts disassembly, Hex-Rays microcode, and decompiled pseudocode from binary files without launching the IDA GUI.
2. **`ida_lumina`** — Pushes function metadata to Hex-Rays' Lumina collaborative reverse-engineering server.
3. **`lumina_bot`** *(optional, Linux only)* — A Telegram bot that accepts binary files from users and automatically pushes their symbol information to Lumina.

The project exists to enable **batch processing**, **CI/CD integration**, and **automated analysis** of binaries using IDA Pro's analysis engine and Hex-Rays decompiler in headless mode.

### What This Project Is NOT

- It is **not** an IDA plugin (`.dylib`/`.so`/`.dll` loaded inside IDA). It is a standalone executable that links against `libidalib` and `libida`.
- It is **not** a Rust project (no Cargo.toml). It is pure C/C++.
- It does **not** provide a library API. All three targets are self-contained executables.

---

## 2. Repository Structure

```
idalib-dump/
├── CMakeLists.txt           # Root build configuration (3 targets)
├── Makefile                 # GNU Make wrapper for CMake (convenience)
├── README.md                # User-facing documentation
├── agents.md                # THIS FILE — LLM agent reference
├── .gitignore
├── .github/
│   └── workflows/
│       └── build.yml        # CI: macOS/Linux/Windows matrix build + release
├── ida-cmake/               # Custom CMake package for IDA SDK integration
│   ├── bootstrap.cmake      # SDK path detection and validation
│   ├── idasdkConfig.cmake   # CMake find_package config (targets, libs)
│   ├── idasdkConfigVersion.cmake
│   ├── README.md
│   └── cmake/
│       ├── platform.cmake   # OS/arch/compiler detection
│       ├── compiler.cmake   # Compiler flags, warnings, C++17
│       ├── targets.cmake    # ida_add_plugin(), ida_add_idalib(), etc.
│       └── utilities.cmake  # SDK version detection, validation
├── src/
│   ├── main.cpp             # ida_dump — the main analysis dumper (1845 lines)
│   ├── lumina.cpp           # ida_lumina — Lumina push tool (609 lines)
│   ├── lumina_bot.cpp       # lumina_bot — Telegram bot (1457 lines)
│   └── noplugins.c          # Stub: g_block_plugins flag (9 lines)
├── vendor/
│   ├── kat/                 # C syntax highlighter library (MIT)
│   │   ├── highlight.c
│   │   ├── hashtable.c
│   │   ├── include/
│   │   │   ├── highlight.h
│   │   │   ├── hashtable.h
│   │   │   └── optparse.h
│   │   └── LICENSE
│   └── astyle/              # Artistic Style C/C++ formatter (MIT)
│       ├── src/
│       │   ├── astyle.h
│       │   ├── astyle_main.h
│       │   ├── astyle_main.cpp
│       │   ├── ASBeautifier.cpp
│       │   ├── ASFormatter.cpp
│       │   ├── ASEnhancer.cpp
│       │   ├── ASLocalizer.cpp
│       │   ├── ASLocalizer.h
│       │   └── ASResource.cpp
│       └── LICENSE.md
└── build/                   # Build output directory (gitignored)
    ├── ida_dump             # Main analysis executable
    ├── idump                # Symlink/copy of ida_dump
    ├── ida_lumina           # Lumina push executable
    └── lumina_bot           # Telegram bot (if built)
```

---

## 3. Build System

### Prerequisites

| Requirement | Version | Notes |
|---|---|---|
| IDA Pro | 9.x | With Hex-Rays decompiler license |
| IDA SDK | 9.2+ | Set `IDASDK` environment variable |
| CMake | ≥ 3.10 | 3.27 effectively required by ida-cmake bootstrap |
| Ninja | any | Recommended generator (Make also works) |
| C++ Compiler | C++17 | Clang (macOS), GCC (Linux), MSVC (Windows) |
| TDLib | master | *Only* for `lumina_bot` on Linux |

### Build Commands

```bash
# Standard build (Make wrapper)
export IDASDK=/path/to/idasdk
make                    # Build all
make install            # Install to /usr/local/bin
make debug              # Debug build
make clean              # Remove build/
make rebuild            # clean + build
make info               # Show configuration
make sign               # Ad-hoc codesign (macOS)

# Direct CMake
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build

# With Telegram bot (Linux only)
cmake -S . -B build -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_LUMINA_BOT=ON \
    -DTd_DIR=/path/to/td/lib/cmake/Td
cmake --build build
```

### CMake Variables

| Variable | Default | Description |
|---|---|---|
| `IDASDK` | `$IDASDK` env | Path to IDA SDK root (required) |
| `IDASDK_VER` | `92` | SDK version number |
| `IDA_MACOS_DIR` | Auto-detected | Path to IDA.app/Contents/MacOS (macOS rpath) |
| `CMAKE_BUILD_TYPE` | `Release` | `Release` or `Debug` |
| `BUILD_LUMINA_BOT` | `OFF` | Build the Telegram Lumina bot |
| `Td_DIR` | - | Path to TDLib CMake config directory |

### Build Targets

The `CMakeLists.txt` defines three targets via the `ida_add_idalib()` function from `ida-cmake`:

1. **`ida_dump`** — Main binary analysis dumper. Sources: `main.cpp`, `noplugins.c`, all Kat files, all AStyle files. Compiled with `ASTYLE_LIB ASTYLE_NO_EXPORT`. A post-build step copies it to `idump`.
2. **`ida_lumina`** — Lumina push tool. Sources: `lumina.cpp`, `noplugins.c`. Links `dl` on Unix.
3. **`lumina_bot`** *(optional)* — Telegram bot. Sources: `lumina_bot.cpp`, `noplugins.c`. Links `Td::TdStatic`, `dl`, `pthread`. Only built when `BUILD_LUMINA_BOT=ON` and TDLib is found.

### Platform-Specific Build Notes

**macOS:**
- Uses `@rpath` for `libidalib.dylib` and `libida.dylib`. `CMAKE_BUILD_RPATH` and `CMAKE_INSTALL_RPATH` are set to `IDA_MACOS_DIR`.
- Uses `-Wl,-flat_namespace` to work around SDK stub library symbol mismatches (SDK exports `qfree` etc. from `libidalib` stub but runtime has them in `libida`).
- `make install` performs `codesign --force --sign -` on all binaries.
- Auto-detects `IDA_MACOS_DIR` from SDK `bin/` tree or `/Applications/IDA Professional 9.3.app/Contents/MacOS`.

**Windows:**
- Links `psapi` for `EnumProcessModules` (loaded module enumeration in verbose mode).
- Uses MSVC with `/Zi` debug info, `/OPT:REF`, `/OPT:ICF`.
- `_putenv_s` replaces `setenv`; `_dup`/`_dup2`/`_close`/`_open` replace POSIX equivalents.

**Linux:**
- Links `dl` for `dlsym`/`dladdr`/`dlopen`.
- Uses `dl_iterate_phdr` for loaded module enumeration.
- Standard GCC with `-g` debug info.

---

## 4. ida-cmake Build Framework

The `ida-cmake/` subdirectory is a **custom CMake package** that abstracts IDA SDK integration. It is included via `bootstrap.cmake` and provides:

### Key Functions

| Function | Purpose |
|---|---|
| `ida_add_plugin(NAME ...)` | Create an IDA plugin (.dylib/.so/.dll) |
| `ida_add_loader(NAME ...)` | Create an IDA loader module |
| `ida_add_procmod(NAME ...)` | Create an IDA processor module |
| `ida_add_idalib(NAME ...)` | Create an idalib executable/library |

### CMake Targets Provided

| Target | Description |
|---|---|
| `idasdk::plugin` | Interface target for IDA plugins |
| `idasdk::loader` | Interface target for IDA loaders (inherits from plugin) |
| `idasdk::procmod` | Interface target for IDA processor modules |
| `idasdk::idalib` | Interface target for idalib executables |
| `ida_platform_settings` | Platform detection (__NT__, __MAC__, __LINUX__) |
| `ida_compiler_settings` | Compiler flags, C++17, __IDP__, __EA64__ |
| `ida_addon_base` | Common properties for all IDA addons |

### SDK Path Detection

`bootstrap.cmake` auto-detects the SDK layout by probing for `include/pro.h` in:
1. `$IDASDK/include/pro.h` (standard layout)
2. `$IDASDK/sdk/obj/include/pro.h` (alternative layout)
3. `$IDASDK/src/include/pro.h` (source layout)

### Architecture and Library Resolution

The library suffix is constructed as `{arch}_{platform}_{compiler}_64`:
- macOS arm64: `arm64_mac_clang_64`
- macOS x86_64: `x64_mac_clang_64`
- Linux x86_64: `x64_linux_gcc_64`
- Windows x64: `x64_win_vc_64`

Libraries linked: `libida.{dylib,so}` + `libidalib.{dylib,so}` (or `.lib` on Windows).

---

## 5. Source File Deep Dive

### 5.1 `src/main.cpp` — ida_dump (1845 lines)

This is the primary tool and the largest source file. It is a single-file architecture with clearly delimited sections.

#### IDA SDK Header Inclusion Strategy

**CRITICAL:** The IDA SDK redefines standard C library functions via macros (e.g., `setenv`, `getenv`, `fflush`, `fprintf`, `stdout`, `stderr`). The file saves pointers to the real functions *before* including any IDA headers:

```cpp
// Lines 34-56: Save real functions BEFORE IDA includes
static inline int real_setenv(const char* name, const char* value);
static inline const char* real_getenv(const char* name);
static FILE* real_stdout = stdout;
static FILE* real_stderr = stderr;
static inline int real_fflush(FILE* stream);
static inline int real_fprintf(FILE* stream, const char* fmt, ...);
```

Similarly, POSIX file descriptor operations (`dup`, `dup2`, `close`, `open`) are wrapped in `posix_*` inline functions before IDA headers are included, because IDA may redefine them too.

**When modifying this file:** Always include standard headers and save function pointers *above* the `#include <pro.h>` line. The IDA SDK headers begin at line 102.

#### Major Components

| Section | Lines | Description |
|---|---|---|
| Pre-IDA function saves | 34–90 | Save real `setenv`/`getenv`/`stdio`/POSIX functions |
| IDA SDK includes | 101–114 | `pro.h`, `ida.hpp`, `idp.hpp`, `auto.hpp`, `funcs.hpp`, `lines.hpp`, `name.hpp`, `loader.hpp`, `hexrays.hpp`, `idalib.hpp`, `segment.hpp`, `typeinf.hpp`, `nalt.hpp` |
| Global state | 118–165 | `hexdsp`, `g_hexrays_available`, `Options` struct, `Stats` struct, output stream |
| `ProgressDisplay` | 170–310 | ANSI progress bar for file output mode (rate-limited to 20 fps) |
| `OutputWriter` | 319–347 | Byte-counting output stream wrapper |
| `Color` namespace | 353–373 | ANSI color constants with disable support |
| Utilities | 380–537 | `format_address()`, `format_size()`, `parse_address()`, `get_demangled_name()`, `pattern_matches_name()`, `matches_filter()` |
| Kat highlighter | 542–581 | `ensure_highlighter()`, `shutdown_highlighter()`, `format_pseudocode_line()`, RAII `HighlighterGuard` |
| AStyle formatter | 587–626 | `ensure_astyle()`, `format_pseudocode_block()` — Google style, 4-space indent |
| `MicrocodePrinter` | 632–669 | `vd_printer_t` subclass for Hex-Rays microcode output |
| Binary info | 681–941 | `print_binary_info()`, `print_segments()`, `resolve_module_path()`, `print_loaded_modules()` |
| `FunctionDumper` | 947–1183 | Core analysis: `is_special_segment()`, `should_process()`, `dump()`, `list()`, `print_header()`, `dump_assembly()`, `dump_microcode()`, `dump_pseudocode()` |
| Summary | 1189–1224 | `print_summary()` — success rate, error listing |
| `StdioRedirector` | 1231–1276 | RAII stdout/stderr redirection to `/dev/null` (quiet mode) |
| `HeadlessIdaContext` | 1278–1479 | RAII IDA lifecycle: `init_library()` → `open_database()` → `auto_wait()` → `init_hexrays_plugin()`, with fake IDADIR/IDAUSR for plugin isolation |
| Argument parsing | 1485–1701 | `split_string()`, `print_usage()`, `parse_args()` |
| `main()` | 1707–1844 | Entry point: parse args → setup output → create `HeadlessIdaContext` → iterate functions → summary |

#### Options Struct

```cpp
struct Options {
    std::string input_file;
    std::string output_file;         // Output file (empty = stdout)
    std::string filter_pattern;      // Function name filter (regex)
    ea_t filter_address = BADADDR;   // Filter by specific address
    std::vector<std::string> function_list;  // Explicit list of functions
    std::vector<std::string> plugin_patterns;  // --plugin patterns
    bool show_assembly = true;
    bool show_microcode = false;
    bool show_pseudocode = true;
    bool format_pseudocode = true;
    bool errors_only = false;
    bool quiet = false;
    bool show_summary = true;
    bool list_functions = false;
    bool verbose = false;
    bool no_plugins = false;
};
```

#### Plugin Isolation Mechanism

When `--no-plugins` is specified, `HeadlessIdaContext` creates a temporary directory structure at `/tmp/.ida_no_plugins_<pid>/` that:

1. Creates a fake IDADIR (`/tmp/.ida_no_plugins_<pid>/ida/`) that symlinks everything from the real IDADIR (including its `plugins/` directory, since all IDADIR plugins are Hex-Rays system plugins).
2. Creates a fake IDAUSR (`/tmp/.ida_no_plugins_<pid>/user/`) that:
   - Symlinks all entries from `~/.idapro/` *except* `plugins/`, `procs/`, and `loaders/`.
   - For `procs/` and `loaders/`: only symlinks user modules that don't exist in IDADIR (preventing shadowing of system modules).
   - Creates a controlled `plugins/` directory containing only plugins matching `--plugin` patterns.
3. Sets `IDADIR` and `IDAUSR` environment variables to point to the fake directories.
4. Cleans up the temporary directory tree in the destructor via `std::filesystem::remove_all`.

This approach ensures Hex-Rays decompiler plugins always load (they're in IDADIR), while user plugins are blocked unless explicitly whitelisted.

#### Function Filtering Logic

The filter matching (`matches_filter()`) uses this precedence:

1. **Address filter** (`-a`): exact address match.
2. **Function list** (`-F`): tries each item as (a) hex address, (b) exact raw name, (c) exact demangled name, (d) case-insensitive raw name, (e) case-insensitive demangled name.
3. **Pattern filter** (`-f`): tries regex match first, falls back to case-insensitive substring match on both raw and demangled names.
4. **No filter**: matches all functions.

#### Decompilation Flow

For each function, `FunctionDumper::dump()`:

1. Gets function name via `get_func_name()`.
2. Checks `should_process()` (filter match + not a special/extern segment).
3. If Hex-Rays unavailable: dumps assembly only.
4. Otherwise: calls `decompile(pfn, &hf, DECOMP_WARNINGS)`.
5. Silently skips "special segment" and "call analysis failed" errors (expected for extern functions).
6. In `--errors` mode: skips successful functions.
7. Dumps assembly, microcode, and/or pseudocode based on output flags.

#### Pseudocode Pipeline

Raw pseudocode from Hex-Rays goes through:
1. **Tag removal:** `tag_remove()` strips IDA color tags.
2. **AStyle formatting:** Google style, 4-space indent, operator padding, pointer-name alignment.
3. **Kat highlighting:** ANSI color syntax highlighting for terminal output (disabled for file output).

### 5.2 `src/lumina.cpp` — ida_lumina (609 lines)

A standalone tool for pushing function metadata to the Hex-Rays Lumina server.

#### Lumina Interface (Reverse Engineered)

The Lumina connection is established through reverse-engineered vtable offsets discovered via Frida tracing:

```cpp
// Vtable offsets:
// +0x00: Destructor/release
// +0x18: Actual network RPC
// +0x28: Connection status check
// +0x48: Pull metadata from Lumina
// +0x50: Push metadata to Lumina (the one used)
constexpr size_t LUMINA_VTABLE_PUSH_METADATA = 0x50;
```

The `LuminaConnection` class:
1. Loads `libida.so`/`ida.dll` at runtime via `dlsym`/`GetProcAddress`.
2. Finds `get_server_connection2` symbol.
3. Calls it to get a connection object.
4. Reads the vtable pointer from the connection object.
5. Calls `push_metadata` (vtable offset 0x50) with an empty input (push all functions).
6. Parses the output structure: EA array, count, and per-function result codes (0=skip, 1=new, 2=exists, 3+=error).

#### HeadlessIdaContext (Lumina variant)

Similar to `main.cpp` but simpler:
- Uses `g_block_plugins = true` as a fallback for plugin blocking.
- Creates fake IDADIR/IDAUSR with a similar symlink approach.
- Initializes Hex-Rays optionally (useful for Lumina but not required).

### 5.3 `src/lumina_bot.cpp` — lumina_bot (1457 lines)

A Telegram bot built on TDLib that accepts binary files and automatically pushes them to Lumina.

#### Architecture

```
                    ┌─────────────────┐
                    │   Telegram API   │
                    │    (TDLib)        │
                    └───────┬─────────┘
                            │
                    ┌───────▼─────────┐
                    │   LuminaBot     │  ← Main event loop (single-threaded TDLib I/O)
                    │  (td::Client)   │
                    └───────┬─────────┘
                            │
                    ┌───────▼─────────┐
                    │   JobQueue      │  ← Thread-safe job management
                    │  (mutex+cv)     │
                    └───────┬─────────┘
                            │
              ┌─────────────┼─────────────┐
              │             │             │
        ┌─────▼────┐ ┌─────▼────┐ ┌─────▼────┐
        │ Worker 0 │ │ Worker 1 │ │  ... N   │  ← AnalysisWorker threads
        │(popen    │ │(popen    │ │          │     (default 5 workers)
        │ida_lumina│ │ida_lumina│ │          │
        └──────────┘ └──────────┘ └──────────┘
```

Key design decisions:
- Workers use `popen()` to spawn `ida_lumina` as a **subprocess** (not in-process) to avoid fork() issues with multi-threaded TDLib.
- File downloads are tracked by TDLib file_id mapped to job_id.
- For PE/DLL files: the bot prompts for an optional PDB file (replied to the status message) or a `/go` command to proceed without PDB.
- Filenames are anonymized using a hash of the job_id for file storage.
- Status updates use MarkdownV2 formatting with careful escaping.

#### Bot Configuration

```cpp
struct BotConfig {
    std::string api_id;          // TELEGRAM_API_ID env or --api-id
    std::string api_hash;        // TELEGRAM_API_HASH env or --api-hash
    std::string bot_token;       // TELEGRAM_BOT_TOKEN env or --bot-token
    std::string work_dir;        // /tmp/lumina_bot
    std::string tdlib_dir;       // tdlib_bot
    std::string ida_lumina_path; // ./ida_lumina
    size_t max_file_size;        // 100 MB
    bool no_plugins;             // true (default)
};
```

#### Job States

```
PENDING → DOWNLOADING → QUEUED → ANALYZING → CONNECTING_LUMINA → PUSHING → COMPLETED
                                                                         → FAILED
```

For PE files, an extra `waiting_for_pdb` state exists between DOWNLOADING and QUEUED.

#### IDA SDK Macro Conflicts in lumina_bot.cpp

The file saves `std::condition_variable::wait` functionality before IDA headers redefine it:

```cpp
namespace std_cv {
    template<typename Lock, typename Pred>
    void cv_wait(std::condition_variable& cv, Lock& lock, Pred pred) {
        while (!pred()) { cv.wait(lock); }
    }
}
```

It also saves `waitpid`, `fgets`, `popen`, `pclose` before IDA headers.

### 5.4 `src/noplugins.c` — Plugin Blocking Flag (9 lines)

A minimal C file that declares the `g_block_plugins` boolean. This flag is referenced by all three executables via `extern "C"`. The actual plugin blocking is handled in each executable's `HeadlessIdaContext` through IDADIR manipulation.

---

## 6. Vendored Dependencies

### 6.1 Kat (vendor/kat/)

**What:** A lightweight C syntax highlighter originally created by Davidson Francis. Uses ANSI escape codes for terminal color output.

**How it's used:** `ida_dump` calls `highlight_init(nullptr)` to initialize with the built-in "Elf Deity" 256-color theme, then `highlight_line()` on each pseudocode line. The result is ANSI-colored C code suitable for terminal display.

**Files:**
- `highlight.c` / `highlight.h` — Core highlighting engine with state machine parser
- `hashtable.c` / `hashtable.h` — Hash table for keyword lookup (uses SDBM hash)
- `optparse.h` — Header-only option parser (included but not used by idalib-dump)

**License:** MIT

### 6.2 Artistic Style (vendor/astyle/)

**What:** A C/C++ source code formatter/beautifier. Used as a library (`ASTYLE_LIB` + `ASTYLE_NO_EXPORT` defines).

**How it's used:** `ida_dump` calls `AStyleMain()` with options `--style=google --indent=spaces=4 --pad-oper --align-pointer=name` to format raw Hex-Rays pseudocode output into clean, consistently-styled C code.

**Files:**
- `astyle_main.cpp` / `astyle_main.h` — Library entry point (`AStyleMain`)
- `ASBeautifier.cpp` — Indentation engine
- `ASFormatter.cpp` — Line formatting engine
- `ASEnhancer.cpp` — Post-processing enhancements
- `ASResource.cpp` — Keyword/operator tables
- `ASLocalizer.cpp` / `ASLocalizer.h` — Localization (minimal use)
- `astyle.h` — Core data structures

**License:** MIT

---

## 7. IDA SDK Integration Details

### Key IDA SDK APIs Used

| API | Used In | Purpose |
|---|---|---|
| `init_library()` | All targets | Initialize idalib (headless IDA) |
| `open_database()` | All targets | Open binary for analysis |
| `auto_wait()` | All targets | Wait for auto-analysis to complete |
| `init_hexrays_plugin()` | ida_dump, ida_lumina | Initialize Hex-Rays decompiler |
| `term_hexrays_plugin()` | ida_dump, ida_lumina | Shut down Hex-Rays |
| `set_database_flag(DBFL_KILL)` | All targets | Mark DB for deletion on close |
| `term_database()` | All targets | Close the IDA database |
| `enable_console_messages()` | All targets | Toggle IDA console output |
| `get_func_qty()` / `getn_func()` | ida_dump | Iterate all functions |
| `get_func_name()` | ida_dump | Get function name |
| `decompile()` | ida_dump | Hex-Rays decompilation |
| `generate_disasm_line()` | ida_dump | Generate assembly text |
| `tag_remove()` | ida_dump | Remove IDA color tags from text |
| `demangle_name()` | ida_dump | C++ name demangling |
| `ea2str()` | ida_dump | Format effective address |
| `get_segm_name()` / `getnseg()` | ida_dump | Segment information |
| `inf_get_procname()` | ida_dump | Get processor name |
| `inf_is_64bit()` | ida_dump | Check binary bitness |
| `get_input_file_path()` | ida_dump | Get analyzed file path |
| `get_file_type_name()` | ida_dump | Get file format name |

### Global Variables

| Variable | Type | Purpose |
|---|---|---|
| `hexdsp` | `hexdsp_t*` | Hex-Rays dispatch pointer (required by SDK; initialized by `init_hexrays_plugin()`) |
| `g_hexrays_available` | `bool` | Whether Hex-Rays initialized successfully |
| `g_block_plugins` | `bool` | Plugin blocking flag (defined in `noplugins.c`) |

### IDA SDK Macro Hazards

The IDA SDK (`pro.h` and related headers) aggressively redefines standard C library functions via macros. Any code that needs to use the real standard library functions must save them *before* including IDA headers. The current codebase handles this with inline wrapper functions defined before the `#include <pro.h>` line.

Functions known to be redefined by the IDA SDK:
- `setenv` / `getenv` / `putenv`
- `fflush` / `fprintf` / `fgets`
- `stdout` / `stderr`
- `popen` / `pclose`
- `waitpid`
- `wait` (affects `std::condition_variable::wait`)

**When adding new source files:** Always define wrapper functions for any standard library functions you need *above* the first IDA SDK `#include`.

---

## 8. CI/CD Pipeline

### GitHub Actions Workflow (`.github/workflows/build.yml`)

**Triggers:** Push to `master`/`main`, tags matching `v*`, pull requests, manual dispatch.

**Build Matrix:**

| OS | Name | Architecture | Special |
|---|---|---|---|
| `macos-latest` | `macos-x86_64` | x86_64 | |
| `macos-latest` | `macos-arm64` | arm64 | |
| `ubuntu-latest` | `linux-x86_64` | x86_64 | Builds TDLib + lumina_bot |
| `windows-latest` | `windows-x86_64` | x64 | MSVC 2022 |

**Steps per platform:**
1. Checkout repository
2. Checkout IDA SDK from `HexRaysSA/ida-sdk` (private)
3. Platform-specific setup (MSVC dev cmd, apt-get, TDLib cache)
4. Configure CMake with platform-appropriate flags
5. Build
6. Copy artifacts to `artifacts/` directory
7. Upload as GitHub Actions artifacts (30-day retention)

**Release job:** Triggers on `v*` tags, downloads all artifacts, creates a GitHub Release with auto-generated release notes.

### Version Tags

The project uses semantic versioning: `v1.0.0`, `v1.1.0`, `v1.2.0`, `v1.3.0`, `v1.4.0`, `v1.7.0`, `v1.8.0`.

---

## 9. Runtime Behavior

### ida_dump Execution Flow

```
1. Parse command-line arguments
2. Open output file if specified (disables colors, enables quiet/no-plugins)
3. Initialize Kat syntax highlighter (HighlighterGuard RAII)
4. Create HeadlessIdaContext:
   a. Set up fake IDADIR/IDAUSR if --no-plugins
   b. Redirect stdout/stderr to /dev/null if --quiet
   c. init_library()
   d. enable_console_messages(!quiet)
   e. open_database(input_file, true)
   f. auto_wait()  (blocks until IDA analysis completes)
   g. init_hexrays_plugin()
   h. Restore stdout/stderr
5. Print binary info (if not quiet)
6. Print segments + loaded modules (if --verbose)
7. Pre-count functions to process (for progress bar)
8. If --list mode: print function table
9. Else: iterate all functions:
   a. FunctionDumper::dump() for each
   b. Update progress bar
10. Print summary (if enabled)
11. HeadlessIdaContext destructor:
    a. term_hexrays_plugin()
    b. set_database_flag(DBFL_KILL)
    c. term_database()
    d. Remove fake IDADIR/IDAUSR
12. Close output file
13. Exit with 0 (all OK) or 1 (any decompilation failures)
```

### ida_lumina Execution Flow

```
1. Parse arguments
2. Create HeadlessIdaContext (same as ida_dump)
3. Print function count
4. Create LuminaConnection:
   a. dlsym/GetProcAddress for get_server_connection2
   b. Call get_server_connection2(0) to get connection object
   c. Read vtable pointer
5. Call push_all():
   a. Get push_metadata method from vtable[0x50/8]
   b. Prepare empty input (push all functions)
   c. Call push_metadata()
   d. Parse output: count, per-function result codes
6. Print results (new, exists, skipped, errors)
7. Cleanup
```

### Environment Variables

| Variable | Usage |
|---|---|
| `IDASDK` | Build-time: path to IDA SDK |
| `IDADIR` | Runtime: IDA installation directory. Manipulated by `--no-plugins` |
| `IDAUSR` | Runtime: user plugin directory (`~/.idapro`). Manipulated by `--no-plugins` |
| `TELEGRAM_API_ID` | lumina_bot: Telegram API ID |
| `TELEGRAM_API_HASH` | lumina_bot: Telegram API hash |
| `TELEGRAM_BOT_TOKEN` | lumina_bot: Bot token from @BotFather |

### Exit Codes

- **0:** All processed functions decompiled successfully (or no failures in lumina push)
- **1:** One or more decompilation failures occurred, or fatal error

---

## 10. Code Style and Conventions

### General Style

- **C++17** throughout (`std::filesystem`, `std::optional`, structured bindings, `if constexpr`).
- Single-file architecture per target (no internal library decomposition).
- Section headers using `//=====` comment blocks with descriptive names.
- RAII pattern used extensively: `HeadlessIdaContext`, `StdioRedirector`, `HighlighterGuard`.
- Global state: `g_opts`, `g_stats`, `g_output`, `g_progress` are `static` globals in each translation unit.
- No exceptions in normal flow; exceptions only for fatal initialization errors caught in `main()`.

### Naming Conventions

- Classes: `PascalCase` (`FunctionDumper`, `HeadlessIdaContext`, `LuminaConnection`)
- Functions: `snake_case` (`print_binary_info`, `matches_filter`, `parse_address`)
- Global variables: `g_` prefix (`g_opts`, `g_stats`, `g_hexrays_available`)
- Member variables: `m_` prefix (`m_connection`, `m_vtable`, `m_start_time`)
- Constants: `ALL_CAPS` for macros (`CLR`, `LUMINA_VTABLE_PUSH_METADATA`), `PascalCase` for namespace members (`Color::Green`)
- IDA SDK types: used as-is (`ea_t`, `func_t`, `qstring`, `cfuncptr_t`, `segment_t`)

### User Preferences (for LLM agents)

- **Avoid compiler-specific intrinsics** in loader/analysis code.
- **Avoid heavy bit-optimizations** — prefer readable, portable code.
- **Prefer straightforward/portable implementations**.
- **Use `pro.h` helpers** from the IDA SDK when available.
- **Continue to the next task automatically** without stopping.

---

## 11. Common Development Tasks

### Adding a New Command-Line Option

1. Add the field to the `Options` struct in `main.cpp`.
2. Add parsing logic in `parse_args()` (around line 1554).
3. Add help text in `print_usage()` (around line 1514).
4. Update `README.md` option tables.

### Adding a New Output Mode

1. Add a boolean to `Options` (e.g., `show_types`).
2. Add a new dump method to `FunctionDumper` (e.g., `dump_types()`).
3. Call it from `FunctionDumper::dump()` based on the option flag.
4. Add corresponding `--types` / `--types-only` / `--no-types` arguments.

### Modifying the Plugin Isolation Logic

The plugin isolation is in `HeadlessIdaContext` constructor, both in `main.cpp` (lines 1286–1413) and `lumina.cpp` (lines 309–408). They are **not shared code** — each has its own implementation. `main.cpp` has the more sophisticated version that preserves user `procs/` and `loaders/` while preventing shadowing of system modules.

### Modifying the Lumina Interface

The Lumina vtable offsets in `lumina.cpp` and `lumina_bot.cpp` are hardcoded constants discovered via Frida tracing. If the Lumina server protocol changes in a new IDA version, these offsets may need to be re-discovered. The `LuminaConnection` class is duplicated between `lumina.cpp` and `lumina_bot.cpp` — changes should be made in both.

### Adding a New Build Target

Use `ida_add_idalib()` in `CMakeLists.txt`:

```cmake
ida_add_idalib(my_tool
  TYPE EXECUTABLE
  SOURCES
    src/my_tool.cpp
    src/noplugins.c
  INCLUDES
    ${CMAKE_CURRENT_LIST_DIR}/vendor/kat/include
)
target_compile_features(my_tool PRIVATE cxx_std_17)
```

---

## 12. Known Gotchas and Pitfalls

### 1. IDA SDK Macro Pollution

The IDA SDK redefines standard functions. **Always** save references to standard library functions before including IDA headers. See the pattern at the top of each `.cpp` file.

### 2. Symbol Resolution on macOS

On macOS, `libidalib.dylib` and `libida.dylib` use `@rpath` references. The build sets `CMAKE_BUILD_RPATH` to `IDA_MACOS_DIR`. If you get "library not found" errors at runtime, ensure the rpath points to the correct IDA installation directory. The `-Wl,-flat_namespace` linker flag works around cases where the SDK stub library exports symbols from a different library than the runtime.

### 3. HeadlessIdaContext is Non-Copyable

The IDA library maintains global state internally. Only one `HeadlessIdaContext` can exist at a time, and it must be destroyed before the process exits. This is enforced by deleted copy/move constructors.

### 4. hexdsp Global

The `hexdsp` pointer is a **mandatory** global that the IDA SDK references internally. It must be declared in exactly one translation unit per executable. Each `.cpp` file in this project declares it.

### 5. Hex-Rays Graceful Fallback

If `init_hexrays_plugin()` fails (e.g., no decompiler license), `ida_dump` automatically:
- Disables pseudocode and microcode output.
- Falls back to assembly-only output.
- Prints a warning if not in quiet mode.

### 6. Duplicated Code

`LuminaConnection` is implemented identically in both `lumina.cpp` and `lumina_bot.cpp`. The `HeadlessIdaContext` has slightly different implementations in `main.cpp` vs `lumina.cpp`. There is no shared library between the executables. When fixing bugs, check all copies.

### 7. Quiet Mode Side Effects

When `--output` is specified, `ida_dump` automatically enables `--quiet` and `--no-plugins`. This is intentional: file output mode assumes batch processing where console noise and user plugins are undesirable.

### 8. Progress Bar Only in File Mode

The `ProgressDisplay` class only activates when `--output` is specified (output goes to file, progress goes to stderr). In normal stdout mode, no progress bar is shown.

---

## 13. Testing

There are **no automated tests** in this repository. The project is tested manually by running the tools against known binaries and verifying output. The CI pipeline only verifies that the project compiles successfully on all platforms.

To manually test:

```bash
# Basic functionality
./build/ida_dump /path/to/binary

# Specific function
./build/ida_dump -f main /path/to/binary

# Pseudocode only to file
./build/ida_dump -o output.c --pseudo-only /path/to/binary

# List functions
./build/ida_dump -l /path/to/binary

# Find decompilation errors
./build/ida_dump -e /path/to/binary

# Lumina push
./build/ida_lumina /path/to/binary
```

---

## 14. Dependency Graph

```
ida_dump
├── src/main.cpp
├── src/noplugins.c
├── vendor/kat/ (highlight.c, hashtable.c)
├── vendor/astyle/ (ASBeautifier.cpp, ASFormatter.cpp, ASEnhancer.cpp, ASLocalizer.cpp, ASResource.cpp, astyle_main.cpp)
├── IDA SDK (libidalib + libida)
└── System: dl (Unix), psapi (Windows)

ida_lumina
├── src/lumina.cpp
├── src/noplugins.c
├── IDA SDK (libidalib + libida)
└── System: dl (Unix)

lumina_bot (optional, Linux only)
├── src/lumina_bot.cpp
├── src/noplugins.c
├── IDA SDK (libidalib + libida)
├── TDLib (Td::TdStatic)
└── System: dl, pthread
```

---

## 15. Git History and Evolution

The project evolved through clear phases (from earliest to latest):

1. **v1.0.0:** Initial `ida_dump` for headless assembly and pseudocode extraction.
2. **v1.1.0:** Added `--no-plugins` flag for user plugin isolation.
3. **v1.2.0:** Added `ida_lumina` Lumina push tool and Hex-Rays preservation in no-plugins mode.
4. **v1.3.0:** Added `lumina_bot` Telegram bot for automated Lumina symbol submission.
5. **v1.4.0:** Added file output support with progress bar, list filtering, and selective plugin loading.
6. **Post-1.4.0:** Windows porting, C++ name demangling support, Hex-Rays fallback, RPATH fixes, loaded module reporting, IDADIR auto-detection, full IDAUSR environment mirroring, Windows module enumeration.
7. **v1.7.0–v1.8.0:** Mature state with comprehensive plugin isolation, cross-platform support, and robust error handling.

---

## 16. Quick Reference: CLI Options

### ida_dump

```
ida_dump [options] <binary_file>

Output Selection:
  --asm                    Show assembly
  --mc                     Show microcode
  --pseudo                 Show pseudocode
  --asm-only               Show only assembly
  --mc-only                Show only microcode
  --pseudo-only            Show only pseudocode
  --no-asm / --no-mc / --no-pseudo   Disable specific outputs

Filtering:
  -f, --filter <pattern>   Filter functions by name (regex)
  -F, --functions <list>   Comma or pipe-separated function names/addresses
  -a, --address <hex>      Show only function at specific address
  -e, --errors             Show only functions with decompilation errors
  -l, --list               List function names without decompilation

Output Control:
  -o, --output <file>      Write to file (shows progress on stderr)
  -q, --quiet              Suppress IDA messages and binary info
  -v, --verbose            Show extra metadata (size, flags, segments)
  --no-format-pseudo       Disable AStyle formatting of pseudocode
  --no-color               Disable ANSI color output
  --no-summary             Don't show summary statistics

Plugin Control:
  --no-plugins             Don't load user plugins (Hex-Rays still loads)
  --plugin <pattern>       Load plugins matching pattern (implies --no-plugins)

Other:
  -h, --help               Show help
  --version                Show build info (SDK path, lib path)
```

### ida_lumina

```
ida_lumina [options] <binary_file>

  -q, --quiet              Suppress IDA messages
  -v, --verbose            Show extra debug output
  --no-color               Disable colored output
  --no-plugins             Don't load user plugins
  --plugin <pattern>       Load plugins matching pattern
  -h, --help               Show help
```

### lumina_bot

```
lumina_bot [options]

  --api-id <id>            Telegram API ID (or TELEGRAM_API_ID env)
  --api-hash <hash>        Telegram API hash (or TELEGRAM_API_HASH env)
  --bot-token <token>      Bot token (or TELEGRAM_BOT_TOKEN env)
  --work-dir <path>        Working directory (default: /tmp/lumina_bot)
  --tdlib-dir <path>       TDLib database directory (default: tdlib_bot)
  --ida-lumina <path>      Path to ida_lumina tool (default: ./ida_lumina)
  --max-size <mb>          Maximum file size in MB (default: 100)
  --no-plugins             Disable user plugins (default)
  --plugins                Enable user plugins
  -h, --help               Show help
```
