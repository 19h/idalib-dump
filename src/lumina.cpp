/**
 * IDA Pro Lumina Push Tool
 *
 * A headless tool for pushing function metadata to the Lumina server after analysis.
 * This uses the internal Lumina interface discovered via reverse engineering.
 *
 * Based on Frida script analysis of libida.so vtable structure:
 *   +0x18: rpc_call         - The actual network RPC
 *   +0x48: pull_metadata    - Query Lumina for matches
 *   +0x50: push_metadata    - Push metadata to Lumina
 */

#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <memory>
#include <stdexcept>
#include <cctype>
#include <cstring>
#include <algorithm>
#include <cstdlib>
#include <cstdint>
#include <filesystem>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <dlfcn.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#endif

// Save real setenv/getenv before IDA SDK redefines them with macros
static inline int real_setenv(const char* name, const char* value) {
#ifdef _WIN32
    return _putenv_s(name, value);
#else
    return setenv(name, value, 1);
#endif
}

static inline const char* real_getenv(const char* name) {
    return getenv(name);
}

// From noplugins.c - controls plugin blocking
extern "C" bool g_block_plugins;

// IDA SDK Headers
#include <pro.h>
#include <ida.hpp>
#include <idp.hpp>
#include <auto.hpp>
#include <funcs.hpp>
#include <name.hpp>
#include <loader.hpp>
#include <hexrays.hpp>
#include <idalib.hpp>
#include <segment.hpp>

//=============================================================================
// Global State
//=============================================================================

hexdsp_t *hexdsp = nullptr;

//=============================================================================
// Command Line Options
//=============================================================================

struct Options {
    std::string input_file;
    bool quiet = false;
    bool no_plugins = false;
    bool verbose = false;
    std::vector<std::string> plugin_patterns;  // Additional plugins to load in no-plugins mode
};

static Options g_opts;

//=============================================================================
// ANSI Colors
//=============================================================================

namespace Color {
    const char* Reset   = "\033[0m";
    const char* Bold    = "\033[1m";
    const char* Dim     = "\033[2m";
    const char* Red     = "\033[31m";
    const char* Green   = "\033[32m";
    const char* Yellow  = "\033[33m";
    const char* Blue    = "\033[34m";
    const char* Cyan    = "\033[36m";

    bool enabled = true;
    void disable() { enabled = false; }
    const char* get(const char* c) { return enabled ? c : ""; }
}

#define CLR(c) Color::get(Color::c)

//=============================================================================
// Lumina Interface (based on reverse engineered vtable)
//=============================================================================

// Vtable offsets discovered via Frida tracing
// Note: Only PUSH_METADATA is used currently, others kept for documentation
constexpr size_t LUMINA_VTABLE_PUSH_METADATA = 0x50;  // Push metadata to Lumina
// Unused but documented offsets:
// 0x00: Destructor/release
// 0x18: Actual network RPC
// 0x28: Connection status check
// 0x48: Pull metadata from Lumina

// Function pointer types for Lumina interface
using GetServerConnection2Fn = void* (*)(uint64_t mode);
using PushMetadataFn = uint8_t (*)(void* self, void* output, void* input, void* error_out, uint64_t arg4, uint64_t arg5);

// Push result codes
enum class PushResultCode : uint32_t {
    SKIP = 0,      // Function skipped (e.g., too small, thunk)
    NEW = 1,       // New metadata pushed
    EXISTS = 2,    // Metadata already exists
    FAILED = 3     // Error occurred (note: can't use ERROR - it's a Windows macro)
};

struct PushStats {
    size_t total = 0;
    size_t skip = 0;
    size_t new_count = 0;
    size_t exists = 0;
    size_t error = 0;
};

class LuminaConnection {
private:
    void* m_connection = nullptr;
    void* m_vtable = nullptr;
    GetServerConnection2Fn m_get_server_connection2 = nullptr;
#ifdef _WIN32
    HMODULE m_libida = nullptr;
#else
    void* m_libida = nullptr;
#endif

    void* get_push_metadata_method() {
        if (!m_vtable) return nullptr;
        void** vtable = static_cast<void**>(m_vtable);
        return vtable[LUMINA_VTABLE_PUSH_METADATA / sizeof(void*)];
    }

public:
    LuminaConnection() {
#ifdef _WIN32
        // Get handle to ida.dll on Windows
        m_libida = GetModuleHandleA("ida.dll");
        if (!m_libida) {
            m_libida = GetModuleHandleA(nullptr);  // Try current process
        }

        if (!m_libida) {
            throw std::runtime_error("Failed to get ida.dll handle");
        }

        // Get get_server_connection2 function
        m_get_server_connection2 = reinterpret_cast<GetServerConnection2Fn>(
            GetProcAddress(m_libida, "get_server_connection2")
        );
#else
        // Get handle to libida.so on Linux
        m_libida = dlopen("libida.so", RTLD_NOW | RTLD_NOLOAD);
        if (!m_libida) {
            m_libida = dlopen(nullptr, RTLD_NOW);  // Try current process
        }

        if (!m_libida) {
            throw std::runtime_error("Failed to get libida.so handle");
        }

        // Get get_server_connection2 function
        m_get_server_connection2 = reinterpret_cast<GetServerConnection2Fn>(
            dlsym(m_libida, "get_server_connection2")
        );
#endif

        if (!m_get_server_connection2) {
            throw std::runtime_error("Failed to find get_server_connection2");
        }
    }

    ~LuminaConnection() {
        // Note: We don't close the handle as it's the main process
    }

    bool connect(uint64_t mode = 0) {
        m_connection = m_get_server_connection2(mode);
        if (!m_connection) {
            return false;
        }

        // Read vtable pointer from connection object
        m_vtable = *static_cast<void**>(m_connection);
        return m_vtable != nullptr;
    }

    bool is_connected() const {
        return m_connection != nullptr && m_vtable != nullptr;
    }

    /**
     * Push all function metadata to Lumina.
     *
     * Input structure (empty = push all functions):
     *   +0x00: pointer (nullptr for all)
     *   +0x08: uint64 (0)
     *   +0x10: uint64 (0)
     *   +0x18: int64 (-1 sentinel)
     *
     * Output structure:
     *   +0x00: pointer to EA array
     *   +0x08: count
     *   +0x18: pointer to result code array (uint32 per entry)
     */
    bool push_all(PushStats& stats) {
        if (!is_connected()) {
            std::cerr << CLR(Red) << "[-] Not connected to Lumina" << CLR(Reset) << "\n";
            return false;
        }

        // Get push_metadata method from vtable
        void* push_method = get_push_metadata_method();
        if (!push_method) {
            std::cerr << CLR(Red) << "[-] Failed to get push_metadata method" << CLR(Reset) << "\n";
            return false;
        }

        auto push_fn = reinterpret_cast<PushMetadataFn>(push_method);

        // Allocate input structure (empty = push all)
        struct {
            void* ptr;
            uint64_t field1;
            uint64_t field2;
            int64_t sentinel;
        } input = { nullptr, 0, 0, -1 };

        // Allocate output structure
        struct {
            void* ea_array;
            uint64_t count;
            uint64_t reserved;
            void* result_array;
            uint8_t padding[64];
        } output = {};

        // Allocate error output
        struct {
            void* str_ptr;
            void* has_error;
            uint64_t reserved;
        } error_out = {};

        // Call push_metadata
        if (g_opts.verbose) {
            std::cout << "[*] Calling push_metadata..." << std::endl;
        }

        uint8_t result = push_fn(m_connection, &output, &input, &error_out, 0, 0);

        // Parse results
        stats.total = static_cast<size_t>(output.count);

        if (stats.total > 0 && output.ea_array && output.result_array) {
            auto* results = static_cast<uint32_t*>(output.result_array);

            for (size_t i = 0; i < stats.total; i++) {
                uint32_t code = results[i];
                switch (code) {
                    case 0: stats.skip++; break;
                    case 1: stats.new_count++; break;
                    case 2: stats.exists++; break;
                    default: stats.error++; break;
                }
            }
        }

        // Check for error
        if (error_out.has_error && error_out.str_ptr) {
            const char* err_str = static_cast<const char*>(error_out.str_ptr);
            std::cerr << CLR(Red) << "[-] Lumina error: " << err_str << CLR(Reset) << "\n";
            return false;
        }

        return result != 0;
    }
};

//=============================================================================
// Resource Management
//=============================================================================

class HeadlessIdaContext {
public:
    HeadlessIdaContext(const char *input_file) {
        // Disable plugins by creating a fake IDADIR with empty plugins folder
        if (g_opts.no_plugins) {
            // Only block all plugins if no specific plugins were requested
            // If user specified --plugin patterns, we rely on fake IDADIR to control loading
            if (g_opts.plugin_patterns.empty()) {
                g_block_plugins = true;
            }

#ifndef _WIN32
            const char* idadir = real_getenv("IDADIR");
            const char* home = real_getenv("HOME");

            if (idadir && home) {
                std::string real_idadir = idadir;
                m_fake_idadir_base = "/tmp/.ida_no_plugins_" + std::to_string(getpid());
                std::string fake_idadir = m_fake_idadir_base + "/ida";
                std::string fake_plugins = fake_idadir + "/plugins";

                // Create fake IDA directory structure
                mkdir(m_fake_idadir_base.c_str(), 0755);
                mkdir(fake_idadir.c_str(), 0755);
                mkdir(fake_plugins.c_str(), 0755);

                // Symlink hexrays decompiler plugins and user-specified plugins
                std::string real_plugins = real_idadir + "/plugins";
                DIR* pdir = opendir(real_plugins.c_str());
                if (pdir) {
                    struct dirent* pentry;
                    while ((pentry = readdir(pdir)) != NULL) {
                        bool should_link = false;

                        // Always link hex* plugins (Hex-Rays decompilers)
                        if (strncmp(pentry->d_name, "hex", 3) == 0) {
                            should_link = true;
                        }

                        // Check user-specified patterns
                        for (const auto& pattern : g_opts.plugin_patterns) {
                            if (strstr(pentry->d_name, pattern.c_str()) != nullptr) {
                                should_link = true;
                                break;
                            }
                        }

                        if (should_link) {
                            std::string src = real_plugins + "/" + pentry->d_name;
                            std::string dst = fake_plugins + "/" + pentry->d_name;
                            symlink(src.c_str(), dst.c_str());
                        }
                    }
                    closedir(pdir);
                }

                // Symlink all entries from real IDADIR except plugins
                DIR* dir = opendir(real_idadir.c_str());
                if (dir) {
                    struct dirent* entry;
                    while ((entry = readdir(dir)) != NULL) {
                        if (strcmp(entry->d_name, ".") == 0 ||
                            strcmp(entry->d_name, "..") == 0 ||
                            strcmp(entry->d_name, "plugins") == 0) {
                            continue;
                        }
                        std::string src = real_idadir + "/" + entry->d_name;
                        std::string dst = fake_idadir + "/" + entry->d_name;
                        symlink(src.c_str(), dst.c_str());
                    }
                    closedir(dir);
                }

                real_setenv("IDADIR", fake_idadir.c_str());

                // Also redirect IDAUSR
                std::string real_idausr = std::string(home) + "/.idapro";
                std::string fake_idausr = m_fake_idadir_base + "/user";
                mkdir(fake_idausr.c_str(), 0755);
                symlink((real_idausr + "/ida.reg").c_str(), (fake_idausr + "/ida.reg").c_str());
                real_setenv("IDAUSR", fake_idausr.c_str());
            }
#endif
        }

        if (init_library() != 0) {
            throw std::runtime_error("Failed to initialize IDA library.");
        }

        enable_console_messages(!g_opts.quiet);

        if (open_database(input_file, true) != 0) {
            throw std::runtime_error(std::string("Failed to open: ") + input_file);
        }

        if (!g_opts.quiet) {
            std::cout << "[*] Waiting for auto-analysis..." << std::endl;
        }
        auto_wait();
        if (!g_opts.quiet) {
            std::cout << "[*] Analysis complete." << std::endl;
        }

        // Initialize Hex-Rays (optional for Lumina, but useful)
        if (init_hexrays_plugin()) {
            m_hexrays_available = true;
        }
    }

    ~HeadlessIdaContext() {
        if (m_hexrays_available) {
            term_hexrays_plugin();
        }
        set_database_flag(DBFL_KILL);
        term_database();

        // Clean up fake IDADIR if we created one
        if (!m_fake_idadir_base.empty()) {
            std::error_code ec;
            std::filesystem::remove_all(m_fake_idadir_base, ec);
        }
    }

    bool hexrays_available() const { return m_hexrays_available; }

    HeadlessIdaContext(const HeadlessIdaContext&) = delete;
    HeadlessIdaContext& operator=(const HeadlessIdaContext&) = delete;

private:
    bool m_hexrays_available = false;
    std::string m_fake_idadir_base;  // Path to clean up on destruction
};

//=============================================================================
// Usage
//=============================================================================

static void print_usage(const char* prog) {
    std::cout << CLR(Bold) << "IDA Pro Lumina Push Tool" << CLR(Reset) << "\n\n";
    std::cout << CLR(Cyan) << "Usage:" << CLR(Reset) << " " << prog << " [options] <binary_file>\n\n";
    std::cout << CLR(Cyan) << "Description:" << CLR(Reset) << "\n";
    std::cout << "  Analyzes a binary and pushes all function metadata to the Lumina server.\n\n";
    std::cout << CLR(Cyan) << "Options:" << CLR(Reset) << "\n";
    std::cout << "  -q, --quiet          Suppress IDA's verbose messages\n";
    std::cout << "  -v, --verbose        Show extra debug output\n";
    std::cout << "  --no-color           Disable colored output\n";
    std::cout << "  --no-plugins         Don't load user plugins (except Hex-Rays)\n";
    std::cout << "  --plugin <pattern>   Load plugins matching pattern (implies --no-plugins)\n";
    std::cout << "                       Can be specified multiple times\n";
    std::cout << "  -h, --help           Show this help\n";
    std::cout << "\n";
    std::cout << CLR(Cyan) << "Examples:" << CLR(Reset) << "\n";
    std::cout << "  " << prog << " program.exe         # Analyze and push to Lumina\n";
    std::cout << "  " << prog << " -q program.exe      # Quiet mode\n";
    std::cout << "\n";
    std::cout << CLR(Cyan) << "Note:" << CLR(Reset) << "\n";
    std::cout << "  Lumina credentials must be configured in IDA Pro settings.\n";
    std::cout << "  The tool uses IDA's existing Lumina configuration.\n";
    std::cout << "\n";
}

static bool parse_args(int argc, char* argv[]) {
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];

        if (arg == "-h" || arg == "--help") {
            print_usage(argv[0]);
            exit(0);
        }
        else if (arg == "-q" || arg == "--quiet") {
            g_opts.quiet = true;
        }
        else if (arg == "-v" || arg == "--verbose") {
            g_opts.verbose = true;
        }
        else if (arg == "--no-color") {
            Color::disable();
        }
        else if (arg == "--no-plugins") {
            g_opts.no_plugins = true;
        }
        else if (arg == "--plugin") {
            if (i + 1 >= argc) {
                std::cerr << "Error: --plugin requires a pattern argument\n";
                return false;
            }
            g_opts.plugin_patterns.push_back(argv[++i]);
            g_opts.no_plugins = true;  // --plugin implies --no-plugins
        }
        else if (arg[0] == '-') {
            std::cerr << "Unknown option: " << arg << "\n";
            return false;
        }
        else {
            if (g_opts.input_file.empty()) {
                g_opts.input_file = arg;
            } else {
                std::cerr << "Error: Multiple input files specified\n";
                return false;
            }
        }
    }

    if (g_opts.input_file.empty()) {
        std::cerr << "Error: No input file specified\n";
        return false;
    }

    return true;
}

//=============================================================================
// Main
//=============================================================================

int main(int argc, char *argv[]) {
    if (!parse_args(argc, argv)) {
        std::cerr << "Use --help for usage information\n";
        return EXIT_FAILURE;
    }

    try {
        HeadlessIdaContext ctx(g_opts.input_file.c_str());

        // Print basic info
        if (!g_opts.quiet) {
            size_t func_count = get_func_qty();
            std::cout << "\n";
            std::cout << CLR(Bold) << "Lumina Push" << CLR(Reset) << "\n";
            std::cout << std::string(50, '-') << "\n";
            std::cout << "  Functions: " << func_count << "\n";
            std::cout << "\n";
        }

        // Connect to Lumina
        std::cout << "[*] Connecting to Lumina server..." << std::endl;

        LuminaConnection lumina;
        if (!lumina.connect(0)) {
            std::cerr << CLR(Red) << "[-] Failed to connect to Lumina server" << CLR(Reset) << "\n";
            std::cerr << "    Make sure Lumina is configured in IDA settings.\n";
            return EXIT_FAILURE;
        }

        std::cout << CLR(Green) << "[+] Connected to Lumina" << CLR(Reset) << "\n";

        // Push all metadata
        std::cout << "[*] Pushing function metadata to Lumina..." << std::endl;

        PushStats stats;
        bool success = lumina.push_all(stats);

        // Print results
        std::cout << "\n";
        std::cout << CLR(Bold) << "Results" << CLR(Reset) << "\n";
        std::cout << std::string(50, '-') << "\n";
        std::cout << "  Total processed: " << stats.total << "\n";
        std::cout << "  " << CLR(Green) << "New:      " << stats.new_count << CLR(Reset) << "\n";
        std::cout << "  " << CLR(Cyan) << "Exists:   " << stats.exists << CLR(Reset) << "\n";
        std::cout << "  " << CLR(Dim) << "Skipped:  " << stats.skip << CLR(Reset) << "\n";
        if (stats.error > 0) {
            std::cout << "  " << CLR(Red) << "Errors:   " << stats.error << CLR(Reset) << "\n";
        }
        std::cout << std::string(50, '-') << "\n";

        if (success) {
            std::cout << CLR(Green) << "[+] Lumina push completed successfully" << CLR(Reset) << "\n";
        } else {
            std::cout << CLR(Yellow) << "[!] Lumina push completed with issues" << CLR(Reset) << "\n";
        }

        if (!g_opts.quiet) {
            std::cout << "[*] Done.\n";
        }
    }
    catch (const std::exception &e) {
        std::cerr << CLR(Red) << "[FATAL] " << CLR(Reset) << e.what() << std::endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
