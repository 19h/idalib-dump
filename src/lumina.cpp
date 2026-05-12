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
#include <cerrno>
#include <cstdlib>
#include <cstdint>
#include <fstream>
#include <filesystem>
#include <limits>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <dlfcn.h>
#include <sys/stat.h>
#include <sys/wait.h>
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

#ifndef _WIN32
static inline pid_t real_waitpid(pid_t pid, int* status, int options) {
    return waitpid(pid, status, options);
}

static inline ssize_t real_read(int fd, void* buf, size_t count) {
    return read(fd, buf, count);
}

static inline ssize_t real_write(int fd, const void* buf, size_t count) {
    return write(fd, buf, count);
}

static inline int real_close(int fd) {
    return close(fd);
}

static inline int real_pipe(int pipefd[2]) {
    return pipe(pipefd);
}

static inline pid_t real_fork() {
    return fork();
}
#endif

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
    bool recursive = false;
    bool verbose = false;
    bool require_debug = false;
    unsigned int jobs = 0;
    bool jobs_specified = false;
    std::vector<std::string> extensions;
    std::vector<std::string> file_types;
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

struct FileRunResult {
    size_t function_count = 0;
    PushStats stats;
    bool success = false;
    std::string error_message;
};

#ifndef _WIN32
constexpr size_t CHILD_ERROR_MESSAGE_SIZE = 512;

struct ChildRunMessage {
    uint64_t total = 0;
    uint64_t skip = 0;
    uint64_t new_count = 0;
    uint64_t exists = 0;
    uint64_t error = 0;
    uint8_t success = 0;
    char error_message[CHILD_ERROR_MESSAGE_SIZE] = {};
};

struct WorkerProcess {
    pid_t pid = -1;
    int read_fd = -1;
    std::string input_file;
};

struct BatchRunStats {
    size_t files_total = 0;
    size_t files_succeeded = 0;
    size_t files_failed = 0;
    PushStats lumina;
};
#endif

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
    bool push_all(PushStats& stats, std::string* error_message = nullptr, bool emit_output = true) {
        if (!is_connected()) {
            if (error_message) {
                *error_message = "Not connected to Lumina";
            }
            if (emit_output) {
                std::cerr << CLR(Red) << "[-] Not connected to Lumina" << CLR(Reset) << "\n";
            }
            return false;
        }

        // Get push_metadata method from vtable
        void* push_method = get_push_metadata_method();
        if (!push_method) {
            if (error_message) {
                *error_message = "Failed to get push_metadata method";
            }
            if (emit_output) {
                std::cerr << CLR(Red) << "[-] Failed to get push_metadata method" << CLR(Reset) << "\n";
            }
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
        if (emit_output && g_opts.verbose) {
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
            if (error_message) {
                *error_message = err_str;
            }
            if (emit_output) {
                std::cerr << CLR(Red) << "[-] Lumina error: " << err_str << CLR(Reset) << "\n";
            }
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
    HeadlessIdaContext(const char *input_file, bool quiet_mode) {
        if (g_opts.no_plugins) {
#ifndef _WIN32
            const char* idadir_env = real_getenv("IDADIR");
            const char* home = real_getenv("HOME");

            std::string detected_idadir;
            if (!idadir_env) {
                void* libida_sym = dlsym(RTLD_DEFAULT, "qalloc");
                Dl_info dli;
                if (libida_sym && dladdr(libida_sym, &dli) && dli.dli_fname) {
                    std::string libida_path(dli.dli_fname);
                    auto slash = libida_path.rfind('/');
                    if (slash != std::string::npos) {
                        detected_idadir = libida_path.substr(0, slash);
                    }
                }
            }

            const char* idadir = idadir_env ? idadir_env : (detected_idadir.empty() ? nullptr : detected_idadir.c_str());

            if (idadir && home) {
                std::string real_idadir = idadir;
                m_fake_idadir_base = "/tmp/.ida_no_plugins_" + std::to_string(getpid());
                std::string fake_idadir = m_fake_idadir_base + "/ida";

                mkdir(m_fake_idadir_base.c_str(), 0755);
                mkdir(fake_idadir.c_str(), 0755);

                // Mirror IDADIR so bundled Hex-Rays/system plugins still load.
                DIR* dir = opendir(real_idadir.c_str());
                if (dir) {
                    struct dirent* entry;
                    while ((entry = readdir(dir)) != NULL) {
                        if (strcmp(entry->d_name, ".") == 0 ||
                            strcmp(entry->d_name, "..") == 0) {
                            continue;
                        }
                        std::string src = real_idadir + "/" + entry->d_name;
                        std::string dst = fake_idadir + "/" + entry->d_name;
                        symlink(src.c_str(), dst.c_str());
                    }
                    closedir(dir);
                }

                real_setenv("IDADIR", fake_idadir.c_str());

                std::string real_idausr = std::string(home) + "/.idapro";
                std::string fake_idausr = m_fake_idadir_base + "/user";
                mkdir(fake_idausr.c_str(), 0755);

                auto symlink_user_dir_unique = [&](const char* subdir) {
                    std::string user_dir = real_idausr + "/" + subdir;
                    std::string fake_dir = fake_idausr + "/" + subdir;
                    std::string sys_dir = real_idadir + "/" + subdir;
                    mkdir(fake_dir.c_str(), 0755);
                    DIR* d = opendir(user_dir.c_str());
                    if (!d) {
                        return;
                    }
                    struct dirent* e;
                    while ((e = readdir(d)) != NULL) {
                        if (e->d_name[0] == '.') {
                            continue;
                        }
                        std::string sys_path = sys_dir + "/" + e->d_name;
                        struct stat st;
                        if (stat(sys_path.c_str(), &st) == 0) {
                            continue;
                        }
                        std::string src = user_dir + "/" + e->d_name;
                        std::string dst = fake_dir + "/" + e->d_name;
                        symlink(src.c_str(), dst.c_str());
                    }
                    closedir(d);
                };

                DIR* udir = opendir(real_idausr.c_str());
                if (udir) {
                    struct dirent* uentry;
                    while ((uentry = readdir(udir)) != NULL) {
                        if (strcmp(uentry->d_name, ".") == 0 ||
                            strcmp(uentry->d_name, "..") == 0 ||
                            strcmp(uentry->d_name, "plugins") == 0 ||
                            strcmp(uentry->d_name, "procs") == 0 ||
                            strcmp(uentry->d_name, "loaders") == 0) {
                            continue;
                        }
                        std::string src = real_idausr + "/" + uentry->d_name;
                        std::string dst = fake_idausr + "/" + uentry->d_name;
                        symlink(src.c_str(), dst.c_str());
                    }
                    closedir(udir);
                }

                symlink_user_dir_unique("procs");
                symlink_user_dir_unique("loaders");

                std::string fake_user_plugins = fake_idausr + "/plugins";
                mkdir(fake_user_plugins.c_str(), 0755);

                std::string real_user_plugins = real_idausr + "/plugins";
                DIR* pdir = opendir(real_user_plugins.c_str());
                if (pdir) {
                    struct dirent* pentry;
                    while ((pentry = readdir(pdir)) != NULL) {
                        for (const auto& pattern : g_opts.plugin_patterns) {
                            if (strstr(pentry->d_name, pattern.c_str()) != nullptr) {
                                std::string src = real_user_plugins + "/" + pentry->d_name;
                                std::string dst = fake_user_plugins + "/" + pentry->d_name;
                                symlink(src.c_str(), dst.c_str());
                                break;
                            }
                        }
                    }
                    closedir(pdir);
                }

                real_setenv("IDAUSR", fake_idausr.c_str());
            }
#else
            g_block_plugins = true;
#endif
        }

        if (init_library() != 0) {
            throw std::runtime_error("Failed to initialize IDA library.");
        }

        enable_console_messages(!quiet_mode);

        if (open_database(input_file, true) != 0) {
            throw std::runtime_error(std::string("Failed to open: ") + input_file);
        }

        if (!quiet_mode) {
            std::cout << "[*] Waiting for auto-analysis..." << std::endl;
        }
        auto_wait();
        if (!quiet_mode) {
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

static unsigned int default_job_count() {
#ifdef _WIN32
    SYSTEM_INFO info = {};
    GetSystemInfo(&info);
    return info.dwNumberOfProcessors == 0 ? 1u : info.dwNumberOfProcessors;
#else
    long count = sysconf(_SC_NPROCESSORS_ONLN);
    return count > 0 ? static_cast<unsigned int>(count) : 1u;
#endif
}

static bool parse_positive_uint(const std::string& value, unsigned int& parsed) {
    try {
        size_t consumed = 0;
        unsigned long number = std::stoul(value, &consumed, 10);
        if (consumed != value.size() ||
            number == 0 ||
            number > std::numeric_limits<unsigned int>::max()) {
            return false;
        }
        parsed = static_cast<unsigned int>(number);
        return true;
    }
    catch (...) {
        return false;
    }
}

static std::string to_lower_ascii(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return value;
}

static std::string normalize_extension(std::string value) {
    value = to_lower_ascii(value);
    while (!value.empty() && value.front() == '.') {
        value.erase(value.begin());
    }
    return value;
}

static std::string path_extension_without_dot(const std::filesystem::path& path) {
    return normalize_extension(path.extension().string());
}

static std::string normalize_file_type(std::string value) {
    value = to_lower_ascii(value);
    if (value == "mach" || value == "macho" || value == "mach_o") {
        return "mach-o";
    }
    return value;
}

static bool valid_file_type_filter(const std::string& value) {
    return value == "pe" || value == "elf" || value == "mach-o" || value == "unknown";
}

static bool read_file_range(const std::filesystem::path& path, uint64_t offset, size_t size, std::vector<uint8_t>& out) {
    out.clear();
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        return false;
    }

    file.seekg(0, std::ios::end);
    const std::streamoff length = file.tellg();
    if (length < 0 || offset >= static_cast<uint64_t>(length)) {
        return false;
    }

    const uint64_t available = static_cast<uint64_t>(length) - offset;
    const size_t to_read = static_cast<size_t>(std::min<uint64_t>(available, size));
    out.resize(to_read);
    file.seekg(static_cast<std::streamoff>(offset), std::ios::beg);
    file.read(reinterpret_cast<char*>(out.data()), static_cast<std::streamsize>(out.size()));
    return file.good() || static_cast<size_t>(file.gcount()) == out.size();
}

static uint16_t read_u16(const std::vector<uint8_t>& data, size_t off, bool little_endian = true) {
    if (off + 2 > data.size()) {
        return 0;
    }
    if (little_endian) {
        return static_cast<uint16_t>(data[off] | (data[off + 1] << 8));
    }
    return static_cast<uint16_t>((data[off] << 8) | data[off + 1]);
}

static uint32_t read_u32(const std::vector<uint8_t>& data, size_t off, bool little_endian = true) {
    if (off + 4 > data.size()) {
        return 0;
    }
    if (little_endian) {
        return static_cast<uint32_t>(data[off])
            | (static_cast<uint32_t>(data[off + 1]) << 8)
            | (static_cast<uint32_t>(data[off + 2]) << 16)
            | (static_cast<uint32_t>(data[off + 3]) << 24);
    }
    return (static_cast<uint32_t>(data[off]) << 24)
        | (static_cast<uint32_t>(data[off + 1]) << 16)
        | (static_cast<uint32_t>(data[off + 2]) << 8)
        | static_cast<uint32_t>(data[off + 3]);
}

static uint64_t read_u64(const std::vector<uint8_t>& data, size_t off, bool little_endian = true) {
    if (off + 8 > data.size()) {
        return 0;
    }
    if (little_endian) {
        uint64_t value = 0;
        for (size_t i = 0; i < 8; ++i) {
            value |= static_cast<uint64_t>(data[off + i]) << (i * 8);
        }
        return value;
    }

    uint64_t value = 0;
    for (size_t i = 0; i < 8; ++i) {
        value = (value << 8) | data[off + i];
    }
    return value;
}

static bool starts_with_string(const std::string& value, const char* prefix) {
    const size_t prefix_len = std::strlen(prefix);
    return value.size() >= prefix_len && value.compare(0, prefix_len, prefix) == 0;
}

static size_t bounded_cstring_length(const char* value, size_t max_len) {
    size_t len = 0;
    while (len < max_len && value[len] != '\0') {
        ++len;
    }
    return len;
}

static bool same_basename_pdb_exists(const std::filesystem::path& input_path) {
    std::error_code ec;
    std::filesystem::path direct = input_path;
    direct.replace_extension(".pdb");
    if (std::filesystem::is_regular_file(direct, ec) && !ec) {
        return true;
    }

    ec.clear();
    const std::filesystem::path parent = input_path.parent_path().empty()
        ? std::filesystem::path(".")
        : input_path.parent_path();
    if (!std::filesystem::is_directory(parent, ec) || ec) {
        return false;
    }

    const std::string target = to_lower_ascii(input_path.stem().string() + ".pdb");
    for (const auto& entry : std::filesystem::directory_iterator(parent, ec)) {
        if (ec) {
            break;
        }
        if (!entry.is_regular_file(ec) || ec) {
            ec.clear();
            continue;
        }
        if (to_lower_ascii(entry.path().filename().string()) == target) {
            return true;
        }
    }
    return false;
}

struct FileInspection {
    std::string type = "unknown";
    bool has_debug = false;
};

static bool has_pe_signature(const std::filesystem::path& path, const std::vector<uint8_t>& prefix) {
    if (prefix.size() < 0x40) {
        return false;
    }

    const uint32_t pe_offset = read_u32(prefix, 0x3c);
    std::vector<uint8_t> headers;
    if (!read_file_range(path, pe_offset, 24, headers) || headers.size() < 24) {
        return false;
    }
    return headers[0] == 'P' && headers[1] == 'E' && headers[2] == 0 && headers[3] == 0;
}

static bool detect_pe_debug_info(const std::filesystem::path& path, const std::vector<uint8_t>& prefix) {
    if (!has_pe_signature(path, prefix)) {
        return false;
    }
    if (same_basename_pdb_exists(path)) {
        return true;
    }

    const uint32_t pe_offset = read_u32(prefix, 0x3c);
    std::vector<uint8_t> headers;
    if (!read_file_range(path, pe_offset, 24, headers) || headers.size() < 24) {
        return false;
    }

    const uint16_t section_count = read_u16(headers, 6);
    const uint16_t optional_header_size = read_u16(headers, 20);
    const size_t full_header_size = 24 + static_cast<size_t>(optional_header_size) + static_cast<size_t>(section_count) * 40;
    if (!read_file_range(path, pe_offset, full_header_size, headers) || headers.size() < full_header_size) {
        return false;
    }

    const size_t optional_offset = 24;
    const uint16_t optional_magic = read_u16(headers, optional_offset);
    size_t data_directory_offset = 0;
    if (optional_magic == 0x10b) {
        data_directory_offset = optional_offset + 96;
    }
    else if (optional_magic == 0x20b) {
        data_directory_offset = optional_offset + 112;
    }
    else {
        return false;
    }

    const size_t debug_directory = data_directory_offset + 6 * 8;
    if (debug_directory + 8 > headers.size()) {
        return false;
    }
    const uint32_t debug_rva = read_u32(headers, debug_directory);
    const uint32_t debug_size = read_u32(headers, debug_directory + 4);
    if (debug_rva == 0 || debug_size == 0) {
        return false;
    }

    const size_t section_table = optional_offset + optional_header_size;
    uint64_t debug_file_offset = 0;
    for (uint16_t i = 0; i < section_count; ++i) {
        const size_t section = section_table + static_cast<size_t>(i) * 40;
        const uint32_t virtual_size = read_u32(headers, section + 8);
        const uint32_t virtual_address = read_u32(headers, section + 12);
        const uint32_t raw_size = read_u32(headers, section + 16);
        const uint32_t raw_pointer = read_u32(headers, section + 20);
        const uint32_t mapped_size = std::max(virtual_size, raw_size);
        if (debug_rva >= virtual_address && debug_rva < virtual_address + mapped_size) {
            debug_file_offset = static_cast<uint64_t>(raw_pointer) + (debug_rva - virtual_address);
            break;
        }
    }

    if (debug_file_offset == 0) {
        return true;
    }

    std::vector<uint8_t> debug_data;
    const size_t debug_read_size = static_cast<size_t>(std::min<uint32_t>(debug_size, 64 * 1024));
    if (!read_file_range(path, debug_file_offset, debug_read_size, debug_data) || debug_data.size() < 28) {
        return true;
    }

    for (size_t off = 0; off + 28 <= debug_data.size(); off += 28) {
        const uint32_t type = read_u32(debug_data, off + 12);
        const uint32_t size_of_data = read_u32(debug_data, off + 16);
        const uint32_t pointer_to_raw_data = read_u32(debug_data, off + 24);
        if (type == 2 && size_of_data >= 4 && pointer_to_raw_data != 0) {
            std::vector<uint8_t> codeview;
            if (read_file_range(path, pointer_to_raw_data, std::min<uint32_t>(size_of_data, 4096), codeview)
                && codeview.size() >= 4
                && ((codeview[0] == 'R' && codeview[1] == 'S' && codeview[2] == 'D' && codeview[3] == 'S')
                    || (codeview[0] == 'N' && codeview[1] == 'B' && codeview[2] == '1' && codeview[3] == '0'))) {
                return true;
            }
        }
    }

    return true;
}

static bool detect_elf_debug_info(const std::filesystem::path& path, const std::vector<uint8_t>& prefix) {
    if (prefix.size() < 64 || prefix[0] != 0x7f || prefix[1] != 'E' || prefix[2] != 'L' || prefix[3] != 'F') {
        return false;
    }

    const uint8_t elf_class = prefix[4];
    const uint8_t elf_data = prefix[5];
    const bool little_endian = elf_data != 2;

    uint64_t section_header_offset = 0;
    uint16_t section_header_size = 0;
    uint16_t section_count = 0;
    uint16_t string_table_index = 0;

    if (elf_class == 1) {
        section_header_offset = read_u32(prefix, 32, little_endian);
        section_header_size = read_u16(prefix, 46, little_endian);
        section_count = read_u16(prefix, 48, little_endian);
        string_table_index = read_u16(prefix, 50, little_endian);
    }
    else if (elf_class == 2) {
        section_header_offset = read_u64(prefix, 40, little_endian);
        section_header_size = read_u16(prefix, 58, little_endian);
        section_count = read_u16(prefix, 60, little_endian);
        string_table_index = read_u16(prefix, 62, little_endian);
    }
    else {
        return false;
    }

    if (section_header_offset == 0 || section_header_size == 0 || section_count == 0 || string_table_index >= section_count) {
        return false;
    }

    const uint64_t table_size64 = static_cast<uint64_t>(section_header_size) * section_count;
    if (table_size64 > 16 * 1024 * 1024) {
        return false;
    }

    std::vector<uint8_t> section_headers;
    if (!read_file_range(path, section_header_offset, static_cast<size_t>(table_size64), section_headers)
        || section_headers.size() < table_size64) {
        return false;
    }

    const size_t str_section = static_cast<size_t>(string_table_index) * section_header_size;
    uint64_t str_offset = 0;
    uint64_t str_size = 0;
    if (elf_class == 1) {
        str_offset = read_u32(section_headers, str_section + 16, little_endian);
        str_size = read_u32(section_headers, str_section + 20, little_endian);
    }
    else {
        str_offset = read_u64(section_headers, str_section + 24, little_endian);
        str_size = read_u64(section_headers, str_section + 32, little_endian);
    }

    if (str_size == 0 || str_size > 16 * 1024 * 1024) {
        return false;
    }

    std::vector<uint8_t> strings;
    if (!read_file_range(path, str_offset, static_cast<size_t>(str_size), strings)) {
        return false;
    }

    for (uint16_t i = 0; i < section_count; ++i) {
        const size_t section = static_cast<size_t>(i) * section_header_size;
        const uint32_t name_offset = read_u32(section_headers, section, little_endian);
        if (name_offset >= strings.size()) {
            continue;
        }

        const char* name_ptr = reinterpret_cast<const char*>(strings.data() + name_offset);
        const size_t remaining = strings.size() - name_offset;
        const size_t name_len = bounded_cstring_length(name_ptr, remaining);
        std::string name(name_ptr, name_len);
        if (starts_with_string(name, ".debug_")
            || starts_with_string(name, ".zdebug_")
            || name == ".gnu_debuglink"
            || name == ".stab"
            || name == ".stabstr") {
            return true;
        }
    }

    return false;
}

static bool has_adjacent_dsym(const std::filesystem::path& input_path) {
    std::error_code ec;
    return std::filesystem::is_directory(input_path.string() + ".dSYM", ec) && !ec;
}

static bool detect_macho_debug_info(const std::filesystem::path& path) {
    if (has_adjacent_dsym(path)) {
        return true;
    }

    std::vector<uint8_t> data;
    if (!read_file_range(path, 0, 1024 * 1024, data)) {
        return false;
    }

    const char dwarf_segment[] = "__DWARF";
    const char debug_prefix[] = "__debug_";
    return std::search(data.begin(), data.end(), std::begin(dwarf_segment), std::end(dwarf_segment) - 1) != data.end()
        || std::search(data.begin(), data.end(), std::begin(debug_prefix), std::end(debug_prefix) - 1) != data.end();
}

static FileInspection inspect_file(const std::string& input_file) {
    const std::filesystem::path path(input_file);
    std::vector<uint8_t> prefix;
    FileInspection inspection;
    if (!read_file_range(path, 0, 4096, prefix) || prefix.size() < 4) {
        return inspection;
    }

    if (prefix[0] == 'M' && prefix[1] == 'Z' && has_pe_signature(path, prefix)) {
        inspection.type = "pe";
        inspection.has_debug = detect_pe_debug_info(path, prefix);
    }
    else if (prefix[0] == 0x7f && prefix[1] == 'E' && prefix[2] == 'L' && prefix[3] == 'F') {
        inspection.type = "elf";
        inspection.has_debug = detect_elf_debug_info(path, prefix);
    }
    else {
        const uint32_t magic = read_u32(prefix, 0, true);
        const uint32_t magic_be = read_u32(prefix, 0, false);
        if (magic == 0xfeedface || magic == 0xfeedfacf || magic == 0xcefaedfe || magic == 0xcffaedfe
            || magic_be == 0xcafebabe || magic_be == 0xcafebabf) {
            inspection.type = "mach-o";
            inspection.has_debug = detect_macho_debug_info(path);
        }
    }

    return inspection;
}

static bool vector_contains(const std::vector<std::string>& values, const std::string& value) {
    return std::find(values.begin(), values.end(), value) != values.end();
}

static bool has_active_input_filters() {
    return !g_opts.extensions.empty() || !g_opts.file_types.empty() || g_opts.require_debug;
}

static bool file_matches_filters(const std::string& input_file, std::string* reason = nullptr) {
    const std::filesystem::path path(input_file);

    if (!g_opts.extensions.empty()) {
        const std::string extension = path_extension_without_dot(path);
        if (!vector_contains(g_opts.extensions, extension)) {
            if (reason) {
                *reason = "extension ." + extension + " is not enabled";
            }
            return false;
        }
    }

    if (!g_opts.file_types.empty() || g_opts.require_debug) {
        const FileInspection inspection = inspect_file(input_file);
        if (!g_opts.file_types.empty() && !vector_contains(g_opts.file_types, inspection.type)) {
            if (reason) {
                *reason = "detected type " + inspection.type + " is not enabled";
            }
            return false;
        }
        if (g_opts.require_debug && !inspection.has_debug) {
            if (reason) {
                *reason = "debug info was not detected";
            }
            return false;
        }
    }

    return true;
}

static void print_run_results(const FileRunResult& result) {
    std::cout << "\n";
    std::cout << CLR(Bold) << "Results" << CLR(Reset) << "\n";
    std::cout << std::string(50, '-') << "\n";
    std::cout << "  Total processed: " << result.stats.total << "\n";
    std::cout << "  " << CLR(Green) << "New:      " << result.stats.new_count << CLR(Reset) << "\n";
    std::cout << "  " << CLR(Cyan) << "Exists:   " << result.stats.exists << CLR(Reset) << "\n";
    std::cout << "  " << CLR(Dim) << "Skipped:  " << result.stats.skip << CLR(Reset) << "\n";
    if (result.stats.error > 0) {
        std::cout << "  " << CLR(Red) << "Errors:   " << result.stats.error << CLR(Reset) << "\n";
    }
    std::cout << std::string(50, '-') << "\n";

    if (result.success) {
        std::cout << CLR(Green) << "[+] Lumina push completed successfully" << CLR(Reset) << "\n";
    }
    else {
        std::cout << CLR(Yellow) << "[!] Lumina push completed with issues" << CLR(Reset) << "\n";
    }
}

static FileRunResult run_single_file(const std::string& input_file, bool emit_output) {
    FileRunResult result;
    HeadlessIdaContext ctx(input_file.c_str(), emit_output ? g_opts.quiet : true);

    result.function_count = get_func_qty();

    if (emit_output && !g_opts.quiet) {
        std::cout << "\n";
        std::cout << CLR(Bold) << "Lumina Push" << CLR(Reset) << "\n";
        std::cout << std::string(50, '-') << "\n";
        std::cout << "  Functions: " << result.function_count << "\n";
        std::cout << "\n";
    }

    if (emit_output) {
        std::cout << "[*] Connecting to Lumina server..." << std::endl;
    }

    LuminaConnection lumina;
    if (!lumina.connect(0)) {
        throw std::runtime_error("Failed to connect to Lumina server. Make sure Lumina is configured in IDA settings.");
    }

    if (emit_output) {
        std::cout << CLR(Green) << "[+] Connected to Lumina" << CLR(Reset) << "\n";
        std::cout << "[*] Pushing function metadata to Lumina..." << std::endl;
    }

    result.success = lumina.push_all(result.stats, &result.error_message, emit_output);

    if (emit_output) {
        print_run_results(result);
        if (!g_opts.quiet) {
            std::cout << "[*] Done.\n";
        }
    }

    return result;
}

#ifndef _WIN32
static bool write_full(int fd, const void* data, size_t size) {
    const uint8_t* ptr = static_cast<const uint8_t*>(data);
    size_t remaining = size;

    while (remaining > 0) {
        ssize_t written = real_write(fd, ptr, remaining);
        if (written <= 0) {
            if (errno == EINTR) {
                continue;
            }
            return false;
        }
        ptr += written;
        remaining -= static_cast<size_t>(written);
    }

    return true;
}

static bool read_full(int fd, void* data, size_t size) {
    uint8_t* ptr = static_cast<uint8_t*>(data);
    size_t remaining = size;

    while (remaining > 0) {
        ssize_t nread = real_read(fd, ptr, remaining);
        if (nread == 0) {
            return false;
        }
        if (nread < 0) {
            if (errno == EINTR) {
                continue;
            }
            return false;
        }
        ptr += nread;
        remaining -= static_cast<size_t>(nread);
    }

    return true;
}

static void set_child_error_message(ChildRunMessage& message, const std::string& error_text) {
    const size_t copy_size = std::min(error_text.size(), sizeof(message.error_message) - 1);
    std::memcpy(message.error_message, error_text.data(), copy_size);
    message.error_message[copy_size] = '\0';
}

static ChildRunMessage make_child_message(const FileRunResult& result) {
    ChildRunMessage message = {};
    message.total = result.stats.total;
    message.skip = result.stats.skip;
    message.new_count = result.stats.new_count;
    message.exists = result.stats.exists;
    message.error = result.stats.error;
    message.success = result.success ? 1 : 0;

    if (!result.error_message.empty()) {
        set_child_error_message(message, result.error_message);
    }

    return message;
}

static std::string wait_status_message(int status) {
    if (WIFEXITED(status)) {
        return "worker exited with status " + std::to_string(WEXITSTATUS(status));
    }
    if (WIFSIGNALED(status)) {
        return "worker terminated by signal " + std::to_string(WTERMSIG(status));
    }
    return "worker terminated unexpectedly";
}

struct InputFilterStats {
    size_t regular_files = 0;
    size_t skipped_by_filter = 0;
};

static std::vector<std::string> collect_recursive_inputs(const std::string& root_dir, InputFilterStats* stats = nullptr) {
    std::filesystem::path root_path(root_dir);
    std::error_code ec;

    if (!std::filesystem::exists(root_path, ec) || ec) {
        throw std::runtime_error("Input path does not exist: " + root_dir);
    }
    if (!std::filesystem::is_directory(root_path, ec) || ec) {
        throw std::runtime_error("Recursive mode requires a directory input: " + root_dir);
    }

    std::vector<std::string> files;
    const auto options = std::filesystem::directory_options::skip_permission_denied;
    std::filesystem::recursive_directory_iterator end;
    std::filesystem::recursive_directory_iterator it(root_path, options, ec);
    if (ec) {
        throw std::runtime_error("Failed to scan directory: " + root_dir + ": " + ec.message());
    }

    for (; it != end; it.increment(ec)) {
        if (ec) {
            ec.clear();
            continue;
        }

        std::error_code status_ec;
        if (it->is_regular_file(status_ec) && !status_ec) {
            if (stats) {
                stats->regular_files++;
            }
            if (file_matches_filters(it->path().string())) {
                files.push_back(it->path().string());
            }
            else if (stats) {
                stats->skipped_by_filter++;
            }
        }
    }

    std::sort(files.begin(), files.end());
    return files;
}

static int run_recursive_mode() {
    InputFilterStats filter_stats;
    const std::vector<std::string> files = collect_recursive_inputs(g_opts.input_file, &filter_stats);
    if (files.empty()) {
        std::cerr << CLR(Yellow) << "[!] No matching regular files found under " << g_opts.input_file << CLR(Reset) << "\n";
        return EXIT_FAILURE;
    }

    const unsigned int requested_jobs = g_opts.jobs_specified ? g_opts.jobs : default_job_count();
    const size_t max_jobs = std::max<size_t>(1, std::min<size_t>(requested_jobs, files.size()));

    std::cout << "[*] Found " << files.size() << " matching files under " << g_opts.input_file;
    if (has_active_input_filters()) {
        std::cout << " (" << filter_stats.skipped_by_filter << " skipped by filters)";
    }
    std::cout << "; running up to " << max_jobs << " worker processes." << std::endl;

    BatchRunStats batch;
    batch.files_total = files.size();

    std::vector<WorkerProcess> running;
    size_t next_index = 0;
    bool scheduling_failed = false;
    std::string scheduling_error;

    while ((next_index < files.size() && !scheduling_failed) || !running.empty()) {
        while (!scheduling_failed && running.size() < max_jobs && next_index < files.size()) {
            int pipefd[2] = {-1, -1};
            if (real_pipe(pipefd) != 0) {
                scheduling_failed = true;
                scheduling_error = std::string("Failed to create worker pipe: ") + std::strerror(errno);
                break;
            }

            std::cout.flush();
            std::cerr.flush();

            const std::string& input_file = files[next_index];
            pid_t pid = real_fork();
            if (pid < 0) {
                real_close(pipefd[0]);
                real_close(pipefd[1]);
                scheduling_failed = true;
                scheduling_error = std::string("Failed to fork worker: ") + std::strerror(errno);
                break;
            }

            if (pid == 0) {
                real_close(pipefd[0]);

                ChildRunMessage message = {};
                int exit_code = EXIT_FAILURE;

                try {
                    message = make_child_message(run_single_file(input_file, false));
                    if (!message.success && message.error_message[0] == '\0') {
                        set_child_error_message(message, "Lumina push completed with issues");
                    }
                    exit_code = message.success ? EXIT_SUCCESS : EXIT_FAILURE;
                }
                catch (const std::exception& e) {
                    set_child_error_message(message, e.what());
                }

                write_full(pipefd[1], &message, sizeof(message));
                real_close(pipefd[1]);
                std::exit(exit_code);
            }

            real_close(pipefd[1]);
            running.push_back(WorkerProcess{pid, pipefd[0], input_file});
            next_index++;
        }

        if (running.empty()) {
            break;
        }

        int status = 0;
        pid_t finished_pid = real_waitpid(-1, &status, 0);
        if (finished_pid < 0) {
            if (errno == EINTR) {
                continue;
            }
            throw std::runtime_error(std::string("waitpid failed: ") + std::strerror(errno));
        }

        auto worker_it = std::find_if(running.begin(), running.end(),
            [finished_pid](const WorkerProcess& worker) {
                return worker.pid == finished_pid;
            });
        if (worker_it == running.end()) {
            continue;
        }

        ChildRunMessage message = {};
        const bool received_message = read_full(worker_it->read_fd, &message, sizeof(message));
        real_close(worker_it->read_fd);

        std::string error_text;
        if (!received_message) {
            error_text = "worker exited without a result message";
        }
        else if (message.error_message[0] != '\0') {
            error_text = message.error_message;
        }

        const bool worker_ok = received_message &&
            WIFEXITED(status) &&
            WEXITSTATUS(status) == EXIT_SUCCESS &&
            message.success != 0;

        if (!worker_ok && error_text.empty()) {
            error_text = wait_status_message(status);
        }

        std::cout << (worker_ok ? CLR(Green) : CLR(Red))
                  << (worker_ok ? "[+]" : "[-]")
                  << CLR(Reset) << " " << worker_it->input_file
                  << "  total=" << message.total
                  << " new=" << message.new_count
                  << " exists=" << message.exists
                  << " skipped=" << message.skip
                  << " errors=" << message.error;
        if (!error_text.empty()) {
            std::cout << "  (" << error_text << ")";
        }
        std::cout << "\n";

        batch.lumina.total += static_cast<size_t>(message.total);
        batch.lumina.skip += static_cast<size_t>(message.skip);
        batch.lumina.new_count += static_cast<size_t>(message.new_count);
        batch.lumina.exists += static_cast<size_t>(message.exists);
        batch.lumina.error += static_cast<size_t>(message.error);

        if (worker_ok) {
            batch.files_succeeded++;
        }
        else {
            batch.files_failed++;
        }

        running.erase(worker_it);
    }

    if (scheduling_failed) {
        batch.files_failed += files.size() - next_index;
        std::cerr << CLR(Red) << "[-] " << scheduling_error << CLR(Reset) << "\n";
    }

    std::cout << "\n";
    std::cout << CLR(Bold) << "Batch Results" << CLR(Reset) << "\n";
    std::cout << std::string(50, '-') << "\n";
    std::cout << "  Files total:     " << batch.files_total << "\n";
    std::cout << "  " << CLR(Green) << "Succeeded:    " << batch.files_succeeded << CLR(Reset) << "\n";
    if (batch.files_failed > 0) {
        std::cout << "  " << CLR(Red) << "Failed:       " << batch.files_failed << CLR(Reset) << "\n";
    }
    else {
        std::cout << "  Failed:       0\n";
    }
    std::cout << "  Total pushed:    " << batch.lumina.total << "\n";
    std::cout << "  " << CLR(Green) << "New:          " << batch.lumina.new_count << CLR(Reset) << "\n";
    std::cout << "  " << CLR(Cyan) << "Exists:       " << batch.lumina.exists << CLR(Reset) << "\n";
    std::cout << "  " << CLR(Dim) << "Skipped:      " << batch.lumina.skip << CLR(Reset) << "\n";
    if (batch.lumina.error > 0) {
        std::cout << "  " << CLR(Red) << "Errors:       " << batch.lumina.error << CLR(Reset) << "\n";
    }
    std::cout << std::string(50, '-') << "\n";

    return batch.files_failed == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
#endif

static void print_usage(const char* prog) {
    std::cout << CLR(Bold) << "IDA Pro Lumina Push Tool" << CLR(Reset) << "\n\n";
    std::cout << CLR(Cyan) << "Usage:" << CLR(Reset) << " " << prog << " [options] <input_path>\n\n";
    std::cout << CLR(Cyan) << "Description:" << CLR(Reset) << "\n";
    std::cout << "  Analyzes a binary and pushes all function metadata to the Lumina server.\n";
    std::cout << "  With --recursive, scans a directory tree and processes files in forked workers.\n\n";
    std::cout << CLR(Cyan) << "Options:" << CLR(Reset) << "\n";
    std::cout << "  -q, --quiet          Suppress IDA's verbose messages\n";
    std::cout << "  -r, --recursive      Recursively process all files under <input_path>\n";
    std::cout << "  -v, --verbose        Show extra debug output\n";
    std::cout << "  -j, --jobs <count>   Worker processes for --recursive (default: CPU count)\n";
    std::cout << "  --ext <ext>          Only process files with extension (repeatable, e.g. dll)\n";
    std::cout << "  --type <type>        Only process binary type: pe, elf, mach-o, unknown (repeatable)\n";
    std::cout << "  --require-debug      Only process files with debug info; PE also accepts an adjacent PDB\n";
    std::cout << "  --no-color           Disable colored output\n";
    std::cout << "  --no-plugins         Don't load user plugins (except Hex-Rays)\n";
    std::cout << "  --plugin <pattern>   Load plugins matching pattern (implies --no-plugins)\n";
    std::cout << "                       Can be specified multiple times\n";
    std::cout << "  -h, --help           Show this help\n";
    std::cout << "\n";
    std::cout << CLR(Cyan) << "Examples:" << CLR(Reset) << "\n";
    std::cout << "  " << prog << " program.exe         # Analyze and push to Lumina\n";
    std::cout << "  " << prog << " -q program.exe      # Quiet mode\n";
    std::cout << "  " << prog << " -r samples/         # Recursively push a folder\n";
    std::cout << "  " << prog << " -r -j 4 samples/    # Limit recursive mode to 4 workers\n";
    std::cout << "  " << prog << " -r --ext dll --ext exe --type pe samples/\n";
    std::cout << "  " << prog << " -r --type pe --require-debug samples/\n";
    std::cout << "\n";
    std::cout << CLR(Cyan) << "Note:" << CLR(Reset) << "\n";
    std::cout << "  Lumina credentials must be configured in IDA Pro settings.\n";
    std::cout << "  The tool uses IDA's existing Lumina configuration.\n";
#ifdef _WIN32
    std::cout << "  Recursive mode is unavailable on Windows because it requires fork().\n";
#endif
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
        else if (arg == "-r" || arg == "--recursive") {
            g_opts.recursive = true;
        }
        else if (arg == "-v" || arg == "--verbose") {
            g_opts.verbose = true;
        }
        else if (arg == "-j" || arg == "--jobs") {
            if (i + 1 >= argc) {
                std::cerr << "Error: --jobs requires a count argument\n";
                return false;
            }

            unsigned int jobs = 0;
            if (!parse_positive_uint(argv[++i], jobs)) {
                std::cerr << "Error: --jobs expects a positive integer\n";
                return false;
            }

            g_opts.jobs = jobs;
            g_opts.jobs_specified = true;
        }
        else if (arg == "--ext" || arg == "--extension") {
            if (i + 1 >= argc) {
                std::cerr << "Error: " << arg << " requires an extension argument\n";
                return false;
            }
            std::string extension = normalize_extension(argv[++i]);
            if (extension.empty()) {
                std::cerr << "Error: " << arg << " expects a non-empty extension\n";
                return false;
            }
            if (!vector_contains(g_opts.extensions, extension)) {
                g_opts.extensions.push_back(extension);
            }
        }
        else if (arg == "--type") {
            if (i + 1 >= argc) {
                std::cerr << "Error: --type requires a type argument\n";
                return false;
            }
            std::string file_type = normalize_file_type(argv[++i]);
            if (!valid_file_type_filter(file_type)) {
                std::cerr << "Error: --type expects one of: pe, elf, mach-o, unknown\n";
                return false;
            }
            if (!vector_contains(g_opts.file_types, file_type)) {
                g_opts.file_types.push_back(file_type);
            }
        }
        else if (arg == "--require-debug" || arg == "--with-debug" || arg == "--debug-info") {
            g_opts.require_debug = true;
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

    if (g_opts.jobs_specified && !g_opts.recursive) {
        std::cerr << "Error: --jobs requires --recursive\n";
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

    std::error_code input_ec;
    if (!g_opts.recursive && std::filesystem::is_directory(g_opts.input_file, input_ec) && !input_ec) {
        std::cerr << "Error: " << g_opts.input_file << " is a directory; use --recursive to process folders\n";
        return EXIT_FAILURE;
    }
    if (!g_opts.recursive && has_active_input_filters()) {
        std::string reason;
        if (!file_matches_filters(g_opts.input_file, &reason)) {
            std::cerr << "Error: " << g_opts.input_file << " does not match input filters";
            if (!reason.empty()) {
                std::cerr << ": " << reason;
            }
            std::cerr << "\n";
            return EXIT_FAILURE;
        }
    }

    try {
        if (g_opts.recursive) {
#ifdef _WIN32
            throw std::runtime_error("Recursive mode is not supported on Windows because ida_lumina uses fork() workers.");
#else
            return run_recursive_mode();
#endif
        }

        run_single_file(g_opts.input_file, true);
    }
    catch (const std::exception &e) {
        std::cerr << CLR(Red) << "[FATAL] " << CLR(Reset) << e.what() << std::endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
