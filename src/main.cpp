/**
 * IDA Pro Binary Analysis Dumper
 *
 * A headless tool for dumping assembly, microcode, and pseudocode from binaries.
 * Useful for testing IDA plugins (especially the AVX lifter) and analyzing binaries.
 *
 * Features:
 *   - Dump assembly, microcode, and/or pseudocode
 *   - Filter functions by name pattern or address
 *   - Show only functions with decompilation errors
 *   - Quiet mode to suppress IDA's verbose output
 *   - Summary statistics
 */

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <memory>
#include <stdexcept>
#include <cctype>
#include <cstring>
#include <algorithm>
#include <regex>
#include <cstdlib>
#include <cstdarg>
#include <cstdio>
#include <new>
#include <filesystem>
#include <chrono>
#include <iomanip>
#include <thread>
#include <limits>
#include <unordered_map>

// Save real setenv/getenv and FILE* pointers before IDA SDK redefines them with macros
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

// Save real stdout/stderr and functions before IDA redefines them
static FILE* real_stdout = stdout;
static FILE* real_stderr = stderr;
static inline int real_fflush(FILE* stream) { return fflush(stream); }
static inline char* real_fgets(char* str, int count, FILE* stream) { return fgets(str, count, stream); }
static inline int real_fprintf(FILE* stream, const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    int ret = vfprintf(stream, fmt, args);
    va_end(args);
    return ret;
}

#ifdef _WIN32
#include <io.h>
#include <fcntl.h>
#include <process.h>
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <psapi.h>
// Windows equivalents - use inline functions to avoid macro conflicts with std library
static inline int posix_dup(int fd) { return _dup(fd); }
static inline int posix_dup2(int fd1, int fd2) { return _dup2(fd1, fd2); }
static inline int posix_close(int fd) { return _close(fd); }
static inline int posix_open(const char* path, int flags) { return _open(path, flags); }
static inline FILE* real_popen(const char* command, const char* mode) { return _popen(command, mode); }
static inline int real_pclose(FILE* stream) { return _pclose(stream); }
static inline int current_process_id() { return _getpid(); }
#define STDOUT_FILENO 1
#define STDERR_FILENO 2
#define O_WRONLY _O_WRONLY
#else
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <dirent.h>
#include <fcntl.h>
#include <dlfcn.h>
#ifdef __APPLE__
#include <mach-o/dyld.h>
#endif
#ifdef __linux__
#include <link.h>
#endif
// POSIX - just use the standard functions
static inline int posix_dup(int fd) { return dup(fd); }
static inline int posix_dup2(int fd1, int fd2) { return dup2(fd1, fd2); }
static inline int posix_close(int fd) { return close(fd); }
static inline int posix_open(const char* path, int flags) { return open(path, flags); }
static inline FILE* real_popen(const char* command, const char* mode) { return popen(command, mode); }
static inline int real_pclose(FILE* stream) { return pclose(stream); }
static inline int current_process_id() { return getpid(); }
#endif

// From noplugins.c - controls plugin blocking
extern "C" bool g_block_plugins;

extern "C" {
#include "highlight.h"
}

#include "astyle_main.h"

// IDA SDK Headers
#include <pro.h>
#include <ida.hpp>
#include <idp.hpp>
#include <auto.hpp>
#include <funcs.hpp>
#include <lines.hpp>
#include <name.hpp>
#include <loader.hpp>
#include <hexrays.hpp>
#include <idalib.hpp>
#include <segment.hpp>
#include <typeinf.hpp>
#include <nalt.hpp>
#include <dirtree.hpp>

//=============================================================================
// Global State
//=============================================================================

hexdsp_t *hexdsp = nullptr;
static bool g_hexrays_available = false;

//=============================================================================
// Command Line Options
//=============================================================================

struct Options {
    std::string input_file;
    std::string output_file;         // Output file (empty = stdout)
    std::string output_dir;          // Folder/file tree export root
    std::string filter_pattern;      // Function name filter (regex)
    std::string sybil_url;           // Hidden: embedding endpoint URL
    ea_t filter_address = BADADDR;   // Filter by specific address
    std::vector<std::string> function_list;  // Explicit list of functions (names or addresses)
    std::vector<std::string> plugin_patterns;  // Additional plugins to load in no-plugins mode
    size_t start_index = 0;          // First exporter-order function index to process
    size_t max_functions = std::numeric_limits<size_t>::max();  // Max functions to process
    bool show_assembly = true;
    bool show_microcode = false;
    bool show_pseudocode = true;
    bool format_pseudocode = true;
    bool errors_only = false;        // Only show functions with errors
    bool quiet = false;              // Suppress IDA messages
    bool show_summary = true;        // Show summary at end
    bool list_functions = false;     // Just list function names
    bool verbose = false;            // Show extra metadata
    bool no_plugins = false;         // Disable loading user plugins
    bool sybil_embeddings = false;   // Hidden: request embeddings instead of dumping
    bool start_index_set = false;    // User explicitly set --start-index/--offset
    bool resume = true;              // Resume file exports from a checkpoint when possible
    bool folder_files = false;       // Export IDA function folders as files/directories
};

static Options g_opts;

// Statistics
struct Stats {
    size_t total_functions = 0;
    size_t functions_to_process = 0;  // After filtering
    size_t processed = 0;             // Currently processed
    size_t decompiled_ok = 0;
    size_t decompiled_fail = 0;
    size_t skipped = 0;
    size_t output_bytes = 0;          // Bytes written to output
    std::vector<std::pair<std::string, std::string>> errors; // (func_name, error)
};

static Stats g_stats;

// Output stream (stdout or file)
static std::ostream* g_output = &std::cout;
static std::unique_ptr<std::ofstream> g_output_file;

//=============================================================================
// Progress Display
//=============================================================================

class ProgressDisplay {
public:
    ProgressDisplay() : m_start_time(std::chrono::steady_clock::now()) {}

    void set_total(size_t total) {
        m_total = total;
    }

    void update(size_t current, const std::string& func_name = "") {
        if (!should_show()) return;

        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - m_start_time).count();

        // Rate limit updates to avoid flicker (max 20 updates/sec)
        if (elapsed - m_last_update_ms < 50 && current < m_total) return;
        m_last_update_ms = elapsed;

        double progress = m_total > 0 ? (double)current / m_total : 0;
        double elapsed_sec = elapsed / 1000.0;
        double rate = elapsed_sec > 0 ? current / elapsed_sec : 0;

        // Estimate remaining time
        std::string eta_str = "---";
        if (rate > 0 && current < m_total) {
            double remaining = (m_total - current) / rate;
            eta_str = format_duration(remaining);
        }

        // Build progress bar
        const int bar_width = 30;
        int filled = (int)(progress * bar_width);
        std::string bar(filled, '\xe2'); // Will be replaced with proper chars

        // Use block characters for smooth progress
        std::string bar_filled(filled, '#');
        std::string bar_empty(bar_width - filled, '-');

        // Truncate function name
        std::string display_name = func_name;
        if (display_name.length() > 30) {
            display_name = display_name.substr(0, 27) + "...";
        }

        // Format output size
        std::string size_str = format_bytes(g_stats.output_bytes);

        // Clear line and print progress
        std::cerr << "\r\033[K";  // Clear line
        std::cerr << "\033[36m[\033[0m";  // Cyan bracket
        std::cerr << "\033[32m" << bar_filled << "\033[90m" << bar_empty << "\033[0m";  // Green filled, gray empty
        std::cerr << "\033[36m]\033[0m ";  // Cyan bracket

        // Percentage
        std::cerr << "\033[1m" << std::setw(5) << std::fixed << std::setprecision(1)
                  << (progress * 100) << "%\033[0m ";

        // Stats
        std::cerr << "\033[90m│\033[0m ";
        std::cerr << "\033[33m" << current << "\033[90m/\033[33m" << m_total << "\033[0m ";
        std::cerr << "\033[90m│\033[0m ";
        std::cerr << "\033[32m" << g_stats.decompiled_ok << "\033[90m ok \033[0m";
        if (g_stats.decompiled_fail > 0) {
            std::cerr << "\033[31m" << g_stats.decompiled_fail << "\033[90m err\033[0m ";
        }
        std::cerr << "\033[90m│\033[0m ";
        std::cerr << "\033[35m" << size_str << "\033[0m ";
        std::cerr << "\033[90m│\033[0m ";
        std::cerr << "\033[90mETA \033[36m" << eta_str << "\033[0m";

        // Current function (if space)
        if (!display_name.empty()) {
            std::cerr << " \033[90m" << display_name << "\033[0m";
        }

        std::cerr.flush();
    }

    void finish() {
        if (!should_show()) return;

        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - m_start_time).count();
        double elapsed_sec = elapsed / 1000.0;

        // Clear line
        std::cerr << "\r\033[K";

        // Final summary line
        std::cerr << "\033[32m✓\033[0m Completed \033[1m" << g_stats.decompiled_ok << "\033[0m functions";
        if (g_stats.decompiled_fail > 0) {
            std::cerr << " (\033[31m" << g_stats.decompiled_fail << " errors\033[0m)";
        }
        std::cerr << " in \033[36m" << format_duration(elapsed_sec) << "\033[0m";
        std::cerr << " \033[90m│\033[0m \033[35m" << format_bytes(g_stats.output_bytes) << "\033[0m";
        if (!g_opts.output_file.empty()) {
            std::cerr << " \033[90m→\033[0m \033[33m" << g_opts.output_file << "\033[0m";
        } else if (g_opts.folder_files) {
            std::cerr << " \033[90m→\033[0m \033[33m" << g_opts.output_dir << "\033[0m";
        }
        std::cerr << "\n";
    }

private:
    std::chrono::steady_clock::time_point m_start_time;
    long long m_last_update_ms = 0;
    size_t m_total = 0;

    bool should_show() const {
        // Show progress when outputting to file (progress goes to stderr)
        return !g_opts.output_file.empty() || g_opts.folder_files;
    }

    static std::string format_duration(double seconds) {
        if (seconds < 60) {
            std::ostringstream oss;
            oss << std::fixed << std::setprecision(1) << seconds << "s";
            return oss.str();
        }
        int mins = (int)(seconds / 60);
        int secs = (int)seconds % 60;
        std::ostringstream oss;
        oss << mins << "m" << secs << "s";
        return oss.str();
    }

    static std::string format_bytes(size_t bytes) {
        const char* units[] = {"B", "KB", "MB", "GB"};
        int unit = 0;
        double size = bytes;
        while (size >= 1024 && unit < 3) {
            size /= 1024;
            unit++;
        }
        std::ostringstream oss;
        if (unit == 0) {
            oss << bytes << " " << units[unit];
        } else {
            oss << std::fixed << std::setprecision(1) << size << " " << units[unit];
        }
        return oss.str();
    }
};

static ProgressDisplay g_progress;

//=============================================================================
// Output Helper
//=============================================================================

// Write to output stream and track bytes written
class OutputWriter {
public:
    template<typename T>
    OutputWriter& operator<<(const T& val) {
        if (!g_opts.output_file.empty() || g_opts.folder_files) {
            std::ostringstream oss;
            oss << val;
            std::string s = oss.str();
            g_stats.output_bytes += s.size();
            *g_output << s;
        } else {
            *g_output << val;
        }
        return *this;
    }

    // Handle manipulators like std::endl
    OutputWriter& operator<<(std::ostream& (*manip)(std::ostream&)) {
        if (!g_opts.output_file.empty()) {
            if (manip == static_cast<std::ostream& (*)(std::ostream&)>(std::endl)) {
                g_stats.output_bytes += 1;  // newline
            }
        }
        *g_output << manip;
        return *this;
    }
};

static OutputWriter out;

static bool open_output_file(std::ios::openmode mode = std::ios::trunc) {
    g_output_file = std::make_unique<std::ofstream>(
        g_opts.output_file, std::ios::out | std::ios::binary | mode);
    if (!g_output_file->is_open()) {
        std::cerr << "Error: Cannot open output file: " << g_opts.output_file << "\n";
        return false;
    }
    g_output = g_output_file.get();
    return true;
}

static bool open_output_path(const std::filesystem::path &path,
                             std::ios::openmode mode = std::ios::trunc) {
    std::error_code ec;
    std::filesystem::create_directories(path.parent_path(), ec);
    if (ec) {
        std::cerr << "Error: Cannot create output directory "
                  << path.parent_path().string() << ": " << ec.message() << "\n";
        return false;
    }

    g_output_file = std::make_unique<std::ofstream>(
        path, std::ios::out | std::ios::binary | mode);
    if (!g_output_file->is_open()) {
        std::cerr << "Error: Cannot open output file: " << path.string() << "\n";
        return false;
    }
    g_output = g_output_file.get();
    return true;
}

static void close_output_file() {
    if (g_output_file) {
        g_output_file->flush();
        g_output_file->close();
        g_output_file.reset();
    }
    g_output = &std::cout;
}

//=============================================================================
// ANSI Colors (for terminal output)
//=============================================================================

namespace Color {
    const char* Reset   = "\033[0m";
    const char* Bold    = "\033[1m";
    const char* Dim     = "\033[2m";
    const char* Red     = "\033[31m";
    const char* Green   = "\033[32m";
    const char* Yellow  = "\033[33m";
    const char* Blue    = "\033[34m";
    const char* Magenta = "\033[35m";
    const char* Cyan    = "\033[36m";
    const char* White   = "\033[37m";

    // Check if we should use colors
    bool enabled = true;

    void disable() { enabled = false; }

    const char* get(const char* color) {
        return enabled ? color : "";
    }
}

#define CLR(c) Color::get(Color::c)

//=============================================================================
// Utilities
//=============================================================================

static std::string format_address(ea_t ea) {
    qstring text;
    ea2str(&text, ea);
    return text.c_str();
}

static std::string format_size(uint64_t bytes) {
    if (bytes < 1024) return std::to_string(bytes) + " B";
    if (bytes < 1024 * 1024) return std::to_string(bytes / 1024) + " KB";
    return std::to_string(bytes / (1024 * 1024)) + " MB";
}

static bool is_spacer_line(const char *str) {
    while (*str && std::isspace((unsigned char)*str)) ++str;
    if (!std::isdigit((unsigned char)*str)) return false;
    while (std::isdigit((unsigned char)*str)) ++str;
    if (*str != '.') return false;
    ++str;
    if (!std::isspace((unsigned char)*str)) return false;
    while (*str && std::isspace((unsigned char)*str)) ++str;
    if (!std::isdigit((unsigned char)*str)) return false;
    while (std::isdigit((unsigned char)*str)) ++str;
    while (*str && std::isspace((unsigned char)*str)) ++str;
    return *str == '\0';
}

// Parse an address string (hex with or without 0x prefix)
// Only matches pure hex addresses like "0x1234" or "1234ABCD"
// Does NOT match function names like "sub_14007B090"
static ea_t parse_address(const std::string& str) {
    if (str.empty()) return BADADDR;

    const char* s = str.c_str();

    // Skip 0x prefix if present
    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
        s += 2;
    }
    // If it starts with "sub_" or similar prefix, it's a function name, not an address
    else if (strncmp(str.c_str(), "sub_", 4) == 0 ||
             strncmp(str.c_str(), "loc_", 4) == 0 ||
             strncmp(str.c_str(), "unk_", 4) == 0 ||
             strncmp(str.c_str(), "off_", 4) == 0 ||
             strncmp(str.c_str(), "byte_", 5) == 0 ||
             strncmp(str.c_str(), "word_", 5) == 0 ||
             strncmp(str.c_str(), "dword_", 6) == 0 ||
             strncmp(str.c_str(), "qword_", 6) == 0) {
        return BADADDR;  // This is a function/label name, not an address
    }

    // Check if all remaining chars are hex digits
    bool all_hex = true;
    for (const char* p = s; *p; ++p) {
        if (!std::isxdigit((unsigned char)*p)) {
            all_hex = false;
            break;
        }
    }

    if (all_hex && *s) {
        return strtoull(str.c_str(), nullptr, 16);
    }
    return BADADDR;
}

// Helper to get demangled name (returns empty string if demangling fails or name is not mangled)
static std::string get_demangled_name(const char* mangled_name) {
    if (!mangled_name || !*mangled_name) return "";

    qstring demangled;
    // Use 0 for disable_mask (show everything) and DQT_FULL for full demangling
    if (demangle_name(&demangled, mangled_name, 0, DQT_FULL) > 0) {
        return demangled.c_str();
    }
    return "";
}

// Check if a pattern matches a name (tries regex first, falls back to substring)
static bool pattern_matches_name(const std::string& pattern, const char* name) {
    if (!name || !*name) return false;

    try {
        std::regex re(pattern, std::regex::icase);
        if (std::regex_search(name, re)) return true;
    } catch (const std::regex_error&) {
        // Fall back to case-insensitive substring match
        std::string name_lower(name);
        std::string pattern_lower(pattern);
        std::transform(name_lower.begin(), name_lower.end(), name_lower.begin(), ::tolower);
        std::transform(pattern_lower.begin(), pattern_lower.end(), pattern_lower.begin(), ::tolower);
        if (name_lower.find(pattern_lower) != std::string::npos) return true;
    }
    return false;
}

static bool matches_filter(const char* func_name, ea_t func_addr) {
    // Address filter takes precedence
    if (g_opts.filter_address != BADADDR) {
        return func_addr == g_opts.filter_address;
    }

    // Get demangled name once (empty if not mangled or demangling fails)
    std::string demangled = get_demangled_name(func_name);

    // Explicit function list takes precedence over pattern
    if (!g_opts.function_list.empty()) {
        for (const auto& item : g_opts.function_list) {
            // Try as address first
            ea_t addr = parse_address(item);
            if (addr != BADADDR) {
                if (func_addr == addr) return true;
                // Also check if addr is within the function
                func_t* pfn = get_func(addr);
                if (pfn && pfn->start_ea == func_addr) return true;
                continue;
            }

            // Try as exact name match (raw name)
            if (item == func_name) return true;

            // Try as exact name match (demangled name)
            if (!demangled.empty() && item == demangled) return true;

            // Try case-insensitive match on raw name
            std::string name_lower(func_name);
            std::string item_lower(item);
            std::transform(name_lower.begin(), name_lower.end(), name_lower.begin(), ::tolower);
            std::transform(item_lower.begin(), item_lower.end(), item_lower.begin(), ::tolower);
            if (name_lower == item_lower) return true;

            // Try case-insensitive match on demangled name
            if (!demangled.empty()) {
                std::string demangled_lower(demangled);
                std::transform(demangled_lower.begin(), demangled_lower.end(), demangled_lower.begin(), ::tolower);
                if (demangled_lower == item_lower) return true;
            }
        }
        return false;
    }

    // Name pattern filter (regex) - match against both raw and demangled names
    if (!g_opts.filter_pattern.empty()) {
        // Try matching raw name first
        if (pattern_matches_name(g_opts.filter_pattern, func_name)) {
            return true;
        }

        // Try matching demangled name
        if (!demangled.empty() && pattern_matches_name(g_opts.filter_pattern, demangled.c_str())) {
            return true;
        }

        return false;
    }

    return true;
}

//=============================================================================
// Pseudocode Highlighting (Kat)
//=============================================================================

static bool g_highlighter_initialized = false;
static bool g_highlighter_available = false;

static bool ensure_highlighter() {
    if (!Color::enabled) return false;
    if (g_highlighter_initialized) return g_highlighter_available;

    g_highlighter_initialized = true;
    g_highlighter_available = (highlight_init(nullptr) == 0);
    return g_highlighter_available;
}

static void shutdown_highlighter() {
    if (!g_highlighter_initialized || !g_highlighter_available) return;
    highlight_finish();
    g_highlighter_available = false;
}

// Highlight a pseudocode line if possible, otherwise return the plain text.
static std::string format_pseudocode_line(const qstring &line) {
    if (!ensure_highlighter()) {
        return line.c_str();
    }

    char *buffer = highlight_alloc_line();
    if (!buffer) {
        return line.c_str();
    }

    char *highlighted = highlight_line(line.c_str(), buffer, line.length());
    char *to_free = highlighted ? highlighted : buffer;
    std::string out = highlighted ? highlighted : line.c_str();
    highlight_free(to_free);
    return out;
}

struct HighlighterGuard {
    ~HighlighterGuard() { shutdown_highlighter(); }
};

//=============================================================================
// Pseudocode Formatting (AStyle)
//=============================================================================

static bool g_astyle_initialized = false;
static bool g_astyle_available = false;

static void STDCALL astyle_error_handler(int error_number, const char *error_message) {
    std::cerr << CLR(Red) << "[AStyle] Error " << error_number << ": "
              << (error_message ? error_message : "(null)") << CLR(Reset) << "\n";
}

static char* STDCALL astyle_memory_alloc(unsigned long size) {
    return new (std::nothrow) char[size];
}

static bool ensure_astyle() {
    if (g_astyle_initialized) return g_astyle_available;
    g_astyle_initialized = true;
    // AStyleMain is available once headers are included; no runtime init needed.
    g_astyle_available = true;
    return g_astyle_available;
}

static std::string format_pseudocode_block(const std::string &input) {
    if (!g_opts.format_pseudocode) {
        return input;
    }
    if (!ensure_astyle()) {
        return input;
    }

    const char *options = "--style=google --indent=spaces=4 --pad-oper --align-pointer=name";

    char *formatted = AStyleMain(input.c_str(), options, astyle_error_handler, astyle_memory_alloc);
    if (!formatted) {
        g_astyle_available = false; // Disable formatting on repeated failures
        return input;
    }

    std::string output(formatted);
    delete[] formatted;
    return output;
}

//=============================================================================
// Output Handling
//=============================================================================

struct SybilFunctionInput {
    std::string name;
    std::string address;
    std::string pseudo;
    std::string mc;
    std::string asm_text;
};

class MicrocodePrinter : public vd_printer_t {
private:
    std::ostream &m_out;

public:
    explicit MicrocodePrinter(std::ostream &stream) : m_out(stream) {}

    AS_PRINTF(3, 4) int print(int indent, const char *format, ...) override {
        qstring line;
        if (indent > 0) line.fill(0, ' ', indent);

        va_list va;
        va_start(va, format);
        line.cat_vsprnt(format, va);
        va_end(va);

        tag_remove(&line);

        size_t len = line.length();
        while (len > 0 && std::isspace((unsigned char)line[len-1])) len--;
        line.resize(len);

        if (line.empty()) return 0;

        bool is_empty = true;
        for (size_t i = 0; i < len; ++i) {
            if (!std::isspace((unsigned char)line[i])) {
                is_empty = false;
                break;
            }
        }
        if (is_empty) return 0;
        if (is_spacer_line(line.c_str())) return 0;

        m_out << line.c_str() << std::endl;
        return static_cast<int>(line.length());
    }
};

// Null output stream for suppressing IDA messages
class NullBuffer : public std::streambuf {
public:
    int overflow(int c) override { return c; }
};

//=============================================================================
// Binary Information
//=============================================================================

static void print_binary_info() {
    std::cout << "\n";
    std::cout << CLR(Bold) << "Binary Information" << CLR(Reset) << "\n";
    std::cout << std::string(78, '-') << "\n";

    // File info
    char filepath[QMAXPATH];
    get_input_file_path(filepath, sizeof(filepath));
    std::cout << "  " << CLR(Cyan) << "File:      " << CLR(Reset) << filepath << "\n";

    // File format
    char fileformat[64];
    get_file_type_name(fileformat, sizeof(fileformat));
    std::cout << "  " << CLR(Cyan) << "Format:    " << CLR(Reset) << fileformat << "\n";

    // Processor
    qstring procname = inf_get_procname();
    std::cout << "  " << CLR(Cyan) << "Processor: " << CLR(Reset) << procname.c_str() << "\n";

    // Bitness
    const char* bits = inf_is_64bit() ? "64-bit" : (inf_is_32bit_exactly() ? "32-bit" : "16-bit");
    std::cout << "  " << CLR(Cyan) << "Bitness:   " << CLR(Reset) << bits << "\n";

    // Compiler
    compiler_info_t ci;
    inf_get_cc(&ci);
    const char* cc_name = "Unknown";
    switch (ci.id) {
        case COMP_MS:      cc_name = "Visual C++"; break;
        case COMP_BC:      cc_name = "Borland C++"; break;
        case COMP_WATCOM:  cc_name = "Watcom C++"; break;
        case COMP_GNU:     cc_name = "GNU C++"; break;
        case COMP_VISAGE:  cc_name = "Visual Age C++"; break;
        case COMP_BP:      cc_name = "Delphi"; break;
        default: break;
    }
    std::cout << "  " << CLR(Cyan) << "Compiler:  " << CLR(Reset) << cc_name << "\n";

    // Entry point
    ea_t entry = inf_get_start_ea();
    if (entry != BADADDR) {
        std::cout << "  " << CLR(Cyan) << "Entry:     " << CLR(Reset) << format_address(entry) << "\n";
    }

    // Segments summary
    int seg_count = get_segm_qty();
    uint64_t total_size = 0;
    for (int i = 0; i < seg_count; i++) {
        segment_t* seg = getnseg(i);
        if (seg) total_size += seg->size();
    }
    std::cout << "  " << CLR(Cyan) << "Segments:  " << CLR(Reset) << seg_count
              << " (" << format_size(total_size) << " total)" << "\n";

    // Functions
    std::cout << "  " << CLR(Cyan) << "Functions: " << CLR(Reset) << get_func_qty() << "\n";

    std::cout << "\n";
}

static void print_segments() {
    std::cout << CLR(Bold) << "Segments" << CLR(Reset) << "\n";
    std::cout << std::string(78, '-') << "\n";

    printf("  %-16s  %-16s  %10s  %-8s  %s\n", "Start", "End", "Size", "Perm", "Name");
    printf("  %s  %s  %s  %s  %s\n",
           std::string(16, '-').c_str(),
           std::string(16, '-').c_str(),
           std::string(10, '-').c_str(),
           std::string(8, '-').c_str(),
           std::string(20, '-').c_str());

    int seg_count = get_segm_qty();
    for (int i = 0; i < seg_count; i++) {
        segment_t* seg = getnseg(i);
        if (!seg) continue;

        qstring seg_name;
        get_segm_name(&seg_name, seg);

        char perms[5] = "----";
        if (seg->perm & SEGPERM_READ)  perms[0] = 'r';
        if (seg->perm & SEGPERM_WRITE) perms[1] = 'w';
        if (seg->perm & SEGPERM_EXEC)  perms[2] = 'x';

        printf("  %-16s  %-16s  %10s  %-8s  %s\n",
               format_address(seg->start_ea).c_str(),
               format_address(seg->end_ea).c_str(),
               format_size(seg->size()).c_str(),
               perms,
               seg_name.c_str());
    }
    std::cout << "\n";
}

// Resolve the shared library path that provides a given symbol address.
static std::string resolve_module_path(void* addr) {
    if (!addr) return {};
#ifdef _WIN32
    HMODULE hmod = nullptr;
    if (!GetModuleHandleExA(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
            GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            (LPCSTR)addr, &hmod))
        return {};
    char path[MAX_PATH];
    DWORD len = GetModuleFileNameA(hmod, path, sizeof(path));
    if (len == 0 || len >= sizeof(path)) return {};
    return std::string(path, len);
#else
    Dl_info info;
    if (dladdr(addr, &info) && info.dli_fname)
        return info.dli_fname;
    return {};
#endif
}

static void print_loaded_modules() {
    std::cout << CLR(Bold) << "Loaded Modules" << CLR(Reset) << "\n";
    std::cout << std::string(78, '-') << "\n";

    // Probe well-known symbols to find which libraries are actually providing them.
    // This is more reliable than _dyld_get_image_name() which can report paths
    // that differ from the rpath-resolved ones after IDA's init_library().
    struct Probe {
        const char* label;
        void*       addr;
    };

    auto lookup_sym = [](const char* name) -> void* {
#ifdef _WIN32
        // On Windows, try ida.dll and idalib.dll for IDA's exported symbols.
        for (const char* mod : {"ida.dll", "idalib.dll"}) {
            HMODULE h = GetModuleHandleA(mod);
            if (!h) continue;
            void* p = (void*)GetProcAddress(h, name);
            if (p) return p;
        }
        return nullptr;
#else
        return dlsym(RTLD_DEFAULT, name);
#endif
    };

    Probe probes[] = {
        { "ida_dump",   (void*)&print_loaded_modules },
        { "libida",     lookup_sym("qalloc") },
        { "libidalib",  lookup_sym("init_library") },
    };

    // Extract filename from path, handling both '/' and '\' separators.
    auto path_basename = [](const std::string& p) -> std::string {
        auto pos = p.find_last_of("/\\");
        return (pos == std::string::npos) ? p : p.substr(pos + 1);
    };

    for (size_t i = 0; i < sizeof(probes) / sizeof(probes[0]); i++) {
        const auto& p = probes[i];
        std::string path = resolve_module_path(p.addr);
        if (path.empty()) continue;
        std::string basename = path_basename(path);
        std::cout << "  " << CLR(Cyan) << basename << CLR(Reset)
                  << "\n    " << CLR(Dim) << path << CLR(Reset) << "\n";
    }

    // Scan loaded images for IDA plugins, decompilers, and processor modules.
    // We look for modules in plugins/, procs/, and loaders/ subdirectories,
    // filtering out test/sample plugins and Python bindings.
    // Check for a directory component using both separator styles.
    auto has_dir = [](const std::string& p, const char* dir) {
        std::string fwd = std::string("/") + dir + "/";
        std::string bwd = std::string("\\") + dir + "\\";
        return p.find(fwd) != std::string::npos ||
               p.find(bwd) != std::string::npos;
    };

    auto is_interesting = [&](const std::string& path) {
        // Must be in a plugins/, procs/, or loaders/ directory
        bool in_plugins = has_dir(path, "plugins");
        bool in_procs   = has_dir(path, "procs");
        bool in_loaders = has_dir(path, "loaders");
        if (!in_plugins && !in_procs && !in_loaders) return false;

        // Skip Python bindings
        std::string basename = path_basename(path);
        if (basename.find("_ida_") == 0) return false;

        if (in_plugins) {
            // Only show decompilers (hex*) and user plugins (~/.idapro/ or AppData)
            bool is_decompiler = basename.find("hex") == 0;
            bool is_user = has_dir(path, ".idapro");
            return is_decompiler || is_user;
        }

        // Show active processor module and loaders
        return true;
    };

    struct ModuleEntry {
        std::string path;
        std::string name;
    };
    std::vector<ModuleEntry> extra;

#if defined(__APPLE__)
    {
        uint32_t count = _dyld_image_count();
        for (uint32_t i = 0; i < count; i++) {
            const char* path = _dyld_get_image_name(i);
            if (!path) continue;
            std::string p(path);
            if (is_interesting(p))
                extra.push_back({p, path_basename(p)});
        }
    }
#elif defined(__linux__)
    dl_iterate_phdr([](struct dl_phdr_info* info, size_t, void* data) -> int {
        auto* vec = static_cast<std::vector<ModuleEntry>*>(data);
        if (!info->dlpi_name || !info->dlpi_name[0]) return 0;
        std::string p(info->dlpi_name);
        auto pos = p.find_last_of("/\\");
        std::string basename = (pos == std::string::npos) ? p : p.substr(pos + 1);
        // Apply same filter logic inline (can't capture lambdas)
        bool in_plugins = p.find("/plugins/") != std::string::npos;
        bool in_procs   = p.find("/procs/") != std::string::npos;
        bool in_loaders = p.find("/loaders/") != std::string::npos;
        if (!in_plugins && !in_procs && !in_loaders) return 0;
        if (basename.find("_ida_") == 0) return 0;
        if (in_plugins) {
            bool is_decompiler = basename.find("hex") == 0;
            bool is_user = p.find("/.idapro/") != std::string::npos;
            if (!is_decompiler && !is_user) return 0;
        }
        vec->push_back({p, basename});
        return 0;
    }, &extra);
#elif defined(_WIN32)
    {
        HANDLE proc = GetCurrentProcess();
        HMODULE hmods[1024];
        DWORD needed = 0;
        if (EnumProcessModules(proc, hmods, sizeof(hmods), &needed)) {
            DWORD count = needed / sizeof(HMODULE);
            for (DWORD i = 0; i < count; i++) {
                char path[MAX_PATH];
                if (!GetModuleFileNameA(hmods[i], path, sizeof(path))) continue;
                std::string p(path);
                if (is_interesting(p))
                    extra.push_back({p, path_basename(p)});
            }
        }
    }
#endif

    for (const auto& mod : extra) {
        std::cout << "  " << CLR(Cyan) << mod.name << CLR(Reset)
                  << "\n    " << CLR(Dim) << mod.path << CLR(Reset) << "\n";
    }

    std::cout << "\n";
}

//=============================================================================
// Function Dumping
//=============================================================================

class FunctionDumper {
public:
    // Check if function is in a special/extern segment that can't be decompiled
    static bool is_special_segment(func_t *pfn) {
        segment_t* seg = getseg(pfn->start_ea);
        if (!seg) return false;

        qstring seg_name;
        get_segm_name(&seg_name, seg);

        // Check for extern segment
        if (seg_name == "extern") return true;

        // Check segment type
        if (seg->type == SEG_XTRN) return true;

        return false;
    }

    // Check if function matches filter (without decompiling) - public for pre-counting
    static bool should_process(func_t *pfn, const char* fname) {
        // Check filter first - this is the key optimization
        if (!matches_filter(fname, pfn->start_ea)) {
            return false;
        }

        // Skip special segments entirely - they can't be decompiled
        if (is_special_segment(pfn)) {
            return false;
        }

        return true;
    }

    // Returns true if decompilation succeeded
    static bool dump(func_t *pfn) {
        if (!pfn) return false;

        qstring fname;
        get_func_name(&fname, pfn->start_ea);

        // Check filter BEFORE decompiling - critical for performance
        if (!should_process(pfn, fname.c_str())) {
            g_stats.skipped++;
            return true;
        }

        // If Hex-Rays is not available, just dump assembly
        if (!g_hexrays_available) {
            print_header(pfn, fname.c_str(), true);  // Always "success" for asm-only
            if (g_opts.show_assembly) {
                dump_assembly(pfn);
            }
            g_stats.decompiled_ok++;
            return true;
        }

        // Now decompile (only for functions that pass the filter)
        hexrays_failure_t hf;
        cfuncptr_t cfunc = decompile(pfn, &hf, DECOMP_WARNINGS);

        bool success = (cfunc != nullptr);

        // Check if this is a "special segments cannot be decompiled" error
        // These are expected and should not count as real errors
        std::string err_msg;
        if (!success) {
            err_msg = hf.desc().c_str();
            if (err_msg.find("special segment") != std::string::npos ||
                err_msg.find("call analysis failed") != std::string::npos) {
                // Skip these non-errors
                g_stats.skipped++;
                return true;
            }
        }

        // In errors_only mode, skip successful functions
        if (g_opts.errors_only && success) {
            g_stats.skipped++;
            return true;
        }

        // Print function header
        print_header(pfn, fname.c_str(), success);

        if (!success) {
            g_stats.decompiled_fail++;
            g_stats.errors.push_back({fname.c_str(), err_msg});

            out << CLR(Red) << "  [ERROR] " << CLR(Reset)
                << "Decompilation failed at " << format_address(hf.errea)
                << ": " << err_msg << "\n\n";

            // Still show assembly if requested
            if (g_opts.show_assembly) {
                dump_assembly(pfn);
            }
            return false;
        }

        g_stats.decompiled_ok++;

        if (g_opts.show_assembly) dump_assembly(pfn);
        if (g_opts.show_microcode) dump_microcode((cfunc_t*)cfunc);
        if (g_opts.show_pseudocode) dump_pseudocode((cfunc_t*)cfunc);

        return true;
    }

    static bool collect_sybil_input(func_t *pfn, SybilFunctionInput &item) {
        if (!pfn) return false;

        qstring fname;
        get_func_name(&fname, pfn->start_ea);

        if (!should_process(pfn, fname.c_str())) {
            g_stats.skipped++;
            return false;
        }

        if (g_opts.show_assembly) {
            item.asm_text = collect_assembly(pfn);
        }

        bool needs_decompiler = g_opts.show_microcode || g_opts.show_pseudocode;
        bool success = true;
        std::string err_msg;

        if (needs_decompiler) {
            if (!g_hexrays_available) {
                success = false;
                err_msg = "Hex-Rays decompiler is not available";
            } else {
                hexrays_failure_t hf;
                cfuncptr_t cfunc = decompile(pfn, &hf, DECOMP_WARNINGS);
                success = (cfunc != nullptr);

                if (!success) {
                    err_msg = hf.desc().c_str();
                    if (err_msg.find("special segment") != std::string::npos ||
                        err_msg.find("call analysis failed") != std::string::npos) {
                        g_stats.skipped++;
                        return false;
                    }
                } else {
                    if (g_opts.show_microcode) item.mc = collect_microcode((cfunc_t*)cfunc);
                    if (g_opts.show_pseudocode) item.pseudo = collect_pseudocode((cfunc_t*)cfunc);
                }
            }
        }

        if (!success) {
            g_stats.decompiled_fail++;
            g_stats.errors.push_back({fname.c_str(), err_msg});
            if (item.asm_text.empty()) {
                return false;
            }
        } else {
            g_stats.decompiled_ok++;
        }

        if (item.pseudo.empty() && item.mc.empty() && item.asm_text.empty()) {
            g_stats.skipped++;
            return false;
        }

        item.name = fname.c_str();
        item.address = format_address(pfn->start_ea);
        return true;
    }

    static void list(func_t *pfn, size_t index) {
        if (!pfn) return;

        qstring fname;
        get_func_name(&fname, pfn->start_ea);

        // Get function flags
        std::string flags;
        if (pfn->flags & FUNC_NORET) flags += "noret ";
        if (pfn->flags & FUNC_LIB) flags += "lib ";
        if (pfn->flags & FUNC_THUNK) flags += "thunk ";
        if (pfn->flags & FUNC_LUMINA) flags += "lumina ";

        printf("  %8zu  %-16s  %6zu  %-20s  %s\n",
               index,
               format_address(pfn->start_ea).c_str(),
               (size_t)(pfn->end_ea - pfn->start_ea),
               flags.c_str(),
               fname.c_str());
    }

private:
    static void print_header(func_t *pfn, const char* fname, bool success) {

        // Get segment name
        qstring seg_name;
        segment_t* seg = getseg(pfn->start_ea);
        if (seg) get_segm_name(&seg_name, seg);

        out << "\n";
        out << CLR(Bold) << std::string(78, '=') << CLR(Reset) << "\n";

        // Function name with status indicator
        const char* status_color = success ? CLR(Green) : CLR(Red);
        const char* status_icon = success ? "[OK]" : "[FAIL]";

        out << CLR(Bold) << "Function: " << CLR(Cyan) << fname << CLR(Reset);
        if (!seg_name.empty()) {
            out << " " << CLR(Dim) << "(" << seg_name.c_str() << ":"
                << format_address(pfn->start_ea) << ")" << CLR(Reset);
        }
        out << "  " << status_color << status_icon << CLR(Reset) << "\n";

        // Function metadata
        if (g_opts.verbose) {
            out << CLR(Dim);
            out << "  Size: " << (pfn->end_ea - pfn->start_ea) << " bytes";
            out << "  | Range: " << format_address(pfn->start_ea)
                << " - " << format_address(pfn->end_ea);

            // Flags
            std::vector<std::string> flag_names;
            if (pfn->flags & FUNC_NORET) flag_names.push_back("noreturn");
            if (pfn->flags & FUNC_LIB) flag_names.push_back("library");
            if (pfn->flags & FUNC_THUNK) flag_names.push_back("thunk");
            if (pfn->flags & FUNC_FRAME) flag_names.push_back("frame");

            if (!flag_names.empty()) {
                out << "  | Flags: ";
                for (size_t i = 0; i < flag_names.size(); i++) {
                    if (i > 0) out << ", ";
                    out << flag_names[i];
                }
            }
            out << CLR(Reset) << "\n";
        }

        out << std::string(78, '-') << "\n";
    }

    static void dump_assembly(func_t *pfn) {
        out << CLR(Yellow) << "-- Assembly " << CLR(Dim) << std::string(65, '-') << CLR(Reset) << "\n";
        out << collect_assembly(pfn);
        out << "\n";
    }

    static void dump_microcode(cfunc_t *cfunc) {
        out << CLR(Yellow) << "-- Microcode " << CLR(Dim) << std::string(64, '-') << CLR(Reset) << "\n";
        std::string microcode = collect_microcode(cfunc);
        if (!microcode.empty()) {
            out << microcode;
        } else {
            out << CLR(Dim) << "  (No microcode available)" << CLR(Reset) << "\n";
        }
        out << "\n";
    }

    static void dump_pseudocode(cfunc_t *cfunc) {
        out << CLR(Yellow) << "-- Pseudocode " << CLR(Dim) << std::string(63, '-') << CLR(Reset) << "\n";
        std::string formatted = collect_pseudocode(cfunc);
        std::istringstream stream(formatted);
        std::string line;
        while (std::getline(stream, line)) {
            if (!g_opts.output_file.empty()) {
                // No highlighting for file output
                out << line << "\n";
            } else {
                out << format_pseudocode_line(qstring(line.c_str())) << "\n";
            }
        }
        out << "\n";
    }

    static std::string collect_assembly(func_t *pfn) {
        std::ostringstream text;
        func_item_iterator_t fii;
        for (bool ok = fii.set(pfn); ok; ok = fii.next_code()) {
            ea_t ea = fii.current();
            qstring line;

            if (generate_disasm_line(&line, ea, GENDSM_REMOVE_TAGS | GENDSM_MULTI_LINE | GENDSM_FORCE_CODE)) {
                line.trim2();
                text << format_address(ea) << "  " << line.c_str() << "\n";
            }
        }
        return text.str();
    }

    static std::string collect_microcode(cfunc_t *cfunc) {
        if (!cfunc || !cfunc->mba) {
            return "";
        }
        std::ostringstream text;
        MicrocodePrinter printer(text);
        cfunc->mba->print(printer);
        return text.str();
    }

    static std::string collect_pseudocode(cfunc_t *cfunc) {
        const strvec_t &sv = cfunc->get_pseudocode();
        std::string pseudo_block;
        pseudo_block.reserve(1024);

        for (size_t i = 0; i < sv.size(); ++i) {
            qstring line;
            tag_remove(&line, sv[i].line);
            line.trim2();
            pseudo_block.append(line.c_str());
            pseudo_block.push_back('\n');
        }

        return format_pseudocode_block(pseudo_block);
    }
};

//=============================================================================
// Export Plan and Resume State
//=============================================================================

struct FunctionEntry {
    size_t index = 0;       // Index in the filtered exporter order
    func_t *pfn = nullptr;
    std::string name;
    ea_t start_ea = BADADDR;
    ea_t end_ea = BADADDR;
    std::string tree_path;             // IDA function dirtree path, when available
    std::filesystem::path output_path; // Directory export target, when available
};

struct FunctionRange {
    size_t begin = 0;       // Inclusive index into the export plan
    size_t end = 0;         // Exclusive index into the export plan

    size_t size() const {
        return end > begin ? end - begin : 0;
    }
};

struct ResumeState {
    bool valid = false;
    size_t next_index = 0;      // Next exporter-order index to process
    uintmax_t output_size = 0;  // Last complete output-file byte boundary
    std::filesystem::path output_path; // File that owns output_size in directory mode
};

static std::vector<std::string> split_tree_path(const std::string &path) {
    std::vector<std::string> parts;
    std::string part;
    for (char c : path) {
        if (c == '/' || c == '\\') {
            if (!part.empty()) {
                parts.push_back(part);
                part.clear();
            }
        } else {
            part.push_back(c);
        }
    }
    if (!part.empty()) parts.push_back(part);
    return parts;
}

static std::string to_lower_copy(std::string text) {
    std::transform(text.begin(), text.end(), text.begin(),
                   [](unsigned char c) { return (char)std::tolower(c); });
    return text;
}

static bool has_source_file_extension(const std::string &name) {
    static const char *exts[] = {
        ".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx",
        ".asm", ".s", ".inc", ".mc", ".txt"
    };
    std::string lower = to_lower_copy(name);
    for (const char *ext : exts) {
        size_t ext_len = strlen(ext);
        if (lower.size() >= ext_len &&
            lower.compare(lower.size() - ext_len, ext_len, ext) == 0) {
            return true;
        }
    }
    return false;
}

static std::string sanitize_path_component(const std::string &text,
                                           const std::string &fallback) {
    std::string out;
    out.reserve(text.size());
    for (unsigned char c : text) {
        if (std::isalnum(c) || c == '.' || c == '_' || c == '-' || c == '+') {
            out.push_back((char)c);
        } else if (std::isspace(c)) {
            out.push_back('_');
        } else {
            out.push_back('_');
        }
    }

    while (!out.empty() && (out.front() == '.' || out.front() == ' ')) out.erase(out.begin());
    while (!out.empty() && (out.back() == ' ')) out.pop_back();
    if (out.empty()) out = fallback;
    if (out == "." || out == "..") out = fallback;
    return out;
}

static std::string default_export_extension() {
    size_t selected = (g_opts.show_assembly ? 1 : 0) +
                      (g_opts.show_microcode ? 1 : 0) +
                      (g_opts.show_pseudocode ? 1 : 0);
    if (selected == 1) {
        if (g_opts.show_pseudocode) return ".c";
        if (g_opts.show_microcode) return ".mc";
        if (g_opts.show_assembly) return ".asm";
    }
    return ".txt";
}

static std::filesystem::path build_sanitized_relative_path(
        const std::vector<std::string> &parts,
        size_t begin,
        size_t end) {
    std::filesystem::path rel;
    for (size_t i = begin; i < end; ++i) {
        rel /= sanitize_path_component(parts[i], "folder");
    }
    return rel;
}

static std::filesystem::path unique_output_path(
        const std::filesystem::path &desired,
        std::unordered_map<std::string, std::filesystem::path> &key_to_path,
        std::unordered_map<std::string, size_t> &path_counts,
        const std::string &stable_key) {
    auto found = key_to_path.find(stable_key);
    if (found != key_to_path.end()) {
        return found->second;
    }

    std::filesystem::path chosen = desired;
    std::string normalized = chosen.lexically_normal().generic_string();
    size_t count = path_counts[normalized]++;
    if (count > 0) {
        std::filesystem::path parent = desired.parent_path();
        std::string stem = desired.stem().string();
        std::string ext = desired.extension().string();
        chosen = parent / (stem + "_" + std::to_string(count) + ext);
        normalized = chosen.lexically_normal().generic_string();
        while (path_counts.find(normalized) != path_counts.end()) {
            ++count;
            chosen = parent / (stem + "_" + std::to_string(count) + ext);
            normalized = chosen.lexically_normal().generic_string();
        }
        path_counts[normalized] = 1;
    }

    key_to_path[stable_key] = chosen;
    return chosen;
}

static std::filesystem::path fallback_function_output_path(
        const FunctionEntry &entry,
        const std::vector<std::string> &parts) {
    std::filesystem::path rel = build_sanitized_relative_path(parts, 0, parts.size());
    std::string fname = sanitize_path_component(entry.name, "function");
    std::string addr = sanitize_path_component(format_address(entry.start_ea), "addr");
    rel /= fname + "_" + addr + default_export_extension();
    return std::filesystem::path(g_opts.output_dir) / rel;
}

static std::filesystem::path folder_file_output_path(
        const FunctionEntry &entry,
        const std::string &abs_path,
        std::unordered_map<std::string, std::filesystem::path> &key_to_path,
        std::unordered_map<std::string, size_t> &path_counts) {
    std::vector<std::string> parts = split_tree_path(abs_path);
    if (!parts.empty()) parts.pop_back(); // Drop the function item name.

    for (size_t i = parts.size(); i > 0; --i) {
        if (!has_source_file_extension(parts[i - 1])) continue;

        std::filesystem::path rel = build_sanitized_relative_path(parts, 0, i - 1);
        rel /= sanitize_path_component(parts[i - 1], "source.txt");
        std::filesystem::path desired = std::filesystem::path(g_opts.output_dir) / rel;

        std::string stable_key;
        for (size_t j = 0; j < i; ++j) {
            stable_key += "/";
            stable_key += parts[j];
        }
        return unique_output_path(desired, key_to_path, path_counts, stable_key);
    }

    return fallback_function_output_path(entry, parts);
}

static std::vector<FunctionEntry> collect_export_plan() {
    std::vector<FunctionEntry> plan;
    plan.reserve(g_stats.total_functions);

    for (size_t i = 0; i < g_stats.total_functions; ++i) {
        func_t *pfn = getn_func(i);
        if (!pfn) continue;

        qstring fname;
        get_func_name(&fname, pfn->start_ea);
        if (!FunctionDumper::should_process(pfn, fname.c_str())) {
            continue;
        }

        FunctionEntry entry;
        entry.index = plan.size();
        entry.pfn = pfn;
        entry.name = fname.c_str();
        entry.start_ea = pfn->start_ea;
        entry.end_ea = pfn->end_ea;
        plan.push_back(std::move(entry));
    }

    return plan;
}

static std::vector<FunctionEntry> collect_folder_file_export_plan() {
    std::vector<FunctionEntry> plan;
    dirtree_t *dt = get_std_dirtree(DIRTREE_FUNCS);
    if (!dt || !dt->load()) {
        return plan;
    }

    std::unordered_map<std::string, std::filesystem::path> key_to_path;
    std::unordered_map<std::string, size_t> path_counts;

    struct Visitor : public dirtree_visitor_t {
        dirtree_t *dt = nullptr;
        std::vector<FunctionEntry> *plan = nullptr;
        std::unordered_map<std::string, std::filesystem::path> *key_to_path = nullptr;
        std::unordered_map<std::string, size_t> *path_counts = nullptr;

        ssize_t visit(const dirtree_cursor_t &cursor, const direntry_t &de) override {
            if (!dirtree_t::isfile(de)) return 0;

            ea_t ea = (ea_t)de.idx;
            func_t *pfn = get_func(ea);
            if (!pfn) return 0;

            qstring fname;
            get_func_name(&fname, pfn->start_ea);
            if (!FunctionDumper::should_process(pfn, fname.c_str())) {
                return 0;
            }

            qstring abs_path = dt->get_abspath(cursor, DTN_DISPLAY_NAME);

            FunctionEntry entry;
            entry.index = plan->size();
            entry.pfn = pfn;
            entry.name = fname.c_str();
            entry.start_ea = pfn->start_ea;
            entry.end_ea = pfn->end_ea;
            entry.tree_path = abs_path.c_str();
            entry.output_path = folder_file_output_path(
                entry, entry.tree_path, *key_to_path, *path_counts);
            plan->push_back(std::move(entry));
            return 0;
        }
    };

    Visitor visitor;
    visitor.dt = dt;
    visitor.plan = &plan;
    visitor.key_to_path = &key_to_path;
    visitor.path_counts = &path_counts;
    dt->traverse(visitor);

    return plan;
}

static std::vector<FunctionEntry> collect_active_export_plan() {
    if (g_opts.folder_files) {
        std::vector<FunctionEntry> plan = collect_folder_file_export_plan();
        if (!plan.empty()) {
            return plan;
        }
        std::cerr << "\033[33mWarning: Function folder tree is empty; "
                  << "falling back to flat function order.\033[0m\n";
        plan = collect_export_plan();
        std::vector<std::string> no_parts;
        for (auto &entry : plan) {
            entry.output_path = fallback_function_output_path(entry, no_parts);
        }
        return plan;
    }
    return collect_export_plan();
}

static FunctionRange selected_function_range(size_t plan_size) {
    FunctionRange range;
    range.begin = std::min(g_opts.start_index, plan_size);
    if (g_opts.max_functions == std::numeric_limits<size_t>::max()) {
        range.end = plan_size;
    } else {
        size_t available = plan_size - range.begin;
        range.end = range.begin + std::min(g_opts.max_functions, available);
    }
    return range;
}

static void hash_byte(uint64_t &hash, unsigned char value) {
    hash ^= value;
    hash *= 1099511628211ULL;
}

static void hash_text(uint64_t &hash, const std::string &text) {
    for (unsigned char c : text) {
        hash_byte(hash, c);
    }
    hash_byte(hash, 0xff);
}

static std::string export_plan_signature(const std::vector<FunctionEntry> &plan,
                                         const FunctionRange &range) {
    uint64_t hash = 1469598103934665603ULL;

    hash_text(hash, g_opts.input_file);
    hash_text(hash, g_opts.output_dir);
    hash_text(hash, g_opts.filter_pattern);
    for (const auto &item : g_opts.function_list) hash_text(hash, item);
    hash_text(hash, format_address(g_opts.filter_address));
    hash_text(hash, g_opts.show_assembly ? "asm" : "no-asm");
    hash_text(hash, g_opts.show_microcode ? "mc" : "no-mc");
    hash_text(hash, g_opts.show_pseudocode ? "pseudo" : "no-pseudo");
    hash_text(hash, g_opts.format_pseudocode ? "format" : "no-format");
    hash_text(hash, g_opts.errors_only ? "errors-only" : "all");
    hash_text(hash, g_opts.folder_files ? "folder-files" : "flat-file");
    hash_text(hash, std::to_string(g_opts.start_index));
    hash_text(hash, std::to_string(g_opts.max_functions));
    hash_text(hash, std::to_string(plan.size()));
    hash_text(hash, std::to_string(range.begin));
    hash_text(hash, std::to_string(range.end));

    for (size_t i = range.begin; i < range.end; ++i) {
        const auto &entry = plan[i];
        hash_text(hash, entry.name);
        hash_text(hash, format_address(entry.start_ea));
        hash_text(hash, format_address(entry.end_ea));
        hash_text(hash, entry.tree_path);
        hash_text(hash, entry.output_path.generic_string());
    }

    std::ostringstream oss;
    oss << std::hex << std::setw(16) << std::setfill('0') << hash;
    return oss.str();
}

static std::filesystem::path checkpoint_path_for_output() {
    return std::filesystem::path(g_opts.output_file + ".progress");
}

static std::filesystem::path checkpoint_path_for_output_dir() {
    return std::filesystem::path(g_opts.output_dir) / ".idalib-dump.progress";
}

static bool parse_size_value(const std::string &text, size_t &value) {
    try {
        size_t pos = 0;
        unsigned long long parsed = std::stoull(text, &pos, 10);
        if (pos != text.size()) return false;
        value = static_cast<size_t>(parsed);
        return parsed == static_cast<unsigned long long>(value);
    } catch (...) {
        return false;
    }
}

static bool parse_uintmax_value(const std::string &text, uintmax_t &value) {
    try {
        size_t pos = 0;
        unsigned long long parsed = std::stoull(text, &pos, 10);
        if (pos != text.size()) return false;
        value = static_cast<uintmax_t>(parsed);
        return parsed == static_cast<unsigned long long>(value);
    } catch (...) {
        return false;
    }
}

static ResumeState read_resume_state(const std::filesystem::path &path,
                                     const std::string &signature,
                                     const FunctionRange &range) {
    ResumeState state;
    std::ifstream file(path);
    if (!file) return state;

    std::string line;
    std::string checkpoint_signature;
    bool have_next_index = false;
    bool have_output_size = false;
    while (std::getline(file, line)) {
        size_t eq = line.find('=');
        if (eq == std::string::npos) continue;
        std::string key = line.substr(0, eq);
        std::string value = line.substr(eq + 1);
        if (key == "signature") {
            checkpoint_signature = value;
        } else if (key == "next_index") {
            have_next_index = parse_size_value(value, state.next_index);
        } else if (key == "output_size") {
            have_output_size = parse_uintmax_value(value, state.output_size);
        } else if (key == "output_path") {
            state.output_path = value;
        }
    }

    if (checkpoint_signature != signature) {
        return ResumeState{};
    }
    if (!have_next_index || !have_output_size) {
        return ResumeState{};
    }
    if (state.next_index < range.begin || state.next_index > range.end) {
        return ResumeState{};
    }
    if (state.output_size > static_cast<uintmax_t>(std::numeric_limits<size_t>::max())) {
        return ResumeState{};
    }

    std::error_code ec;
    std::filesystem::path size_path = state.output_path.empty()
        ? std::filesystem::path(g_opts.output_file)
        : state.output_path;
    uintmax_t actual_size = std::filesystem::file_size(size_path, ec);
    if (ec || actual_size < state.output_size) {
        return ResumeState{};
    }

    state.valid = true;
    return state;
}

static void write_resume_state(const std::filesystem::path &path,
                               const std::string &signature,
                               size_t next_index,
                               uintmax_t output_size,
                               const FunctionRange &range,
                               const std::filesystem::path &output_path = {}) {
    std::filesystem::path tmp_path = path;
    tmp_path += ".tmp";

    {
        std::ofstream file(tmp_path, std::ios::out | std::ios::trunc | std::ios::binary);
        if (!file) return;
        file << "version=1\n";
        file << "signature=" << signature << "\n";
        file << "next_index=" << next_index << "\n";
        file << "output_size=" << output_size << "\n";
        if (!output_path.empty()) {
            file << "output_path=" << output_path.lexically_normal().string() << "\n";
        }
        file << "range_begin=" << range.begin << "\n";
        file << "range_end=" << range.end << "\n";
    }

    std::error_code ec;
    std::filesystem::remove(path, ec);
    ec.clear();
    std::filesystem::rename(tmp_path, path, ec);
    if (ec) {
        std::filesystem::remove(tmp_path, ec);
    }
}

static uintmax_t current_output_size() {
    if (!g_output_file) return g_stats.output_bytes;
    auto pos = g_output_file->tellp();
    if (pos == std::ostream::pos_type(-1)) return g_stats.output_bytes;
    return static_cast<uintmax_t>(pos);
}

static bool dump_folder_file_plan(const std::vector<FunctionEntry> &plan,
                                  const FunctionRange &range) {
    std::error_code ec;
    std::filesystem::create_directories(g_opts.output_dir, ec);
    if (ec) {
        std::cerr << "Error: Cannot create output directory "
                  << g_opts.output_dir << ": " << ec.message() << "\n";
        return false;
    }

    size_t dump_begin = range.begin;
    std::filesystem::path checkpoint_path = checkpoint_path_for_output_dir();
    std::string checkpoint_signature = export_plan_signature(plan, range);
    bool checkpoint_enabled = g_opts.resume;
    bool resumed_from_checkpoint = false;
    std::filesystem::path resume_path;

    if (checkpoint_enabled) {
        ResumeState state = read_resume_state(checkpoint_path, checkpoint_signature, range);
        if (state.valid) {
            resumed_from_checkpoint = true;
            dump_begin = state.next_index;
            resume_path = state.output_path;

            if (dump_begin >= range.end) {
                std::cerr << "\r\033[KFolder export already complete; removing checkpoint "
                          << checkpoint_path.string() << "\n";
                std::filesystem::remove(checkpoint_path, ec);
                return true;
            }

            if (!resume_path.empty()) {
                std::filesystem::resize_file(resume_path, state.output_size, ec);
                if (ec) {
                    std::cerr << "Error: Cannot truncate output file for resume: "
                              << resume_path.string() << ": " << ec.message() << "\n";
                    return false;
                }
            }

            g_stats.processed = dump_begin - range.begin;
            std::cerr << "\r\033[KResuming folder export at function index "
                      << dump_begin << " (" << g_stats.processed << "/"
                      << range.size() << " complete)\n";
        }
    } else {
        std::filesystem::remove(checkpoint_path, ec);
    }

    bool append_from_explicit_offset = g_opts.start_index_set && range.begin > 0;
    if (append_from_explicit_offset && !resumed_from_checkpoint) {
        std::cerr << "\r\033[KAppending folder export from function index "
                  << range.begin << "\n";
    }

    std::unordered_map<std::string, bool> opened_paths;
    std::filesystem::path current_path;

    for (size_t i = dump_begin; i < range.end; ++i) {
        const FunctionEntry &entry = plan[i];
        if (entry.output_path.empty()) {
            std::cerr << "\nError: Missing output path for " << entry.name << "\n";
            return false;
        }

        if (!g_output_file || current_path != entry.output_path) {
            close_output_file();
            current_path = entry.output_path;

            std::string key = current_path.lexically_normal().generic_string();
            bool first_open = opened_paths.find(key) == opened_paths.end();
            std::ios::openmode mode = std::ios::app;

            if (resumed_from_checkpoint && i == dump_begin && current_path == resume_path) {
                mode = std::ios::app;
            } else if (append_from_explicit_offset) {
                mode = std::ios::app;
            } else if (first_open) {
                mode = std::ios::trunc;
            }

            if (!open_output_path(current_path, mode)) {
                return false;
            }
            opened_paths[key] = true;
        }

        FunctionDumper::dump(entry.pfn);

        g_output_file->flush();
        if (!*g_output_file) {
            std::cerr << "\nError: Failed to write output file: "
                      << current_path.string() << "\n";
            return false;
        }

        g_stats.processed = (i + 1) - range.begin;
        uintmax_t file_size = current_output_size();
        if (checkpoint_enabled) {
            write_resume_state(checkpoint_path, checkpoint_signature,
                               i + 1, file_size, range, current_path);
        }
        g_progress.update(g_stats.processed, entry.name);
    }

    close_output_file();
    g_progress.finish();
    std::filesystem::remove(checkpoint_path, ec);
    return true;
}

//=============================================================================
// Summary
//=============================================================================

static void print_summary() {
    std::cout << "\n";
    std::cout << CLR(Bold) << std::string(78, '=') << CLR(Reset) << "\n";
    std::cout << CLR(Bold) << "Summary" << CLR(Reset) << "\n";
    std::cout << std::string(78, '-') << "\n";

    std::cout << "  Total functions:    " << g_stats.total_functions << "\n";
    std::cout << "  " << CLR(Green) << "Decompiled OK:    " << CLR(Reset) << g_stats.decompiled_ok << "\n";

    if (g_stats.decompiled_fail > 0) {
        std::cout << "  " << CLR(Red) << "Decompilation failed: " << CLR(Reset) << g_stats.decompiled_fail << "\n";
    }

    if (g_stats.skipped > 0) {
        std::cout << "  " << CLR(Dim) << "Skipped (filtered):   " << CLR(Reset) << g_stats.skipped << "\n";
    }

    // Success rate
    size_t attempted = g_stats.decompiled_ok + g_stats.decompiled_fail;
    if (attempted > 0) {
        double rate = 100.0 * g_stats.decompiled_ok / attempted;
        const char* color = rate == 100.0 ? CLR(Green) : (rate >= 90.0 ? CLR(Yellow) : CLR(Red));
        printf("  %sSuccess rate:     %.1f%%%s\n", color, rate, CLR(Reset));
    }

    // List errors
    if (!g_stats.errors.empty()) {
        std::cout << "\n" << CLR(Red) << "Errors:" << CLR(Reset) << "\n";
        for (const auto& err : g_stats.errors) {
            std::cout << "  " << CLR(Cyan) << err.first << CLR(Reset)
                      << ": " << err.second << "\n";
        }
    }

    std::cout << std::string(78, '=') << "\n";
}

//=============================================================================
// Sybil Embedding Requests
//=============================================================================

static std::string json_escape(const std::string &text) {
    std::ostringstream out;
    for (unsigned char c : text) {
        switch (c) {
            case '"': out << "\\\""; break;
            case '\\': out << "\\\\"; break;
            case '\b': out << "\\b"; break;
            case '\f': out << "\\f"; break;
            case '\n': out << "\\n"; break;
            case '\r': out << "\\r"; break;
            case '\t': out << "\\t"; break;
            default:
                if (c < 0x20) {
                    out << "\\u" << std::hex << std::setw(4) << std::setfill('0') << (int)c
                        << std::dec << std::setfill(' ');
                } else {
                    out << c;
                }
                break;
        }
    }
    return out.str();
}

static bool ends_with(const std::string &text, const std::string &suffix) {
    return text.size() >= suffix.size() &&
           text.compare(text.size() - suffix.size(), suffix.size(), suffix) == 0;
}

static std::string normalize_sybil_auto_url(const std::string &url) {
    std::string normalized = url;
    while (!normalized.empty() && normalized.back() == '/') {
        normalized.pop_back();
    }

    if (ends_with(normalized, "/v1/embed")) {
        normalized.replace(normalized.size() - strlen("/v1/embed"), strlen("/v1/embed"), "/v1/auto");
    } else if (ends_with(normalized, "/embed")) {
        normalized.replace(normalized.size() - strlen("/embed"), strlen("/embed"), "/auto");
    } else if (ends_with(normalized, "/v1/auto") || ends_with(normalized, "/auto")) {
        return normalized;
    } else if (ends_with(normalized, "/v1")) {
        normalized += "/auto";
    } else {
        normalized += "/v1/auto";
    }

    return normalized;
}

static std::string shell_quote(const std::string &text) {
#ifdef _WIN32
    std::string quoted = "\"";
    for (char c : text) {
        if (c == '"' || c == '\\') quoted.push_back('\\');
        quoted.push_back(c);
    }
    quoted.push_back('"');
    return quoted;
#else
    std::string quoted = "'";
    for (char c : text) {
        if (c == '\'') quoted += "'\\''";
        else quoted.push_back(c);
    }
    quoted.push_back('\'');
    return quoted;
#endif
}

static std::string build_sybil_request_json(const std::vector<SybilFunctionInput> &items,
                                            size_t begin,
                                            size_t end) {
    std::ostringstream json;
    json << "{\"inputs\":[";
    for (size_t i = begin; i < end; ++i) {
        if (i > begin) json << ",";
        json << "{";
        bool wrote_field = false;
        if (!items[i].pseudo.empty()) {
            json << "\"pseudo\":\"" << json_escape(items[i].pseudo) << "\"";
            wrote_field = true;
        }
        if (!items[i].mc.empty()) {
            if (wrote_field) json << ",";
            json << "\"mc\":\"" << json_escape(items[i].mc) << "\"";
            wrote_field = true;
        }
        if (!items[i].asm_text.empty()) {
            if (wrote_field) json << ",";
            json << "\"asm\":\"" << json_escape(items[i].asm_text) << "\"";
        }
        json << "}";
    }
    json << "]}";
    return json.str();
}

static bool run_curl_post_json(const std::string &url,
                               const std::string &request_json,
                               std::string &response,
                               std::string &error) {
    std::filesystem::path tmp_path = std::filesystem::temp_directory_path() /
        ("idalib_sybil_" + std::to_string(current_process_id()) + "_" +
         std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()) + ".json");

    {
        std::ofstream request_file(tmp_path, std::ios::binary);
        if (!request_file) {
            error = "failed to create request file: " + tmp_path.string();
            return false;
        }
        request_file << request_json;
    }

    std::string command = "curl -sS --retry 3 --retry-all-errors --retry-delay 1 --max-time 180 "
        "-X POST -H " +
        shell_quote("Content-type: application/json") +
        " --data-binary @" + shell_quote(tmp_path.string()) +
        " " + shell_quote(url);

    FILE *pipe = real_popen(command.c_str(), "r");
    if (!pipe) {
        std::filesystem::remove(tmp_path);
        error = "failed to execute curl";
        return false;
    }

    char buffer[4096];
    while (real_fgets(buffer, sizeof(buffer), pipe)) {
        response.append(buffer);
    }

    int rc = real_pclose(pipe);
    std::filesystem::remove(tmp_path);

    if (rc != 0) {
#ifdef _WIN32
        error = "curl exited with status " + std::to_string(rc);
#else
        if (WIFEXITED(rc)) {
            error = "curl exited with status " + std::to_string(WEXITSTATUS(rc));
        } else if (WIFSIGNALED(rc)) {
            error = "curl terminated by signal " + std::to_string(WTERMSIG(rc));
        } else {
            error = "curl exited with status " + std::to_string(rc);
        }
#endif
        return false;
    }
    return true;
}

static size_t skip_json_ws(const std::string &text, size_t pos) {
    while (pos < text.size() && std::isspace((unsigned char)text[pos])) ++pos;
    return pos;
}

static bool find_balanced_json_array(const std::string &text,
                                     size_t open_pos,
                                     size_t &close_pos) {
    if (open_pos >= text.size() || text[open_pos] != '[') return false;

    int depth = 0;
    bool in_string = false;
    bool escaped = false;
    for (size_t i = open_pos; i < text.size(); ++i) {
        char c = text[i];
        if (in_string) {
            if (escaped) {
                escaped = false;
            } else if (c == '\\') {
                escaped = true;
            } else if (c == '"') {
                in_string = false;
            }
            continue;
        }

        if (c == '"') {
            in_string = true;
        } else if (c == '[') {
            ++depth;
        } else if (c == ']') {
            --depth;
            if (depth == 0) {
                close_pos = i;
                return true;
            }
        }
    }
    return false;
}

static bool is_numeric_json_array(const std::string &array_text) {
    bool has_digit = false;
    for (size_t i = 0; i < array_text.size(); ++i) {
        char c = array_text[i];
        unsigned char uc = (unsigned char)c;
        if (std::isdigit(uc)) {
            has_digit = true;
            continue;
        }
        if ((c == '[' && i == 0) || (c == ']' && i + 1 == array_text.size())) {
            continue;
        }
        if (std::isspace(uc) || c == ',' ||
            c == '-' || c == '+' || c == '.' || c == 'e' || c == 'E') {
            continue;
        }
        return false;
    }
    return has_digit;
}

static void collect_numeric_arrays(const std::string &text,
                                   size_t begin,
                                   size_t end,
                                   std::vector<std::string> &arrays) {
    bool in_string = false;
    bool escaped = false;
    for (size_t i = begin; i < end; ++i) {
        char c = text[i];
        if (in_string) {
            if (escaped) {
                escaped = false;
            } else if (c == '\\') {
                escaped = true;
            } else if (c == '"') {
                in_string = false;
            }
            continue;
        }

        if (c == '"') {
            in_string = true;
        } else if (c == '[') {
            size_t close_pos = 0;
            if (!find_balanced_json_array(text, i, close_pos)) return;
            std::string array_text = text.substr(i, close_pos - i + 1);
            if (is_numeric_json_array(array_text)) {
                arrays.push_back(array_text);
            } else {
                collect_numeric_arrays(text, i + 1, close_pos, arrays);
            }
            i = close_pos;
        }
    }
}

static std::vector<std::string> extract_embedding_arrays(const std::string &response) {
    std::vector<std::string> embeddings;

    for (const char *key : {"\"embedding\"", "\"embeddings\""}) {
        size_t pos = 0;
        while ((pos = response.find(key, pos)) != std::string::npos) {
            size_t colon = response.find(':', pos + strlen(key));
            if (colon == std::string::npos) break;
            size_t value = skip_json_ws(response, colon + 1);
            if (value >= response.size() || response[value] != '[') {
                pos = colon + 1;
                continue;
            }

            size_t close_pos = 0;
            if (!find_balanced_json_array(response, value, close_pos)) break;
            std::string array_text = response.substr(value, close_pos - value + 1);
            if (is_numeric_json_array(array_text)) {
                embeddings.push_back(array_text);
            } else {
                collect_numeric_arrays(response, value + 1, close_pos, embeddings);
            }
            pos = close_pos + 1;
        }
    }

    if (embeddings.empty()) {
        collect_numeric_arrays(response, 0, response.size(), embeddings);
    }

    return embeddings;
}

static std::string response_preview(const std::string &response) {
    constexpr size_t kMaxPreview = 2048;
    std::string preview = response.substr(0, std::min(response.size(), kMaxPreview));
    for (char &c : preview) {
        if (c == '\n' || c == '\r' || c == '\t') c = ' ';
    }
    if (response.size() > kMaxPreview) {
        preview += "...";
    }
    return preview;
}

static bool is_sybil_batch_token_error(const std::string &response) {
    return response.find("max-batch-estimated-tokens") != std::string::npos;
}

static bool is_sybil_batch_oom_error(const std::string &response) {
    return response.find("out of memory") != std::string::npos ||
           response.find("CUDA error") != std::string::npos ||
           response.find("cuDNN") != std::string::npos ||
           response.find("illegal memory access") != std::string::npos ||
           response.find("CUDNN_STATUS") != std::string::npos;
}

static bool is_sybil_transient_error(const std::string &response) {
    return response.find("error code: 502") != std::string::npos ||
           response.find("error code: 503") != std::string::npos ||
           response.find("error code: 504") != std::string::npos ||
           response.find("502 Bad Gateway") != std::string::npos ||
           response.find("503 Service Unavailable") != std::string::npos ||
           response.find("504 Gateway Timeout") != std::string::npos ||
           response.find("Bad Gateway") != std::string::npos ||
           response.find("Service Unavailable") != std::string::npos ||
           response.find("Gateway Timeout") != std::string::npos;
}

static bool is_sybil_error_response(const std::string &response) {
    return response.find("\"error\"") != std::string::npos;
}

static void write_sybil_export(const std::vector<SybilFunctionInput> &items,
                               const std::vector<std::string> &embeddings) {
    out << "[";
    for (size_t i = 0; i < items.size(); ++i) {
        if (i > 0) out << ",";
        out << "[\"" << json_escape(items[i].name) << "\","
            << "\"" << json_escape(items[i].address) << "\","
            << embeddings[i] << "]";
    }
    out << "]\n";
}

static bool request_sybil_embeddings(const std::vector<SybilFunctionInput> &items,
                                     std::vector<std::string> &embeddings) {
    constexpr size_t kInitialBatchItems = 8;
    constexpr size_t kMaxRetryAttempts = 8;
    std::string endpoint_url = normalize_sybil_auto_url(g_opts.sybil_url);
    size_t max_batch_items = kInitialBatchItems;
    size_t retry_attempts = 0;
    size_t batch_begin = 0;

    while (batch_begin < items.size()) {
        size_t batch_end = std::min(items.size(), batch_begin + max_batch_items);

        std::string response;
        std::string error;
        std::string request_json = build_sybil_request_json(items, batch_begin, batch_end);
        if (!g_opts.output_file.empty()) {
            std::cerr << "\r\033[KSybil request " << (batch_begin + 1)
                      << "-" << batch_end << "/" << items.size() << "..."
                      << std::flush;
        }
        if (!run_curl_post_json(endpoint_url, request_json, response, error)) {
            if (!g_opts.output_file.empty()) std::cerr << "\n";
            std::cerr << "Error: Sybil request failed: " << error << "\n";
            return false;
        }

        if (g_opts.output_file.empty()) {
            std::cout << response;
            if (!response.empty() && response.back() != '\n') std::cout << "\n";
        } else {
            std::vector<std::string> batch_embeddings = extract_embedding_arrays(response);
            if (batch_embeddings.size() != batch_end - batch_begin) {
                if ((is_sybil_batch_token_error(response) || is_sybil_batch_oom_error(response) ||
                     is_sybil_transient_error(response)) &&
                    batch_end - batch_begin > 1) {
                    max_batch_items = std::max<size_t>(1, (batch_end - batch_begin) / 2);
                    retry_attempts = 0;
                    continue;
                }
                if ((is_sybil_batch_oom_error(response) || is_sybil_transient_error(response)) &&
                    retry_attempts < kMaxRetryAttempts) {
                    ++retry_attempts;
                    if (is_sybil_transient_error(response)) {
                        std::this_thread::sleep_for(std::chrono::seconds(std::min<size_t>(retry_attempts, 5)));
                    }
                    continue;
                }
                if (is_sybil_transient_error(response)) {
                    std::cerr << "Error: Sybil transient server error";
                    if (batch_end - batch_begin == 1) {
                        std::cerr << " for " << items[batch_begin].name;
                    }
                    std::cerr << " after " << kMaxRetryAttempts << " retries: "
                              << response_preview(response) << "\n";
                    return false;
                }
                if (is_sybil_error_response(response)) {
                    std::cerr << "Error: Sybil server error: " << response_preview(response) << "\n";
                    return false;
                }
                std::cerr << "Error: Sybil response contained " << batch_embeddings.size()
                          << " embeddings for " << (batch_end - batch_begin) << " inputs\n";
                std::cerr << "Response preview: " << response_preview(response) << "\n";
                return false;
            }
            embeddings.insert(embeddings.end(), batch_embeddings.begin(), batch_embeddings.end());
        }

        retry_attempts = 0;
        batch_begin = batch_end;
    }

    return true;
}

//=============================================================================
// Resource Management
//=============================================================================

// RAII helper for redirecting stdout/stderr to /dev/null (or NUL on Windows)
class StdioRedirector {
public:
    StdioRedirector(bool redirect) : m_active(redirect), m_saved_stdout(-1), m_saved_stderr(-1) {
        if (!redirect) return;
        real_fflush(real_stdout);
        real_fflush(real_stderr);
        m_saved_stdout = posix_dup(STDOUT_FILENO);
        m_saved_stderr = posix_dup(STDERR_FILENO);
#ifdef _WIN32
        int devnull = posix_open("NUL", O_WRONLY);
#else
        int devnull = posix_open("/dev/null", O_WRONLY);
#endif
        if (devnull >= 0) {
            posix_dup2(devnull, STDOUT_FILENO);
            posix_dup2(devnull, STDERR_FILENO);
            posix_close(devnull);
        }
    }

    ~StdioRedirector() {
        restore();
    }

    void restore() {
        if (!m_active) return;
        if (m_saved_stdout >= 0) {
            real_fflush(real_stdout);
            posix_dup2(m_saved_stdout, STDOUT_FILENO);
            posix_close(m_saved_stdout);
            m_saved_stdout = -1;
        }
        if (m_saved_stderr >= 0) {
            real_fflush(real_stderr);
            posix_dup2(m_saved_stderr, STDERR_FILENO);
            posix_close(m_saved_stderr);
            m_saved_stderr = -1;
        }
        m_active = false;
    }

private:
    bool m_active;
    int m_saved_stdout;
    int m_saved_stderr;
};

class HeadlessIdaContext {
public:
    HeadlessIdaContext(const char *input_file) {
        // In quiet mode, suppress stdout during IDA initialization
        // Use RAII to ensure restoration even on exceptions
        StdioRedirector redirector(g_opts.quiet);

        // Disable plugins by creating a fake IDADIR with empty plugins folder
        if (g_opts.no_plugins) {
#ifndef _WIN32
            const char* idadir_env = real_getenv("IDADIR");
            const char* home = real_getenv("HOME");

            // If IDADIR isn't set, derive it from libida.dylib's location
            // (which is resolved via rpath at load time)
            std::string detected_idadir;
            if (!idadir_env) {
                void* libida_sym = dlsym(RTLD_DEFAULT, "qalloc");
                Dl_info dli;
                if (libida_sym && dladdr(libida_sym, &dli) && dli.dli_fname) {
                    std::string libida_path(dli.dli_fname);
                    auto slash = libida_path.rfind('/');
                    if (slash != std::string::npos)
                        detected_idadir = libida_path.substr(0, slash);
                }
            }

            const char* idadir = idadir_env ? idadir_env : (detected_idadir.empty() ? nullptr : detected_idadir.c_str());

            if (idadir && home) {
                std::string real_idadir = idadir;
                m_fake_idadir_base = "/tmp/.ida_no_plugins_" + std::to_string(getpid());
                std::string fake_idadir = m_fake_idadir_base + "/ida";
                std::string fake_plugins = fake_idadir + "/plugins";

                // Create fake IDA directory structure that keeps all Hex-Rays
                // system plugins (from IDADIR/plugins/) but blocks user plugins
                // (from IDAUSR/plugins/) unless they match --plugin patterns.
                mkdir(m_fake_idadir_base.c_str(), 0755);
                mkdir(fake_idadir.c_str(), 0755);

                // Symlink everything from IDADIR as-is (including plugins/)
                // All plugins in IDADIR are Hex-Rays system plugins and should load.
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

                // Redirect IDAUSR: symlink everything (procs, loaders, cfg,
                // sig, til, ids, ida.reg, etc.) except plugins/, which we
                // replace with a controlled directory.
                std::string real_idausr = std::string(home) + "/.idapro";
                std::string fake_idausr = m_fake_idadir_base + "/user";
                mkdir(fake_idausr.c_str(), 0755);

                // For procs/ and loaders/, only symlink user modules that
                // don't exist in IDADIR (so the SDK tree's versions take
                // priority over user-installed copies).
                auto symlink_user_dir_unique = [&](const char* subdir) {
                    std::string user_dir = real_idausr + "/" + subdir;
                    std::string fake_dir = fake_idausr + "/" + subdir;
                    std::string sys_dir  = real_idadir + "/" + subdir;
                    mkdir(fake_dir.c_str(), 0755);
                    DIR* d = opendir(user_dir.c_str());
                    if (!d) return;
                    struct dirent* e;
                    while ((e = readdir(d)) != NULL) {
                        if (e->d_name[0] == '.') continue;
                        // Skip if IDADIR already has this module
                        std::string sys_path = sys_dir + "/" + e->d_name;
                        struct stat st;
                        if (stat(sys_path.c_str(), &st) == 0) continue;
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

                // Symlink user procs/loaders that don't shadow IDADIR ones
                symlink_user_dir_unique("procs");
                symlink_user_dir_unique("loaders");

                // Create controlled plugins dir with only --plugin matches
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

        if (init_hexrays_plugin()) {
            g_hexrays_available = true;
        } else {
            g_hexrays_available = false;
            // Disable pseudocode and microcode since they require Hex-Rays
            bool had_decompiler_features = g_opts.show_pseudocode || g_opts.show_microcode;
            g_opts.show_pseudocode = false;
            g_opts.show_microcode = false;
            if (!g_opts.quiet && had_decompiler_features) {
                std::cerr << "\033[33m[WARNING]\033[0m Hex-Rays decompiler not available. "
                          << "Pseudocode and microcode output disabled.\n";
            }
            // Ensure assembly is shown if nothing else would be
            if (!g_opts.show_assembly) {
                g_opts.show_assembly = true;
                if (!g_opts.quiet) {
                    std::cerr << "\033[90m[INFO]\033[0m Falling back to assembly-only output.\n";
                }
            }
        }

        // Explicitly restore before leaving constructor (RAII destructor would also do it)
        redirector.restore();
    }

    ~HeadlessIdaContext() {
        shutdown();
    }

    void shutdown() {
        if (m_shutdown) return;
        m_shutdown = true;

        if (g_hexrays_available) {
            term_hexrays_plugin();
            g_hexrays_available = false;
        }
        set_database_flag(DBFL_KILL);
        term_database();

        // Clean up fake IDADIR if we created one
        if (!m_fake_idadir_base.empty()) {
            std::error_code ec;
            std::filesystem::remove_all(m_fake_idadir_base, ec);
        }
    }

    HeadlessIdaContext(const HeadlessIdaContext&) = delete;
    HeadlessIdaContext& operator=(const HeadlessIdaContext&) = delete;

private:
    std::string m_fake_idadir_base;  // Path to clean up on destruction
    bool m_shutdown = false;
};

//=============================================================================
// Usage
//=============================================================================

// Split a string by multiple delimiters (comma or pipe)
static std::vector<std::string> split_string(const std::string& str) {
    std::vector<std::string> result;
    std::string item;

    for (char c : str) {
        if (c == ',' || c == '|') {
            // Trim whitespace
            size_t start = item.find_first_not_of(" \t");
            size_t end = item.find_last_not_of(" \t");
            if (start != std::string::npos) {
                result.push_back(item.substr(start, end - start + 1));
            }
            item.clear();
        } else {
            item += c;
        }
    }

    // Don't forget the last item
    size_t start = item.find_first_not_of(" \t");
    size_t end = item.find_last_not_of(" \t");
    if (start != std::string::npos) {
        result.push_back(item.substr(start, end - start + 1));
    }

    return result;
}

static void print_usage(const char* prog) {
    std::cout << CLR(Bold) << "IDA Pro Binary Analysis Dumper" << CLR(Reset) << "\n\n";
    std::cout << CLR(Cyan) << "Usage:" << CLR(Reset) << " " << prog << " [options] <binary_file>\n\n";
    std::cout << CLR(Cyan) << "Options:" << CLR(Reset) << "\n";
    std::cout << "  -o, --output <file>      Write output to file (shows progress on stderr)\n";
    std::cout << "  -O, --output-dir <dir>   Export function folder tree into files under dir\n";
    std::cout << "  --folder-files           Treat source-like function folders as aggregate files\n";
    std::cout << "  -f, --filter <pattern>   Filter functions by name (regex)\n";
    std::cout << "  -F, --functions <list>   List of functions (comma or pipe separated)\n";
    std::cout << "  -a, --address <addr>     Show only function at address (hex)\n";
    std::cout << "  -e, --errors             Show only functions with decompilation errors\n";
    std::cout << "  -l, --list               List exporter-order indexes (no decompilation)\n";
    std::cout << "  --start-index <n>        Start at exporter-order index n; appends with -o/-O\n";
    std::cout << "  --offset <n>             Alias for --start-index\n";
    std::cout << "  --count <n>              Process at most n functions from the start index\n";
    std::cout << "  --limit <n>              Alias for --count\n";
    std::cout << "  -q, --quiet              Suppress IDA's verbose messages\n";
    std::cout << "  -v, --verbose            Show extra metadata for each function\n";
    std::cout << "  --asm                    Show assembly\n";
    std::cout << "  --mc                     Show microcode\n";
    std::cout << "  --pseudo                 Show pseudocode\n";
    std::cout << "  --no-asm                 Don't show assembly\n";
    std::cout << "  --no-mc                  Don't show microcode\n";
    std::cout << "  --no-pseudo              Don't show pseudocode\n";
    std::cout << "  --no-format-pseudo       Disable C-style formatting for pseudocode\n";
    std::cout << "  --asm-only               Show only assembly\n";
    std::cout << "  --mc-only                Show only microcode\n";
    std::cout << "  --pseudo-only            Show only pseudocode\n";
    std::cout << "  --no-color               Disable colored output\n";
    std::cout << "  --no-summary             Don't show summary at end\n";
    std::cout << "  --no-resume              Disable checkpoint resume for file exports\n";
    std::cout << "  --no-plugins             Don't load user plugins (keeps IDA built-in plugins)\n";
    std::cout << "  --plugin <pattern>       Also load user plugins matching pattern (comma-separated)\n";
    std::cout << "                           Implies --no-plugins. Can be specified multiple times\n";
     std::cout << "  -h, --help               Show this help\n";
    std::cout << "  --version                Show build info (SDK path, runtime lib path)\n";
    std::cout << "\n";
    std::cout << CLR(Cyan) << "Examples:" << CLR(Reset) << "\n";
    std::cout << "  " << prog << " program.exe                        # Dump all functions\n";
    std::cout << "  " << prog << " -f main program.exe                # Only 'main' function\n";
    std::cout << "  " << prog << " -F main,foo,bar program.exe        # Specific functions by name\n";
    std::cout << "  " << prog << " -o out.c --pseudo-only program.exe # Export to file with progress\n";
    std::cout << "  " << prog << " -O dump --folder-files --pseudo-only program.exe\n";
    std::cout << "  " << prog << " -l program.exe                     # List exporter-order indexes\n";
    std::cout << "  " << prog << " -o out.c --start-index 100 --count 50 program.exe\n";
    std::cout << "  " << prog << " -e program.exe                     # Only show errors\n";
    std::cout << "\n";
}

static bool parse_args(int argc, char* argv[]) {
    bool asm_selected = false;
    bool mc_selected = false;
    bool pseudo_selected = false;

    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];

        if (arg == "-h" || arg == "--help") {
            print_usage(argv[0]);
            exit(0);
        }
        else if (arg == "--version") {
            std::cout << "ida_dump (idalib-dump)\n";
#ifdef BUILD_IDASDK_DIR
            std::cout << "  SDK:     " << BUILD_IDASDK_DIR << "\n";
#endif
#ifdef BUILD_IDA_LIBDIR
            if (strlen(BUILD_IDA_LIBDIR) > 0)
                std::cout << "  libdir:  " << BUILD_IDA_LIBDIR << "\n";
#endif
#ifdef BUILD_TYPE
            std::cout << "  build:   " << BUILD_TYPE << "\n";
#endif
            exit(0);
        }
        else if (arg == "-o" || arg == "--output") {
            if (i + 1 >= argc) {
                std::cerr << "Error: --output requires a filename\n";
                return false;
            }
            g_opts.output_file = argv[++i];
        }
        else if (arg == "-O" || arg == "--output-dir") {
            if (i + 1 >= argc) {
                std::cerr << "Error: --output-dir requires a directory\n";
                return false;
            }
            g_opts.output_dir = argv[++i];
            g_opts.folder_files = true;
        }
        else if (arg == "--folder-files") {
            g_opts.folder_files = true;
        }
        else if (arg == "-f" || arg == "--filter") {
            if (i + 1 >= argc) {
                std::cerr << "Error: --filter requires an argument\n";
                return false;
            }
            g_opts.filter_pattern = argv[++i];
        }
        else if (arg == "-a" || arg == "--address") {
            if (i + 1 >= argc) {
                std::cerr << "Error: --address requires an argument\n";
                return false;
            }
            g_opts.filter_address = strtoull(argv[++i], nullptr, 16);
        }
        else if (arg == "-F" || arg == "--functions") {
            if (i + 1 >= argc) {
                std::cerr << "Error: --functions requires an argument\n";
                return false;
            }
            g_opts.function_list = split_string(argv[++i]);
        }
        else if (arg == "--sybil") {
            if (i + 1 >= argc) {
                std::cerr << "Error: --sybil requires an endpoint URL\n";
                return false;
            }
            g_opts.sybil_url = argv[++i];
            g_opts.sybil_embeddings = true;
        }
        else if (arg == "-e" || arg == "--errors") {
            g_opts.errors_only = true;
        }
        else if (arg == "-l" || arg == "--list") {
            g_opts.list_functions = true;
        }
        else if (arg == "--start-index" || arg == "--offset") {
            if (i + 1 >= argc) {
                std::cerr << "Error: " << arg << " requires a non-negative integer\n";
                return false;
            }
            size_t value = 0;
            if (!parse_size_value(argv[++i], value)) {
                std::cerr << "Error: " << arg << " requires a non-negative integer\n";
                return false;
            }
            g_opts.start_index = value;
            g_opts.start_index_set = true;
        }
        else if (arg == "--count" || arg == "--limit") {
            if (i + 1 >= argc) {
                std::cerr << "Error: " << arg << " requires a non-negative integer\n";
                return false;
            }
            size_t value = 0;
            if (!parse_size_value(argv[++i], value)) {
                std::cerr << "Error: " << arg << " requires a non-negative integer\n";
                return false;
            }
            g_opts.max_functions = value;
        }
        else if (arg == "-q" || arg == "--quiet") {
            g_opts.quiet = true;
        }
        else if (arg == "-v" || arg == "--verbose") {
            g_opts.verbose = true;
        }
        else if (arg == "--asm") {
            asm_selected = true;
        }
        else if (arg == "--mc") {
            mc_selected = true;
        }
        else if (arg == "--pseudo") {
            pseudo_selected = true;
        }
        else if (arg == "--no-asm") {
            g_opts.show_assembly = false;
        }
        else if (arg == "--no-mc") {
            g_opts.show_microcode = false;
        }
        else if (arg == "--no-pseudo") {
            g_opts.show_pseudocode = false;
        }
        else if (arg == "--no-format-pseudo") {
            g_opts.format_pseudocode = false;
        }
        else if (arg == "--asm-only") {
            g_opts.show_assembly = true;
            g_opts.show_microcode = false;
            g_opts.show_pseudocode = false;
        }
        else if (arg == "--mc-only") {
            g_opts.show_assembly = false;
            g_opts.show_microcode = true;
            g_opts.show_pseudocode = false;
        }
        else if (arg == "--pseudo-only") {
            g_opts.show_assembly = false;
            g_opts.show_microcode = false;
            g_opts.show_pseudocode = true;
        }
        else if (arg == "--no-color") {
            Color::disable();
        }
        else if (arg == "--no-summary") {
            g_opts.show_summary = false;
        }
        else if (arg == "--no-resume") {
            g_opts.resume = false;
        }
        else if (arg == "--no-plugins") {
            g_opts.no_plugins = true;
        }
        else if (arg == "--plugin") {
            if (i + 1 >= argc) {
                std::cerr << "Error: --plugin requires a pattern argument\n";
                return false;
            }
            auto patterns = split_string(argv[++i]);
            g_opts.plugin_patterns.insert(g_opts.plugin_patterns.end(), patterns.begin(), patterns.end());
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

    if (g_opts.sybil_embeddings && g_opts.list_functions) {
        std::cerr << "Error: --sybil cannot be combined with --list\n";
        return false;
    }
    if (g_opts.folder_files && g_opts.output_dir.empty()) {
        std::cerr << "Error: --folder-files requires --output-dir <dir>\n";
        return false;
    }
    if (g_opts.folder_files && !g_opts.output_file.empty()) {
        std::cerr << "Error: --output cannot be combined with --output-dir/--folder-files\n";
        return false;
    }
    if (g_opts.folder_files && g_opts.sybil_embeddings) {
        std::cerr << "Error: --sybil cannot be combined with --folder-files\n";
        return false;
    }

    // If user explicitly selected any outputs, show only those selections.
    if (asm_selected || mc_selected || pseudo_selected) {
        g_opts.show_assembly = asm_selected;
        g_opts.show_microcode = mc_selected;
        g_opts.show_pseudocode = pseudo_selected;
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

    // File output is opened after the export plan is known, so checkpoint resume
    // can validate the same function order before truncating or appending.
    if (!g_opts.output_file.empty()) {
        // Disable colors for file output
        Color::disable();
        // Auto-enable quiet mode and no-plugins for file output
        g_opts.quiet = true;
        g_opts.no_plugins = true;
    }
    if (g_opts.folder_files) {
        Color::disable();
        g_opts.quiet = true;
        g_opts.no_plugins = true;
    }

    if (g_opts.sybil_embeddings) {
        Color::disable();
        g_opts.quiet = true;
        g_opts.no_plugins = true;
    }

    // In file mode, suppress normal console output
    bool show_console_info = g_opts.output_file.empty() && !g_opts.folder_files &&
                             !g_opts.quiet && !g_opts.sybil_embeddings;
    bool sybil_completed = false;

    HighlighterGuard highlighter_guard;

    try {
        HeadlessIdaContext ctx(g_opts.input_file.c_str());

        // Print binary info unless in quiet/raw/file mode
        if (show_console_info) {
            print_binary_info();
            if (g_opts.verbose) {
                print_segments();
                print_loaded_modules();
            }
        }

        g_stats.total_functions = get_func_qty();
        std::vector<FunctionEntry> export_plan = collect_active_export_plan();
        FunctionRange function_range = selected_function_range(export_plan.size());
        g_stats.functions_to_process = function_range.size();
        g_progress.set_total(g_stats.functions_to_process);

        // Warn if no functions matched the filter
        if (export_plan.empty() &&
            (!g_opts.function_list.empty() || !g_opts.filter_pattern.empty() || g_opts.filter_address != BADADDR)) {
            std::cerr << "\033[33mWarning: No functions matched the filter.\033[0m\n";
            if (!g_opts.function_list.empty()) {
                std::cerr << "\033[90mSearched for: ";
                for (size_t i = 0; i < g_opts.function_list.size() && i < 5; ++i) {
                    if (i > 0) std::cerr << ", ";
                    std::cerr << g_opts.function_list[i];
                }
                if (g_opts.function_list.size() > 5) {
                    std::cerr << " (+" << (g_opts.function_list.size() - 5) << " more)";
                }
                std::cerr << "\033[0m\n";
            }
        }

        if (show_console_info) {
            std::cout << "[*] Processing " << g_stats.functions_to_process
                      << " of " << export_plan.size() << " matching functions...\n";
        }

        if (g_opts.sybil_embeddings) {
            std::vector<SybilFunctionInput> sybil_inputs;
            sybil_inputs.reserve(function_range.size());

            for (size_t i = function_range.begin; i < function_range.end; ++i) {
                const FunctionEntry &entry = export_plan[i];

                SybilFunctionInput item;
                bool collected = FunctionDumper::collect_sybil_input(entry.pfn, item);
                if (collected) {
                    sybil_inputs.push_back(std::move(item));
                }

                if (!g_opts.output_file.empty()) {
                    g_stats.processed = (i + 1) - function_range.begin;
                    g_progress.update(g_stats.processed, entry.name);
                }
            }

            if (sybil_inputs.empty()) {
                std::cerr << "Error: No functions available for Sybil embedding request\n";
                return EXIT_FAILURE;
            }

            if (!g_opts.output_file.empty()) {
                std::cerr << "\r\033[KCollected " << sybil_inputs.size()
                          << " functions; requesting Sybil embeddings...\n";
            }

            std::vector<std::string> embeddings;
            if (!request_sybil_embeddings(sybil_inputs, embeddings)) {
                return EXIT_FAILURE;
            }

            if (!g_opts.output_file.empty()) {
                if (!open_output_file()) {
                    return EXIT_FAILURE;
                }
                write_sybil_export(sybil_inputs, embeddings);
                g_output_file->flush();
                if (!*g_output_file) {
                    std::cerr << "Error: Failed to write output file: "
                              << g_opts.output_file << "\n";
                    return EXIT_FAILURE;
                }
                g_progress.finish();
            }
            sybil_completed = true;
            std::cout.flush();
            std::cerr.flush();
            if (g_output_file) {
                g_output_file->close();
                g_output_file.reset();
            }
            real_fflush(real_stdout);
            real_fflush(real_stderr);
            _exit(0);
        } else if (g_opts.list_functions) {
            // List mode - show the exact filtered order used by the exporter.
            printf("\n  %8s  %-16s  %6s  %-20s  %s\n", "Index", "Address", "Size", "Flags", "Name");
            printf("  %s  %s  %s  %s  %s\n",
                   std::string(8, '-').c_str(),
                   std::string(16, '-').c_str(),
                   std::string(6, '-').c_str(),
                   std::string(20, '-').c_str(),
                   std::string(30, '-').c_str());

            for (size_t i = function_range.begin; i < function_range.end; ++i) {
                FunctionDumper::list(export_plan[i].pfn, export_plan[i].index);
            }
            std::cout << "\n";
        } else if (g_opts.folder_files) {
            if (!dump_folder_file_plan(export_plan, function_range)) {
                return EXIT_FAILURE;
            }
        } else {
            size_t dump_begin = function_range.begin;
            std::filesystem::path checkpoint_path;
            std::string checkpoint_signature;
            bool checkpoint_enabled = !g_opts.output_file.empty() && g_opts.resume;

            if (!g_opts.output_file.empty()) {
                bool append_from_explicit_offset = g_opts.start_index_set && function_range.begin > 0;
                std::ios::openmode output_mode =
                    append_from_explicit_offset ? std::ios::app : std::ios::trunc;
                checkpoint_path = checkpoint_path_for_output();
                checkpoint_signature = export_plan_signature(export_plan, function_range);
                bool resumed_from_checkpoint = false;

                if (checkpoint_enabled) {
                    ResumeState state = read_resume_state(
                        checkpoint_path, checkpoint_signature, function_range);
                    if (state.valid) {
                        resumed_from_checkpoint = true;
                        dump_begin = state.next_index;
                        g_stats.output_bytes = static_cast<size_t>(state.output_size);

                        if (dump_begin >= function_range.end) {
                            std::cerr << "\r\033[KExport already complete; removing checkpoint "
                                      << checkpoint_path.string() << "\n";
                            std::error_code ec;
                            std::filesystem::remove(checkpoint_path, ec);
                            return EXIT_SUCCESS;
                        }

                        std::error_code ec;
                        std::filesystem::resize_file(g_opts.output_file, state.output_size, ec);
                        if (ec) {
                            std::cerr << "Error: Cannot truncate output file for resume: "
                                      << ec.message() << "\n";
                            return EXIT_FAILURE;
                        }
                        output_mode = std::ios::app;
                        g_stats.processed = dump_begin - function_range.begin;
                        std::cerr << "\r\033[KResuming " << g_opts.output_file
                                  << " at function index " << dump_begin
                                  << " (" << g_stats.processed << "/"
                                  << function_range.size() << " complete)\n";
                    }
                } else {
                    std::error_code ec;
                    std::filesystem::remove(checkpoint_path, ec);
                }

                if (append_from_explicit_offset && !resumed_from_checkpoint) {
                    std::error_code ec;
                    uintmax_t output_size = std::filesystem::file_size(g_opts.output_file, ec);
                    if (!ec && output_size <= static_cast<uintmax_t>(std::numeric_limits<size_t>::max())) {
                        g_stats.output_bytes = static_cast<size_t>(output_size);
                    }
                    std::cerr << "\r\033[KAppending " << g_opts.output_file
                              << " from function index " << function_range.begin << "\n";
                }

                if (!open_output_file(output_mode)) {
                    return EXIT_FAILURE;
                }
            }

            // Normal mode - dump functions
            for (size_t i = dump_begin; i < function_range.end; ++i) {
                const FunctionEntry &entry = export_plan[i];

                FunctionDumper::dump(entry.pfn);

                if (!g_opts.output_file.empty()) {
                    g_output_file->flush();
                    if (!*g_output_file) {
                        std::cerr << "\nError: Failed to write output file: "
                                  << g_opts.output_file << "\n";
                        return EXIT_FAILURE;
                    }

                    g_stats.processed = (i + 1) - function_range.begin;
                    uintmax_t file_size = current_output_size();
                    if (checkpoint_enabled) {
                        write_resume_state(checkpoint_path, checkpoint_signature,
                                           i + 1, file_size, function_range);
                    }
                    g_progress.update(g_stats.processed, entry.name);
                }
            }

            // Finish progress display
            if (!g_opts.output_file.empty()) {
                g_progress.finish();
                std::error_code ec;
                std::filesystem::remove(checkpoint_path, ec);
            }
        }

        if (g_opts.show_summary && !g_opts.list_functions && show_console_info) {
            print_summary();
        }

        if (show_console_info) {
            std::cout << "[*] Done.\n";
        }
    }
    catch (const std::exception &e) {
        // Force output to real stderr in case it's still redirected
        real_fprintf(real_stderr, "\033[31m[FATAL]\033[0m %s\n", e.what());
        real_fflush(real_stderr);
        return EXIT_FAILURE;
    }

    // Close output file
    if (g_output_file) {
        g_output_file->close();
    }

    if (g_opts.sybil_embeddings && sybil_completed) {
        std::cout.flush();
        std::cerr.flush();
        real_fflush(real_stdout);
        real_fflush(real_stderr);
        _exit(0);
    }

    return g_stats.decompiled_fail > 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
