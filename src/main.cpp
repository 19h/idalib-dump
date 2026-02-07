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
#include <new>
#include <filesystem>
#include <chrono>
#include <iomanip>

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
// Windows equivalents - use inline functions to avoid macro conflicts with std library
static inline int posix_dup(int fd) { return _dup(fd); }
static inline int posix_dup2(int fd1, int fd2) { return _dup2(fd1, fd2); }
static inline int posix_close(int fd) { return _close(fd); }
static inline int posix_open(const char* path, int flags) { return _open(path, flags); }
#define STDOUT_FILENO 1
#define STDERR_FILENO 2
#define O_WRONLY _O_WRONLY
#else
#include <sys/stat.h>
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
    std::string filter_pattern;      // Function name filter (regex)
    ea_t filter_address = BADADDR;   // Filter by specific address
    std::vector<std::string> function_list;  // Explicit list of functions (names or addresses)
    std::vector<std::string> plugin_patterns;  // Additional plugins to load in no-plugins mode
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
        }
        std::cerr << "\n";
    }

private:
    std::chrono::steady_clock::time_point m_start_time;
    long long m_last_update_ms = 0;
    size_t m_total = 0;

    bool should_show() const {
        // Show progress when outputting to file (progress goes to stderr)
        return !g_opts.output_file.empty();
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
        if (!g_opts.output_file.empty()) {
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
    Dl_info info;
    if (addr && dladdr(addr, &info) && info.dli_fname)
        return info.dli_fname;
    return {};
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

    Probe probes[] = {
        { "ida_dump",   (void*)&print_loaded_modules },
        { "libida",     (void*)dlsym(RTLD_DEFAULT, "qalloc") },
        { "libidalib",  (void*)dlsym(RTLD_DEFAULT, "init_library") },
    };

    for (size_t i = 0; i < sizeof(probes) / sizeof(probes[0]); i++) {
        const auto& p = probes[i];
        std::string path = resolve_module_path(p.addr);
        if (path.empty()) continue;
        std::string basename = path.substr(path.rfind('/') + 1);
        std::cout << "  " << CLR(Cyan) << basename << CLR(Reset)
                  << "\n    " << CLR(Dim) << path << CLR(Reset) << "\n";
    }

    // Scan for additional IDA modules (plugins, loaders) that can't be
    // probed via dlsym because they don't export well-known symbols.
    auto print_module = [](const std::string& path) {
        std::string basename = path.substr(path.rfind('/') + 1);
        std::cout << "  " << CLR(Cyan) << basename << CLR(Reset)
                  << "\n    " << CLR(Dim) << path << CLR(Reset) << "\n";
    };

    auto is_ida_plugin = [](const std::string& name) {
        // Skip Python bindings (_ida_*.so) — only match native plugins
        if (name.find("_ida_") == 0) return false;
        return name.find("hexrays") != std::string::npos
            || name.find("hexx64") != std::string::npos;
    };

#if defined(__APPLE__)
    {
        uint32_t count = _dyld_image_count();
        for (uint32_t i = 0; i < count; i++) {
            const char* path = _dyld_get_image_name(i);
            if (!path) continue;
            std::string p(path);
            std::string basename = p.substr(p.rfind('/') + 1);
            if (is_ida_plugin(basename))
                print_module(p);
        }
    }
#elif defined(__linux__)
    {
        struct PrintCtx { decltype(print_module)* fn; decltype(is_ida_plugin)* filter; };
        PrintCtx ctx = { &print_module, &is_ida_plugin };
        dl_iterate_phdr([](struct dl_phdr_info* info, size_t, void* data) -> int {
            auto* c = static_cast<PrintCtx*>(data);
            if (!info->dlpi_name || !info->dlpi_name[0]) return 0;
            std::string p(info->dlpi_name);
            std::string basename = p.substr(p.rfind('/') + 1);
            if ((*c->filter)(basename))
                (*c->fn)(p);
            return 0;
        }, &ctx);
    }
#endif

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

    static void list(func_t *pfn) {
        if (!pfn) return;

        qstring fname;
        get_func_name(&fname, pfn->start_ea);

        if (!matches_filter(fname.c_str(), pfn->start_ea)) return;

        // Get function flags
        std::string flags;
        if (pfn->flags & FUNC_NORET) flags += "noret ";
        if (pfn->flags & FUNC_LIB) flags += "lib ";
        if (pfn->flags & FUNC_THUNK) flags += "thunk ";
        if (pfn->flags & FUNC_LUMINA) flags += "lumina ";

        printf("  %-16s  %6zu  %-20s  %s\n",
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

        func_item_iterator_t fii;
        for (bool ok = fii.set(pfn); ok; ok = fii.next_code()) {
            ea_t ea = fii.current();
            qstring line;

            if (generate_disasm_line(&line, ea, GENDSM_REMOVE_TAGS | GENDSM_MULTI_LINE | GENDSM_FORCE_CODE)) {
                line.trim2();
                out << CLR(Dim) << format_address(ea) << CLR(Reset) << "  " << line.c_str() << "\n";
            }
        }
        out << "\n";
    }

    static void dump_microcode(cfunc_t *cfunc) {
        out << CLR(Yellow) << "-- Microcode " << CLR(Dim) << std::string(64, '-') << CLR(Reset) << "\n";

        if (mba_t *mba = cfunc->mba) {
            MicrocodePrinter printer(*g_output);
            mba->print(printer);
        } else {
            out << CLR(Dim) << "  (No microcode available)" << CLR(Reset) << "\n";
        }
        out << "\n";
    }

    static void dump_pseudocode(cfunc_t *cfunc) {
        out << CLR(Yellow) << "-- Pseudocode " << CLR(Dim) << std::string(63, '-') << CLR(Reset) << "\n";

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

        std::string formatted = format_pseudocode_block(pseudo_block);
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
};

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
                mkdir(fake_plugins.c_str(), 0755);  // Plugins dir with only hexrays

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
                std::string fake_user_plugins = fake_idausr + "/plugins";
                mkdir(fake_idausr.c_str(), 0755);
                mkdir(fake_user_plugins.c_str(), 0755);
                symlink((real_idausr + "/ida.reg").c_str(), (fake_idausr + "/ida.reg").c_str());

                // Symlink user plugins matching patterns
                std::string real_user_plugins = real_idausr + "/plugins";
                DIR* udir = opendir(real_user_plugins.c_str());
                if (udir) {
                    struct dirent* uentry;
                    while ((uentry = readdir(udir)) != NULL) {
                        // Check user-specified patterns (no hex* here - those are in IDADIR)
                        for (const auto& pattern : g_opts.plugin_patterns) {
                            if (strstr(uentry->d_name, pattern.c_str()) != nullptr) {
                                std::string src = real_user_plugins + "/" + uentry->d_name;
                                std::string dst = fake_user_plugins + "/" + uentry->d_name;
                                symlink(src.c_str(), dst.c_str());
                                break;
                            }
                        }
                    }
                    closedir(udir);
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
        if (g_hexrays_available) {
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

    HeadlessIdaContext(const HeadlessIdaContext&) = delete;
    HeadlessIdaContext& operator=(const HeadlessIdaContext&) = delete;

private:
    std::string m_fake_idadir_base;  // Path to clean up on destruction
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
    std::cout << "  -f, --filter <pattern>   Filter functions by name (regex)\n";
    std::cout << "  -F, --functions <list>   List of functions (comma or pipe separated)\n";
    std::cout << "  -a, --address <addr>     Show only function at address (hex)\n";
    std::cout << "  -e, --errors             Show only functions with decompilation errors\n";
    std::cout << "  -l, --list               List functions only (no decompilation)\n";
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
    std::cout << "  --no-plugins             Don't load user plugins (except Hex-Rays)\n";
    std::cout << "  --plugin <pattern>       Load plugins matching pattern (implies --no-plugins)\n";
    std::cout << "                           Can be specified multiple times\n";
     std::cout << "  -h, --help               Show this help\n";
    std::cout << "  --version                Show build info (SDK path, runtime lib path)\n";
    std::cout << "\n";
    std::cout << CLR(Cyan) << "Examples:" << CLR(Reset) << "\n";
    std::cout << "  " << prog << " program.exe                        # Dump all functions\n";
    std::cout << "  " << prog << " -f main program.exe                # Only 'main' function\n";
    std::cout << "  " << prog << " -F main,foo,bar program.exe        # Specific functions by name\n";
    std::cout << "  " << prog << " -o out.c --pseudo-only program.exe # Export to file with progress\n";
    std::cout << "  " << prog << " -e program.exe                     # Only show errors\n";
    std::cout << "  " << prog << " -l program.exe                     # List functions\n";
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
        else if (arg == "-e" || arg == "--errors") {
            g_opts.errors_only = true;
        }
        else if (arg == "-l" || arg == "--list") {
            g_opts.list_functions = true;
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

    // Set up output file if specified
    if (!g_opts.output_file.empty()) {
        g_output_file = std::make_unique<std::ofstream>(g_opts.output_file);
        if (!g_output_file->is_open()) {
            std::cerr << "Error: Cannot open output file: " << g_opts.output_file << "\n";
            return EXIT_FAILURE;
        }
        g_output = g_output_file.get();
        // Disable colors for file output
        Color::disable();
        // Auto-enable quiet mode and no-plugins for file output
        g_opts.quiet = true;
        g_opts.no_plugins = true;
    }

    // In file mode, suppress normal console output
    bool show_console_info = g_opts.output_file.empty() && !g_opts.quiet;

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

        // Count functions to process (for progress display)
        if (!g_opts.output_file.empty()) {
            size_t count = 0;
            for (size_t i = 0; i < g_stats.total_functions; ++i) {
                func_t *pfn = getn_func(i);
                if (pfn) {
                    qstring fname;
                    get_func_name(&fname, pfn->start_ea);
                    if (FunctionDumper::should_process(pfn, fname.c_str())) {
                        count++;
                    }
                }
            }
            g_stats.functions_to_process = count;
            g_progress.set_total(count);

            // Warn if no functions matched the filter
            if (count == 0 && (!g_opts.function_list.empty() || !g_opts.filter_pattern.empty() || g_opts.filter_address != BADADDR)) {
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
        }

        if (show_console_info) {
            std::cout << "[*] Processing " << g_stats.total_functions << " functions...\n";
        }

        if (g_opts.list_functions) {
            // List mode - just show function names
            printf("\n  %-16s  %6s  %-20s  %s\n", "Address", "Size", "Flags", "Name");
            printf("  %s  %s  %s  %s\n",
                   std::string(16, '-').c_str(),
                   std::string(6, '-').c_str(),
                   std::string(20, '-').c_str(),
                   std::string(30, '-').c_str());

            for (size_t i = 0; i < g_stats.total_functions; ++i) {
                func_t *pfn = getn_func(i);
                if (pfn) FunctionDumper::list(pfn);
            }
            std::cout << "\n";
        } else {
            // Normal mode - dump functions
            for (size_t i = 0; i < g_stats.total_functions; ++i) {
                func_t *pfn = getn_func(i);
                if (pfn) {
                    // Get function name for progress display
                    qstring fname;
                    get_func_name(&fname, pfn->start_ea);

                    FunctionDumper::dump(pfn);

                    // Update progress (only counts processed, not skipped)
                    if (!g_opts.output_file.empty()) {
                        g_stats.processed = g_stats.decompiled_ok + g_stats.decompiled_fail;
                        g_progress.update(g_stats.processed, fname.c_str());
                    }
                }
            }

            // Finish progress display
            if (!g_opts.output_file.empty()) {
                g_progress.finish();
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

    return g_stats.decompiled_fail > 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
