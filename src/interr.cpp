/**
 * IDA Pro Internal-Error (INTERR) Hunter
 *
 * A headless tool that decompiles every function in a binary and reports the
 * ones that trip a Hex-Rays internal error (INTERR). For each offender it also
 * dumps the raw generated microcode, which is exactly what you want when
 * debugging a buggy microcode lifter/plugin (e.g. an AVX lifter).
 *
 * Modes (modelled on ida_lumina):
 *   - Single file: analyze one binary in-process.
 *   - Recursive (-r): walk a directory tree and process each file in its own
 *     forked worker, so a hard crash or interr in one binary can't take the
 *     whole batch down.
 *
 * An INTERR can surface two ways and both are captured:
 *   - a soft failure with hexrays_failure_t::code == MERR_INTERR, or
 *   - a hard interr() which by default aborts the process. set_interr_throws()
 *     turns that into a catchable interr_exc_t so the scan can keep going.
 */

#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <stdexcept>
#include <cctype>
#include <cstring>
#include <algorithm>
#include <cerrno>
#include <cstdlib>
#include <cstdint>
#include <cstdarg>
#include <csignal>
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
#include <lines.hpp>
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
    std::string output_file;   // INTERR report destination (empty = stderr)
    bool quiet = false;
    bool no_plugins = false;
    bool recursive = false;
    unsigned int jobs = 0;
    bool jobs_specified = false;
    std::vector<std::string> extensions;
    std::vector<std::string> file_types;
    std::vector<std::string> plugin_patterns;  // Additional plugins to load in no-plugins mode
};

static Options g_opts;

// Detailed INTERR report sink (stderr by default, or the -o file). Per-file
// status lines and the batch summary go to stdout instead.
static std::ostream* g_report = &std::cerr;
static std::ofstream g_report_file;

//=============================================================================
// ANSI Colors (used only for stdout status/summary, never the plain report)
//=============================================================================

namespace Color {
    const char* Reset   = "\033[0m";
    const char* Bold    = "\033[1m";
    const char* Dim     = "\033[2m";
    const char* Red     = "\033[31m";
    const char* Green   = "\033[32m";
    const char* Yellow  = "\033[33m";
    const char* Cyan    = "\033[36m";

    bool enabled = true;
    void disable() { enabled = false; }
    const char* get(const char* c) { return enabled ? c : ""; }
}

#define CLR(c) Color::get(Color::c)

//=============================================================================
// Interrupt-safe database cleanup
//
// IDA unpacks a binary into loose working files (<input>.id0/.id1/.id2/.nam/
// .til). Normal teardown removes them, but a worker that is killed by a signal
// (a true lifter crash, Ctrl+C, ...) skips that teardown and orphans the files
// next to the input. Register them up front and unlink them from a signal
// handler using only async-signal-safe calls.
//=============================================================================

static char* g_db_cleanup_paths[16];
static volatile sig_atomic_t g_db_cleanup_count = 0;

static inline int posix_unlink(const char* path) {
#ifdef _WIN32
    return _unlink(path);
#else
    return unlink(path);
#endif
}

extern "C" void db_cleanup_signal_handler(int sig) {
    int count = g_db_cleanup_count;
    for (int i = 0; i < count; ++i) {
        if (g_db_cleanup_paths[i]) posix_unlink(g_db_cleanup_paths[i]);
    }
#ifndef _WIN32
    // For a real crash (a buggy lifter, an abort()), restore the default
    // disposition and re-raise so the crash is preserved: a core dump is
    // produced and the parent's waitpid sees WIFSIGNALED with the true signal,
    // rather than a clean exit that hides what happened. Interrupt signals
    // (Ctrl+C / TERM / HUP) are a clean shutdown, so just exit.
    if (sig != SIGINT && sig != SIGTERM && sig != SIGHUP) {
        signal(sig, SIG_DFL);
        raise(sig);
    }
#endif
    _exit(128 + sig);
}

static void install_db_cleanup_handler(const std::string& input_file) {
    static const char* const kExts[] = {
        ".id0", ".id1", ".id2", ".nam", ".til"
    };
    int n = 0;
    for (const char* ext : kExts) {
        if (n >= static_cast<int>(sizeof(g_db_cleanup_paths) / sizeof(g_db_cleanup_paths[0]))) break;
        std::string path = input_file + ext;
        g_db_cleanup_paths[n++] = strdup(path.c_str());
    }
    g_db_cleanup_count = n;

    // Both interruption and the crash signals a buggy lifter is likely to
    // raise, so the loose database files never leak next to the input.
    signal(SIGINT, db_cleanup_signal_handler);
    signal(SIGTERM, db_cleanup_signal_handler);
#ifndef _WIN32
    signal(SIGHUP, db_cleanup_signal_handler);
    signal(SIGSEGV, db_cleanup_signal_handler);
    signal(SIGABRT, db_cleanup_signal_handler);
    signal(SIGILL, db_cleanup_signal_handler);
    signal(SIGBUS, db_cleanup_signal_handler);
    signal(SIGFPE, db_cleanup_signal_handler);
#endif
}

//=============================================================================
// Microcode printer (renders an mba to plain text, tags stripped)
//=============================================================================

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
        if (is_spacer_line(line.c_str())) return 0;

        m_out << "    " << line.c_str() << "\n";
        return static_cast<int>(line.length());
    }
};

//=============================================================================
// Resource Management (IDA headless context, no-plugins isolation)
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

        // Arm interrupt cleanup before the unpacked DB files come into existence.
        install_db_cleanup_handler(input_file);

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
    std::string m_fake_idadir_base;
};

//=============================================================================
// Input filtering (extension + magic-based file type)
//=============================================================================

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

static bool vector_contains(const std::vector<std::string>& values, const std::string& value) {
    return std::find(values.begin(), values.end(), value) != values.end();
}

// Lightweight magic-byte classification (enough for --type filtering).
static std::string detect_file_type(const std::filesystem::path& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        return "unknown";
    }
    // Read a small prefix so 'MZ' can be validated by following e_lfanew to the
    // real PE signature (a bare 'MZ' alone is just a DOS stub).
    unsigned char hdr[0x40] = {};
    file.read(reinterpret_cast<char*>(hdr), sizeof(hdr));
    const std::streamsize got = file.gcount();
    if (got < 4) {
        return "unknown";
    }
    const unsigned char* b = hdr;

    if (b[0] == 'M' && b[1] == 'Z') {
        if (got >= 0x40) {
            const uint32_t e_lfanew = static_cast<uint32_t>(hdr[0x3c])
                | (static_cast<uint32_t>(hdr[0x3d]) << 8)
                | (static_cast<uint32_t>(hdr[0x3e]) << 16)
                | (static_cast<uint32_t>(hdr[0x3f]) << 24);
            file.clear();
            file.seekg(e_lfanew, std::ios::beg);
            unsigned char sig[4] = {};
            if (file && file.read(reinterpret_cast<char*>(sig), 4)
                && sig[0] == 'P' && sig[1] == 'E' && sig[2] == 0 && sig[3] == 0) {
                return "pe";
            }
        }
        return "unknown";  // DOS stub / NE / LE — not an analyzable PE
    }
    if (b[0] == 0x7f && b[1] == 'E' && b[2] == 'L' && b[3] == 'F') {
        return "elf";
    }

    const uint32_t le = static_cast<uint32_t>(b[0]) | (static_cast<uint32_t>(b[1]) << 8)
        | (static_cast<uint32_t>(b[2]) << 16) | (static_cast<uint32_t>(b[3]) << 24);
    const uint32_t be = (static_cast<uint32_t>(b[0]) << 24) | (static_cast<uint32_t>(b[1]) << 16)
        | (static_cast<uint32_t>(b[2]) << 8) | static_cast<uint32_t>(b[3]);
    if (le == 0xfeedface || le == 0xfeedfacf || le == 0xcefaedfe || le == 0xcffaedfe
        || be == 0xcafebabe || be == 0xcafebabf) {
        return "mach-o";
    }

    return "unknown";
}

static bool has_active_input_filters() {
    return !g_opts.extensions.empty() || !g_opts.file_types.empty();
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

    if (!g_opts.file_types.empty()) {
        const std::string type = detect_file_type(path);
        if (!vector_contains(g_opts.file_types, type)) {
            if (reason) {
                *reason = "detected type " + type + " is not enabled";
            }
            return false;
        }
    }

    return true;
}

//=============================================================================
// INTERR scanning
//=============================================================================

struct InterrRecord {
    ea_t address = BADADDR;
    int code = 0;            // real interr number (hard interr_exc_t); 0 if only the soft sentinel
    std::string name;
    std::string stage;       // where the internal error fired
    std::string detail;      // human-readable failure text (hf.desc()), if any
    std::string microcode;   // raw MMAT_GENERATED microcode (empty if unavailable)
};

struct FileScanResult {
    size_t functions_scanned = 0;
    size_t interr_count = 0;
    bool success = false;
    std::string error_message;
};

// Render a freshly generated mba to plain text.
static std::string render_microcode(mba_t *mba) {
    if (!mba) return std::string();
    std::ostringstream text;
    MicrocodePrinter printer(text);
    mba->print(printer);
    return text.str();
}

// Decompile one function with internal errors caught. Returns true and fills
// `rec` when an internal error fires. Microcode is generated first on a clean
// engine so we can show the raw lifter output even when the later, fuller
// decompilation is what trips the error.
static bool scan_function_for_interr(func_t *pfn, InterrRecord &rec) {
    if (!pfn) return false;

    qstring fname;
    get_func_name(&fname, pfn->start_ea);
    mba_ranges_t mbr(pfn);

    bool have_interr = false;

    // Record a soft failure (decompiler returned nullptr / threw vd_failure_t
    // with MERR_INTERR). The MERR_INTERR code itself is just the -1 sentinel, so
    // the useful information is hf.desc() (the real message, often carrying the
    // internal-error number) and hf.errea (the precise faulting address).
    auto record_soft = [&](const hexrays_failure_t &hf, const char *stage) {
        rec.stage = stage;
        rec.detail = hf.desc().c_str();
        if (hf.errea != BADADDR) rec.address = hf.errea;
        have_interr = true;
    };

    // Stage 1: generate raw microcode (also surfaces generation-time interrs,
    // which is where most lifter bugs live).
    try {
        hexrays_failure_t hf;
        mba_t *mba = gen_microcode(mbr, &hf, nullptr, DECOMP_WARNINGS, MMAT_GENERATED);
        if (mba != nullptr) {
            rec.microcode = render_microcode(mba);
            delete mba;  // mba_t::~mba_t() calls term()
        } else if (hf.code == MERR_INTERR) {
            record_soft(hf, "microcode generation");
        }
        // Any other generation failure just means the function doesn't lift;
        // that is not an internal error and is of no interest here.
    } catch (const interr_exc_t &e) {
        rec.code = e.code;  // the genuine internal-error number
        rec.stage = "microcode generation";
        have_interr = true;
    } catch (const vd_failure_t &e) {
        if (e.hf.code == MERR_INTERR) record_soft(e.hf, "microcode generation");
    } catch (...) {
        // Non-interr failure during generation; not our concern.
    }

    // Stage 2: full decompilation, to surface interrs raised by the optimizer,
    // verifier, or ctree builder. Skipped if generation already interr'd (the
    // engine is best left alone after that). DECOMP_NO_CACHE keeps the result
    // out of the global cfunc cache — we only inspect hf, never reuse cfunc.
    if (!have_interr) {
        try {
            hexrays_failure_t hf;
            cfuncptr_t cfunc = decompile(pfn, &hf, DECOMP_WARNINGS | DECOMP_NO_CACHE);
            if (cfunc == nullptr && hf.code == MERR_INTERR) {
                record_soft(hf, "decompilation");
            }
        } catch (const interr_exc_t &e) {
            rec.code = e.code;
            rec.stage = "decompilation";
            have_interr = true;
        } catch (const vd_failure_t &e) {
            if (e.hf.code == MERR_INTERR) record_soft(e.hf, "decompilation");
        } catch (...) {
            // Non-interr failure; ignore.
        }
    }

    if (have_interr) {
        if (rec.address == BADADDR) rec.address = pfn->start_ea;
        rec.name = fname.c_str();
    }
    return have_interr;
}

static std::string format_address(ea_t ea) {
    qstring text;
    ea2str(&text, ea);
    return text.c_str();
}

// Append a plain-text report block for a single offender. The header reads
// "<addr>  INTERR[ <code>]  <name>  [<stage>][: <detail>]". The numeric code is
// only shown when known (hard interr_exc_t); soft failures carry the message in
// <detail> instead of the meaningless MERR_INTERR (-1) sentinel.
static void format_interr_block(std::ostream &out, const InterrRecord &rec) {
    out << format_address(rec.address) << "  INTERR";
    if (rec.code > 0) out << " " << rec.code;
    out << "  " << rec.name << "  [" << rec.stage << "]";
    if (!rec.detail.empty()) out << ": " << rec.detail;
    out << "\n";

    if (rec.microcode.empty()) {
        out << "    ; microcode unavailable (internal error during generation)\n";
    } else {
        out << "    ; microcode (MMAT_GENERATED)\n";
        out << rec.microcode;
    }
    out << "\n";
}

// Scan every function in the already-open database, writing report blocks to
// `report` and counting offenders. set_interr_throws() is enabled for the scan
// so hard interrs become catchable and the scan can run to completion.
static FileScanResult scan_open_database(const std::string &input_file, std::ostream &report) {
    FileScanResult result;

    // RAII so the process-global flag is restored on any exit path (an I/O or
    // allocation failure in the loop body sits outside scan_function_for_interr's
    // own try/catch).
    struct InterrThrowsGuard {
        bool prev;
        InterrThrowsGuard() : prev(set_interr_throws(true)) {}
        ~InterrThrowsGuard() { set_interr_throws(prev); }
    } interr_guard;

    const size_t qty = get_func_qty();

    bool wrote_header = false;
    for (size_t i = 0; i < qty; ++i) {
        func_t *pfn = getn_func(i);
        if (!pfn) continue;

        result.functions_scanned++;

        InterrRecord rec;
        if (scan_function_for_interr(pfn, rec)) {
            if (!wrote_header) {
                report << "==== " << input_file << " ====\n";
                wrote_header = true;
            }
            format_interr_block(report, rec);
            report.flush();
            result.interr_count++;
        }
    }

    result.success = true;
    return result;
}

// Open `input_file`, scan it, and return the result. Throws on load failure.
static FileScanResult scan_file(const std::string &input_file, std::ostream &report, bool quiet) {
    HeadlessIdaContext ctx(input_file.c_str(), quiet);
    if (!ctx.hexrays_available()) {
        throw std::runtime_error("Hex-Rays decompiler is not available");
    }
    return scan_open_database(input_file, report);
}

//=============================================================================
// Single-file mode
//=============================================================================

static int run_single_file() {
    FileScanResult result = scan_file(g_opts.input_file, *g_report, g_opts.quiet);
    g_report->flush();

    std::cout << "\n";
    if (result.interr_count == 0) {
        std::cout << CLR(Green) << "[+] No internal errors" << CLR(Reset)
                  << " across " << result.functions_scanned << " functions in "
                  << g_opts.input_file << "\n";
    } else {
        std::cout << CLR(Red) << "[!] " << result.interr_count << " internal error"
                  << (result.interr_count == 1 ? "" : "s") << CLR(Reset)
                  << " across " << result.functions_scanned << " functions in "
                  << g_opts.input_file;
        if (!g_opts.output_file.empty()) {
            std::cout << "  (report: " << g_opts.output_file << ")";
        }
        std::cout << "\n";
    }

    return result.interr_count == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

//=============================================================================
// Recursive mode (fork one worker per file)
//=============================================================================

#ifndef _WIN32
static unsigned int default_job_count() {
    long count = sysconf(_SC_NPROCESSORS_ONLN);
    return count > 0 ? static_cast<unsigned int>(count) : 1u;
}

constexpr size_t CHILD_ERROR_SIZE = 512;

// Fixed-size message sent by each worker (one write_full). The report itself is
// streamed incrementally to a temp file at a deterministic, pid-derived path
// (worker_report_path) rather than over the pipe: a payload larger than the pipe
// buffer would wedge the worker in write() while the parent blocks in waitpid()
// (deadlock). A fixed message always fits the buffer, so waitpid-then-read is
// safe, and because the path is pid-derived the parent can recover (and clean
// up) the report even when the worker dies before sending this header.
struct ChildHeader {
    uint64_t functions_scanned = 0;
    uint64_t interr_count = 0;
    uint8_t  success = 0;
    char     error_message[CHILD_ERROR_SIZE] = {}; // worker-fatal error (empty on success)
};

static void set_bounded(char* dst, size_t cap, const std::string& src) {
    const size_t n = std::min(src.size(), cap - 1);
    std::memcpy(dst, src.data(), n);
    dst[n] = '\0';
}

struct WorkerProcess {
    pid_t pid = -1;
    int read_fd = -1;
    std::string input_file;
};

struct BatchStats {
    size_t files_total = 0;
    size_t files_succeeded = 0;
    size_t files_failed = 0;
    size_t functions_scanned = 0;
    size_t interr_count = 0;
};

static bool write_full(int fd, const void* data, size_t size) {
    const uint8_t* ptr = static_cast<const uint8_t*>(data);
    size_t remaining = size;
    while (remaining > 0) {
        ssize_t written = real_write(fd, ptr, remaining);
        if (written <= 0) {
            if (errno == EINTR) continue;
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
        if (nread == 0) return false;
        if (nread < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        ptr += nread;
        remaining -= static_cast<size_t>(nread);
    }
    return true;
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

static std::vector<std::string> collect_recursive_inputs(const std::string& root_dir, size_t* skipped) {
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
            if (file_matches_filters(it->path().string())) {
                files.push_back(it->path().string());
            } else if (skipped) {
                (*skipped)++;
            }
        }
    }

    std::sort(files.begin(), files.end());
    return files;
}

// Deterministic per-worker report path, derived from the worker pid so the
// parent can find it whether the worker exits cleanly or dies mid-scan.
static std::string worker_report_path(long pid) {
    return (std::filesystem::temp_directory_path() /
            ("ida_interr_" + std::to_string(pid) + ".txt")).string();
}

// Run inside a forked worker: scan one file, streaming each offender's report
// block straight to its pid-derived temp file (so a hard crash still leaves the
// offenders found so far on disk for the parent to recover), then hand back a
// single fixed-size header. Never returns.
[[noreturn]] static void run_worker(const std::string& input_file, int write_fd) {
    ChildHeader header;
    const std::string report_path = worker_report_path(getpid());

    std::ofstream rep(report_path, std::ios::out | std::ios::trunc | std::ios::binary);
    if (!rep.is_open()) {
        header.success = 0;
        set_bounded(header.error_message, sizeof(header.error_message),
                    "cannot create report file: " + report_path);
    } else {
        try {
            FileScanResult result = scan_file(input_file, rep, true);
            rep.flush();
            if (!rep) {
                // The report couldn't be fully written (disk full, etc.) — don't
                // claim success with a truncated/lost report.
                header.success = 0;
                set_bounded(header.error_message, sizeof(header.error_message),
                            "error writing report file: " + report_path);
            } else {
                header.functions_scanned = result.functions_scanned;
                header.interr_count = result.interr_count;
                header.success = 1;
            }
        } catch (const std::exception& e) {
            header.success = 0;
            set_bounded(header.error_message, sizeof(header.error_message), e.what());
        }
    }

    write_full(write_fd, &header, sizeof(header));
    real_close(write_fd);

    std::_Exit(header.success && header.interr_count == 0 ? EXIT_SUCCESS : EXIT_FAILURE);
}

static int run_recursive_mode() {
    size_t skipped_by_filter = 0;
    const std::vector<std::string> files = collect_recursive_inputs(g_opts.input_file, &skipped_by_filter);
    if (files.empty()) {
        std::cerr << CLR(Yellow) << "[!] No matching regular files found under "
                  << g_opts.input_file << CLR(Reset) << "\n";
        return EXIT_FAILURE;
    }

    const unsigned int requested_jobs = g_opts.jobs_specified ? g_opts.jobs : default_job_count();
    const size_t max_jobs = std::max<size_t>(1, std::min<size_t>(requested_jobs, files.size()));

    std::cout << "[*] Found " << files.size() << " matching files under " << g_opts.input_file;
    if (has_active_input_filters()) {
        std::cout << " (" << skipped_by_filter << " skipped by filters)";
    }
    std::cout << "; running up to " << max_jobs << " worker processes." << std::endl;

    BatchStats batch;
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
            g_report->flush();

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
                run_worker(input_file, pipefd[1]);  // never returns
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
            if (errno == EINTR) continue;
            throw std::runtime_error(std::string("waitpid failed: ") + std::strerror(errno));
        }

        auto worker_it = std::find_if(running.begin(), running.end(),
            [finished_pid](const WorkerProcess& worker) { return worker.pid == finished_pid; });
        if (worker_it == running.end()) {
            continue;
        }

        ChildHeader header;
        std::string error_text;
        bool received = read_full(worker_it->read_fd, &header, sizeof(header));
        real_close(worker_it->read_fd);
        if (received && header.error_message[0] != '\0') {
            error_text = header.error_message;
        }

        // The report lives at a deterministic pid-derived path, so it can be
        // recovered (and cleaned up) whether the worker finished or crashed.
        const std::string report_path = worker_report_path(finished_pid);
        auto stream_report = [&]() {
            std::ifstream tf(report_path, std::ios::binary);
            if (tf && tf.peek() != std::ifstream::traits_type::eof()) {
                *g_report << tf.rdbuf();
                g_report->flush();
            }
        };

        if (!received) {
            // No (complete) message: the worker most likely crashed hard. Still
            // surface whatever offenders it wrote before dying.
            error_text = wait_status_message(status);
            stream_report();
            batch.files_failed++;
        } else if (header.success == 0) {
            // Worker reported a load/setup/report failure for this file.
            batch.files_failed++;
        } else {
            batch.files_succeeded++;
            batch.functions_scanned += static_cast<size_t>(header.functions_scanned);
            batch.interr_count += static_cast<size_t>(header.interr_count);
            stream_report();
        }

        std::error_code rm_ec;
        std::filesystem::remove(report_path, rm_ec);

        const bool had_interrs = received && header.success != 0 && header.interr_count > 0;
        const char* tag = (!received || header.success == 0) ? "[-]"
                        : (had_interrs ? "[!]" : "[+]");
        const char* color = (!received || header.success == 0) ? CLR(Red)
                          : (had_interrs ? CLR(Yellow) : CLR(Green));

        std::cout << color << tag << CLR(Reset) << " " << worker_it->input_file;
        if (received && header.success != 0) {
            std::cout << "  funcs=" << header.functions_scanned
                      << " interrs=" << header.interr_count;
        }
        if (!error_text.empty()) {
            std::cout << "  (" << error_text << ")";
        }
        std::cout << "\n";

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
    std::cout << "  " << (batch.files_failed > 0 ? CLR(Red) : "")
              << "Failed:       " << batch.files_failed << (batch.files_failed > 0 ? CLR(Reset) : "") << "\n";
    std::cout << "  Functions:    " << batch.functions_scanned << "\n";
    std::cout << "  " << (batch.interr_count > 0 ? CLR(Red) : CLR(Green))
              << "Internal errors: " << batch.interr_count << CLR(Reset) << "\n";
    std::cout << std::string(50, '-') << "\n";
    if (!g_opts.output_file.empty() && batch.interr_count > 0) {
        std::cout << "Report written to " << g_opts.output_file << "\n";
    }

    return (batch.files_failed == 0 && batch.interr_count == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
#endif  // !_WIN32

//=============================================================================
// Usage / argument parsing
//=============================================================================

static bool parse_positive_uint(const std::string& value, unsigned int& parsed) {
    try {
        size_t consumed = 0;
        unsigned long number = std::stoul(value, &consumed, 10);
        if (consumed != value.size() || number == 0 ||
            number > std::numeric_limits<unsigned int>::max()) {
            return false;
        }
        parsed = static_cast<unsigned int>(number);
        return true;
    } catch (...) {
        return false;
    }
}

static void print_usage(const char* prog) {
    std::cout << CLR(Bold) << "IDA Pro Internal-Error (INTERR) Hunter" << CLR(Reset) << "\n\n";
    std::cout << CLR(Cyan) << "Usage:" << CLR(Reset) << " " << prog << " [options] <input_path>\n\n";
    std::cout << CLR(Cyan) << "Description:" << CLR(Reset) << "\n";
    std::cout << "  Decompiles every function in a binary and reports the ones that trigger a\n";
    std::cout << "  Hex-Rays internal error (INTERR), dumping the raw generated microcode for\n";
    std::cout << "  each offender. With --recursive, scans a directory tree, one forked worker\n";
    std::cout << "  per file so a crash or interr can't take the whole batch down.\n\n";
    std::cout << "  The interr report goes to stderr (or the -o file); per-file status and the\n";
    std::cout << "  batch summary go to stdout.\n\n";
    std::cout << CLR(Cyan) << "Options:" << CLR(Reset) << "\n";
    std::cout << "  -o, --output <file>  Write the INTERR report to a file instead of stderr\n";
    std::cout << "  -r, --recursive      Recursively process all files under <input_path>\n";
    std::cout << "  -j, --jobs <count>   Worker processes for --recursive (default: CPU count)\n";
    std::cout << "  --ext <ext>          Only process files with extension (repeatable, e.g. dll)\n";
    std::cout << "  --type <type>        Only process binary type: pe, elf, mach-o, unknown (repeatable)\n";
    std::cout << "  -q, --quiet          Suppress IDA's verbose messages\n";
    std::cout << "  --no-color           Disable colored output\n";
    std::cout << "  --no-plugins         Don't load user plugins (keeps IDA built-in plugins)\n";
    std::cout << "  --plugin <pattern>   Also load user plugins matching pattern (implies --no-plugins)\n";
    std::cout << "                       Can be specified multiple times\n";
    std::cout << "  -h, --help           Show this help\n";
    std::cout << "\n";
    std::cout << CLR(Cyan) << "Examples:" << CLR(Reset) << "\n";
    std::cout << "  " << prog << " program.exe              # Scan one binary, report interrs on stderr\n";
    std::cout << "  " << prog << " -o interrs.txt program.exe\n";
    std::cout << "  " << prog << " -r samples/              # Recursively scan a folder\n";
    std::cout << "  " << prog << " -r -j 4 --type pe samples/\n";
    std::cout << "  " << prog << " --plugin avxlifter program.exe   # Load only the AVX lifter, then scan\n";
    std::cout << "\n";
#ifdef _WIN32
    std::cout << CLR(Cyan) << "Note:" << CLR(Reset) << "\n";
    std::cout << "  Recursive mode is unavailable on Windows because it requires fork().\n\n";
#endif
}

static bool parse_args(int argc, char* argv[]) {
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];

        if (arg == "-h" || arg == "--help") {
            print_usage(argv[0]);
            exit(0);
        }
        else if (arg == "-o" || arg == "--output") {
            if (i + 1 >= argc) {
                std::cerr << "Error: --output requires a filename\n";
                return false;
            }
            g_opts.output_file = argv[++i];
        }
        else if (arg == "-q" || arg == "--quiet") {
            g_opts.quiet = true;
        }
        else if (arg == "-r" || arg == "--recursive") {
            g_opts.recursive = true;
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
            if (!reason.empty()) std::cerr << ": " << reason;
            std::cerr << "\n";
            return EXIT_FAILURE;
        }
    }

    // Open the report sink (the file content is plain text regardless of color).
    if (!g_opts.output_file.empty()) {
        g_report_file.open(g_opts.output_file, std::ios::out | std::ios::trunc | std::ios::binary);
        if (!g_report_file.is_open()) {
            std::cerr << "Error: Cannot open output file: " << g_opts.output_file << "\n";
            return EXIT_FAILURE;
        }
        g_report = &g_report_file;
    }

    try {
        if (g_opts.recursive) {
#ifdef _WIN32
            throw std::runtime_error("Recursive mode is not supported on Windows because it uses fork() workers.");
#else
            return run_recursive_mode();
#endif
        }
        return run_single_file();
    }
    catch (const std::exception &e) {
        std::cerr << CLR(Red) << "[FATAL] " << CLR(Reset) << e.what() << std::endl;
        return EXIT_FAILURE;
    }
}
