/**
 * IDA Pro Lumina Metadata Debug Tool
 *
 * Analyzes a binary and dumps per-function Lumina-relevant metadata,
 * including the calculated MD5 hash, EA/RVA, names, and summarized symbol
 * metadata derived through the public SDK APIs in lumina.hpp.
 */

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <regex>
#include <sstream>
#include <string>
#include <system_error>
#include <vector>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <dlfcn.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

// Save real setenv/getenv before IDA SDK redefines them with macros.
static inline int real_setenv(const char *name, const char *value)
{
#ifdef _WIN32
    return _putenv_s(name, value);
#else
    return setenv(name, value, 1);
#endif
}

static inline const char *real_getenv(const char *name)
{
    return getenv(name);
}

// From noplugins.c - controls plugin blocking.
extern "C" bool g_block_plugins;

// IDA SDK headers.
#include <pro.h>
#include <ida.hpp>
#include <auto.hpp>
#include <bytes.hpp>
#include <funcs.hpp>
#include <name.hpp>
#include <loader.hpp>
#include <hexrays.hpp>
#include <idalib.hpp>
#include <segment.hpp>
#include <typeinf.hpp>
#include <nalt.hpp>
#include <lumina.hpp>

//=============================================================================
// Global State
//=============================================================================

struct Options
{
    std::string input_file;
    std::string output_file;
    std::string filter_pattern;
    ea_t filter_address = BADADDR;
    std::vector<std::string> function_list;
    std::vector<std::string> plugin_patterns;
    bool csv_output = false;
    bool show_function_bytes = false;
    bool quiet = false;
    bool no_plugins = false;
    bool verbose = false;
};

static Options g_opts;
static std::ostream *g_output = &std::cout;
hexdsp_t *hexdsp = nullptr;

//=============================================================================
// ANSI Colors
//=============================================================================

namespace Color
{
    const char *Reset = "\033[0m";
    const char *Bold = "\033[1m";
    const char *Red = "\033[31m";
    const char *Green = "\033[32m";
    const char *Yellow = "\033[33m";
    const char *Cyan = "\033[36m";

    bool enabled = true;
    void disable() { enabled = false; }
    const char *get(const char *c) { return enabled ? c : ""; }
}

#define CLR(c) Color::get(Color::c)

//=============================================================================
// Helpers
//=============================================================================

static std::string trim_copy(const std::string &value)
{
    size_t start = 0;
    while (start < value.size() && std::isspace(static_cast<unsigned char>(value[start])) != 0)
        ++start;

    size_t end = value.size();
    while (end > start && std::isspace(static_cast<unsigned char>(value[end - 1])) != 0)
        --end;

    return value.substr(start, end - start);
}

static std::vector<std::string> split_string(const std::string &value)
{
    std::vector<std::string> result;
    std::string current;

    for (char ch : value)
    {
        if (ch == ',' || ch == '|')
        {
            std::string item = trim_copy(current);
            if (!item.empty())
                result.push_back(item);
            current.clear();
        }
        else
        {
            current.push_back(ch);
        }
    }

    std::string tail = trim_copy(current);
    if (!tail.empty())
        result.push_back(tail);

    return result;
}

static ea_t parse_address(const std::string &value)
{
    if (value.empty())
        return BADADDR;

    const char *s = value.c_str();
    if (value.size() > 2 && value[0] == '0' && (value[1] == 'x' || value[1] == 'X'))
        s += 2;

    if (*s == '\0')
        return BADADDR;

    for (const char *p = s; *p != '\0'; ++p)
    {
        if (std::isxdigit(static_cast<unsigned char>(*p)) == 0)
            return BADADDR;
    }

    return static_cast<ea_t>(strtoull(value.c_str(), nullptr, 16));
}

static std::string lowercase_copy(const std::string &value)
{
    std::string out = value;
    std::transform(out.begin(), out.end(), out.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    return out;
}

static std::string get_demangled_name(const char *mangled_name)
{
    if (mangled_name == nullptr || *mangled_name == '\0')
        return "";

    qstring demangled;
    if (demangle_name(&demangled, mangled_name, 0, DQT_FULL) > 0)
        return demangled.c_str();

    return "";
}

static bool pattern_matches_name(const std::string &pattern, const char *name)
{
    if (name == nullptr || *name == '\0')
        return false;

    try
    {
        std::regex re(pattern, std::regex::icase);
        return std::regex_search(name, re);
    }
    catch (const std::regex_error &)
    {
        std::string name_lower = lowercase_copy(name);
        std::string pattern_lower = lowercase_copy(pattern);
        return name_lower.find(pattern_lower) != std::string::npos;
    }
}

static bool matches_filter(const char *func_name, ea_t func_addr)
{
    if (g_opts.filter_address != BADADDR)
        return func_addr == g_opts.filter_address;

    std::string demangled = get_demangled_name(func_name);

    if (!g_opts.function_list.empty())
    {
        for (const std::string &item : g_opts.function_list)
        {
            ea_t addr = parse_address(item);
            if (addr != BADADDR)
            {
                if (func_addr == addr)
                    return true;
                func_t *pfn = get_func(addr);
                if (pfn != nullptr && pfn->start_ea == func_addr)
                    return true;
                continue;
            }

            if (item == func_name)
                return true;
            if (!demangled.empty() && item == demangled)
                return true;

            std::string name_lower = lowercase_copy(func_name != nullptr ? func_name : "");
            std::string item_lower = lowercase_copy(item);
            if (name_lower == item_lower)
                return true;
            if (!demangled.empty() && lowercase_copy(demangled) == item_lower)
                return true;
        }
        return false;
    }

    if (!g_opts.filter_pattern.empty())
    {
        if (pattern_matches_name(g_opts.filter_pattern, func_name))
            return true;
        if (!demangled.empty() && pattern_matches_name(g_opts.filter_pattern, demangled.c_str()))
            return true;
        return false;
    }

    return true;
}

static std::string format_hex(uint64_t value)
{
    std::ostringstream oss;
    oss << "0x";
    oss << std::hex;
    oss.setf(std::ios::uppercase);
    oss.width(inf_is_64bit() ? 16 : 8);
    oss.fill('0');
    oss << value;
    return oss.str();
}

static std::string format_ea(ea_t ea)
{
    if (ea == BADADDR)
        return "";
    return format_hex(static_cast<uint64_t>(ea));
}

static std::string format_rva(ea_t ea, ea_t imagebase)
{
    if (ea == BADADDR || imagebase == BADADDR || ea < imagebase)
        return "";
    return format_hex(static_cast<uint64_t>(ea - imagebase));
}

static std::string format_md5(const md5_t &md5)
{
    std::ostringstream oss;
    oss << std::hex;
    oss.setf(std::ios::uppercase);
    oss.fill('0');
    for (unsigned char byte : md5.hash)
    {
        oss.width(2);
        oss << static_cast<unsigned int>(byte);
    }
    return oss.str();
}

static std::string csv_escape(const std::string &value)
{
    if (value.find_first_of(",\"\n\r") == std::string::npos)
        return value;

    std::string escaped;
    escaped.reserve(value.size() + 8);
    escaped.push_back('"');
    for (char ch : value)
    {
        if (ch == '"')
            escaped.push_back('"');
        escaped.push_back(ch);
    }
    escaped.push_back('"');
    return escaped;
}

static std::string join_strings(const std::vector<std::string> &values, const char *separator)
{
    if (values.empty())
        return "";

    std::ostringstream oss;
    for (size_t i = 0; i < values.size(); ++i)
    {
        if (i != 0)
            oss << separator;
        oss << values[i];
    }
    return oss.str();
}

static void append_hex_byte(std::string &out, uchar byte)
{
    static const char digits[] = "0123456789ABCDEF";
    out.push_back(digits[(byte >> 4) & 0xF]);
    out.push_back(digits[byte & 0xF]);
}

static std::string get_input_path()
{
    char buf[QMAXPATH] = {0};
    if (get_input_file_path(buf, sizeof(buf)) > 0)
        return buf;
    return g_opts.input_file;
}

static std::string get_segment_name(ea_t ea)
{
    qstring seg_name;
    segment_t *seg = getseg(ea);
    if (seg != nullptr)
        get_segm_name(&seg_name, seg);
    return seg_name.c_str();
}

static std::string bool_string(bool value)
{
    return value ? "yes" : "no";
}

static const char *mdkey_name(mdkey_t key)
{
    switch (key)
    {
    case MDK_NONE:
        return "NONE";
    case MDK_TYPE:
        return "TYPE";
    case MDK_VD_ELAPSED:
        return "VD_ELAPSED";
    case MDK_FCMT:
        return "FCMT";
    case MDK_FRPTCMT:
        return "FRPTCMT";
    case MDK_CMTS:
        return "CMTS";
    case MDK_RPTCMTS:
        return "RPTCMTS";
    case MDK_EXTRACMTS:
        return "EXTRACMTS";
    case MDK_USER_STKPNTS:
        return "USER_STKPNTS";
    case MDK_FRAME_DESC:
        return "FRAME_DESC";
    case MDK_OPS:
        return "OPS";
    case MDK_OPS_EX:
        return "OPS_EX";
    case MDK_LAST:
        return "LAST";
    }
    return "UNKNOWN";
}

//=============================================================================
// Metadata Summaries
//=============================================================================

struct MetadataSummary
{
    bool has_type = false;
    bool has_function_comment = false;
    bool has_repeatable_function_comment = false;
    bool has_insn_comments = false;
    bool has_insn_repeatable_comments = false;
    bool has_extra_comments = false;
    bool has_user_stack_points = false;
    bool has_frame_desc = false;
    bool has_operand_reprs = false;
    bool has_operand_reprs_ex = false;
    size_t metadata_bytes = 0;
    std::vector<std::string> keys;
};

struct FunctionBytesInfo
{
    size_t total_len = 0;
    std::string chunks;
    std::string hex;
};

struct FunctionRecord
{
    ea_t ea = BADADDR;
    ea_t imagebase = BADADDR;
    std::string segment;
    std::string db_name;
    std::string lumina_name;
    std::string demangled_name;
    md5_t md5;
    uint32 function_size = 0;
    size_t function_bytes_len = 0;
    std::string function_byte_chunks;
    std::string function_bytes_hex;
    MetadataSummary metadata;
};

struct AnalysisSummary
{
    std::string input_path;
    md5_t input_md5;
    ea_t imagebase = BADADDR;
    size_t total_functions = 0;
    size_t matched_functions = 0;
    size_t metadata_functions = 0;
    size_t typed_functions = 0;
};

static MetadataSummary summarize_metadata(const func_info_t &fi)
{
    MetadataSummary summary;
    summary.metadata_bytes = fi.metadata.size();

    metadata_iterator_t iter(fi.metadata);
    while (iter.next())
    {
        summary.keys.push_back(mdkey_name(iter.key));

        switch (iter.key)
        {
        case MDK_TYPE:
            summary.has_type = true;
            break;
        case MDK_FCMT:
            summary.has_function_comment = true;
            break;
        case MDK_FRPTCMT:
            summary.has_repeatable_function_comment = true;
            break;
        case MDK_CMTS:
            summary.has_insn_comments = true;
            break;
        case MDK_RPTCMTS:
            summary.has_insn_repeatable_comments = true;
            break;
        case MDK_EXTRACMTS:
            summary.has_extra_comments = true;
            break;
        case MDK_USER_STKPNTS:
            summary.has_user_stack_points = true;
            break;
        case MDK_FRAME_DESC:
            summary.has_frame_desc = true;
            break;
        case MDK_OPS:
            summary.has_operand_reprs = true;
            break;
        case MDK_OPS_EX:
            summary.has_operand_reprs_ex = true;
            break;
        default:
            break;
        }
    }

    return summary;
}

static void append_chunk_descriptor(std::string &out, ea_t start_ea, ea_t end_ea, size_t size)
{
    if (!out.empty())
        out += '|';

    out += format_ea(start_ea);
    out += '-';
    out += format_ea(end_ea);
    out += '(';
    out += std::to_string(size);
    out += ')';
}

static size_t append_range_bytes_hex(FunctionBytesInfo &info, ea_t start_ea, ea_t end_ea)
{
    if (start_ea == BADADDR || end_ea == BADADDR || end_ea <= start_ea)
        return 0;

    size_t range_size = static_cast<size_t>(end_ea - start_ea);
    qvector<uchar> bytes;
    bytes.resize(range_size);

    ssize_t read_size = get_bytes(bytes.begin(), static_cast<ssize_t>(range_size), start_ea, GMB_READALL);
    if (read_size < 0)
        throw std::runtime_error("Cancelled while reading bytes for function at " + format_ea(start_ea));
    if (read_size == 0)
        return 0;

    size_t actual_size = static_cast<size_t>(read_size);
    info.hex.reserve(info.hex.size() + (actual_size * 2));
    for (size_t i = 0; i < actual_size; ++i)
        append_hex_byte(info.hex, bytes[i]);

    append_chunk_descriptor(info.chunks, start_ea, start_ea + actual_size, actual_size);
    info.total_len += actual_size;
    return actual_size;
}

static FunctionBytesInfo get_function_bytes_info(const func_t *pfn)
{
    FunctionBytesInfo info;
    if (pfn == nullptr)
        return info;

    append_range_bytes_hex(info, pfn->start_ea, pfn->end_ea);

    func_tail_iterator_t tail_iter(const_cast<func_t *>(pfn));
    for (bool ok = tail_iter.first(); ok; ok = tail_iter.next())
    {
        const range_t &chunk = tail_iter.chunk();
        append_range_bytes_hex(info, chunk.start_ea, chunk.end_ea);
    }

    return info;
}

static FunctionRecord build_record(const func_t *pfn, ea_t imagebase)
{
    FunctionRecord record;
    record.ea = pfn->start_ea;
    record.imagebase = imagebase;
    record.segment = get_segment_name(pfn->start_ea);

    qstring func_name;
    get_func_name(&func_name, pfn->start_ea);
    record.db_name = func_name.c_str();
    record.demangled_name = get_demangled_name(record.db_name.c_str());

    func_info_t fi;
    calc_func_metadata(&record.md5, &fi, pfn, nullptr);

    record.lumina_name = fi.name.c_str();
    record.function_size = fi.size != 0 ? fi.size : static_cast<uint32>(pfn->size());
    if (g_opts.show_function_bytes)
    {
        FunctionBytesInfo bytes_info = get_function_bytes_info(pfn);
        record.function_bytes_len = bytes_info.total_len;
        record.function_byte_chunks = std::move(bytes_info.chunks);
        record.function_bytes_hex = std::move(bytes_info.hex);
    }

    record.metadata = summarize_metadata(fi);

    return record;
}

static std::vector<FunctionRecord> collect_records(AnalysisSummary &summary)
{
    summary.input_path = get_input_path();
    summary.imagebase = get_imagebase();
    retrieve_input_file_md5(summary.input_md5.hash);

    size_t func_count = get_func_qty();
    summary.total_functions = func_count;

    std::vector<FunctionRecord> records;
    records.reserve(func_count);

    for (size_t i = 0; i < func_count; ++i)
    {
        func_t *pfn = getn_func(i);
        if (pfn == nullptr)
            continue;

        qstring func_name;
        get_func_name(&func_name, pfn->start_ea);
        std::string func_name_str = func_name.c_str() != nullptr ? func_name.c_str() : "";

        if (!matches_filter(func_name_str.c_str(), pfn->start_ea))
            continue;

        FunctionRecord record = build_record(pfn, summary.imagebase);
        ++summary.matched_functions;
        if (record.metadata.metadata_bytes != 0)
            ++summary.metadata_functions;
        if (record.metadata.has_type)
            ++summary.typed_functions;
        records.push_back(std::move(record));
    }

    return records;
}

//=============================================================================
// Output
//=============================================================================

static void write_csv_row(std::ostream &out, const AnalysisSummary &summary, const FunctionRecord &record)
{
    std::string metadata_keys = join_strings(record.metadata.keys, "|");

    out
        << csv_escape(format_ea(record.ea)) << ','
        << csv_escape(format_rva(record.ea, record.imagebase)) << ','
        << csv_escape(record.segment) << ','
        << record.function_size << ','
        << csv_escape(format_md5(record.md5)) << ','
        << csv_escape(record.db_name) << ','
        << csv_escape(record.lumina_name) << ','
        << csv_escape(record.demangled_name) << ','
        << record.metadata.metadata_bytes << ','
        << csv_escape(metadata_keys) << ','
        << bool_string(record.metadata.has_type) << ','
        << bool_string(record.metadata.has_function_comment) << ','
        << bool_string(record.metadata.has_repeatable_function_comment) << ','
        << bool_string(record.metadata.has_insn_comments) << ','
        << bool_string(record.metadata.has_insn_repeatable_comments) << ','
        << bool_string(record.metadata.has_extra_comments) << ','
        << bool_string(record.metadata.has_user_stack_points) << ','
        << bool_string(record.metadata.has_frame_desc) << ','
        << bool_string(record.metadata.has_operand_reprs) << ','
        << bool_string(record.metadata.has_operand_reprs_ex);

    if (g_opts.show_function_bytes)
        out << ',' << record.function_bytes_len
            << ',' << csv_escape(record.function_byte_chunks)
            << ',' << csv_escape(record.function_bytes_hex);

    out << ','
        << csv_escape(format_md5(summary.input_md5)) << ','
        << csv_escape(summary.input_path)
        << '\n';
}

static void emit_csv(std::ostream &out, const AnalysisSummary &summary, const std::vector<FunctionRecord> &records)
{
    out << "ea,rva,segment,function_size,lumina_md5,db_name,lumina_name,demangled_name,metadata_bytes,metadata_keys,has_type,has_function_comment,has_repeatable_function_comment,has_insn_comments,has_insn_repeatable_comments,has_extra_comments,has_user_stack_points,has_frame_desc,has_operand_reprs,has_operand_reprs_ex";
    if (g_opts.show_function_bytes)
        out << ",function_bytes_len,function_byte_chunks,function_bytes_hex";
    out << ",input_md5,input_path\n";
    for (const FunctionRecord &record : records)
        write_csv_row(out, summary, record);
}

static void emit_text(std::ostream &out, const AnalysisSummary &summary, const std::vector<FunctionRecord> &records)
{
    out << CLR(Bold) << "Lumina Metadata Debug" << CLR(Reset) << "\n";
    out << std::string(72, '-') << "\n";
    out << "Input:          " << summary.input_path << "\n";
    out << "Input MD5:      " << format_md5(summary.input_md5) << "\n";
    out << "Imagebase:      " << format_ea(summary.imagebase) << "\n";
    out << "Functions:      " << summary.matched_functions << " matched / " << summary.total_functions << " total\n";
    out << "With metadata:  " << summary.metadata_functions << "\n";
    out << "With types:     " << summary.typed_functions << "\n";
    out << std::string(72, '-') << "\n";

    for (const FunctionRecord &record : records)
    {
        std::string name = !record.lumina_name.empty() ? record.lumina_name : record.db_name;
        std::string metadata_keys = join_strings(record.metadata.keys, "|");

        out << format_ea(record.ea)
            << "  rva=" << format_rva(record.ea, record.imagebase)
            << "  md5=" << format_md5(record.md5)
            << "  size=" << record.function_size
            << "  segment=" << (record.segment.empty() ? "?" : record.segment)
            << "  name=" << (name.empty() ? "<unnamed>" : name)
            << "\n";

        bool needs_detail = g_opts.verbose
                         || !record.demangled_name.empty()
                         || record.db_name != record.lumina_name;

        if (needs_detail)
        {
            out << "  db_name=" << (record.db_name.empty() ? "<unnamed>" : record.db_name);
            if (!record.lumina_name.empty())
                out << "  lumina_name=" << record.lumina_name;
            if (!record.demangled_name.empty())
                out << "  demangled=" << record.demangled_name;
            out << "\n";
        }

        out << "  metadata_bytes=" << record.metadata.metadata_bytes
            << "  keys=" << (metadata_keys.empty() ? "-" : metadata_keys)
            << "\n";

        out << "  has_type=" << bool_string(record.metadata.has_type)
            << "  func_cmt=" << bool_string(record.metadata.has_function_comment)
            << "  func_rptcmt=" << bool_string(record.metadata.has_repeatable_function_comment)
            << "  insn_cmts=" << bool_string(record.metadata.has_insn_comments)
            << "  rpt_cmts=" << bool_string(record.metadata.has_insn_repeatable_comments)
            << "  extra_cmts=" << bool_string(record.metadata.has_extra_comments)
            << "  stkpnts=" << bool_string(record.metadata.has_user_stack_points)
            << "  frame_desc=" << bool_string(record.metadata.has_frame_desc)
            << "  opreprs=" << bool_string(record.metadata.has_operand_reprs)
            << "  opreprs_ex=" << bool_string(record.metadata.has_operand_reprs_ex)
            << "\n";

        if (g_opts.show_function_bytes)
        {
            out << "  bytes_len=" << record.function_bytes_len
                << "  byte_chunks=" << (record.function_byte_chunks.empty() ? "-" : record.function_byte_chunks)
                << "\n";
            out << "  bytes_hex=" << (record.function_bytes_hex.empty() ? "-" : record.function_bytes_hex) << "\n";
        }
    }
}

//=============================================================================
// Resource Management
//=============================================================================

class HeadlessIdaContext
{
public:
    explicit HeadlessIdaContext(const char *input_file)
    {
        if (g_opts.no_plugins)
        {
#ifndef _WIN32
            const char *idadir_env = real_getenv("IDADIR");
            const char *home = real_getenv("HOME");

            std::string detected_idadir;
            if (idadir_env == nullptr)
            {
                void *libida_sym = dlsym(RTLD_DEFAULT, "qalloc");
                Dl_info dli;
                if (libida_sym != nullptr && dladdr(libida_sym, &dli) != 0 && dli.dli_fname != nullptr)
                {
                    std::string libida_path(dli.dli_fname);
                    size_t slash = libida_path.rfind('/');
                    if (slash != std::string::npos)
                        detected_idadir = libida_path.substr(0, slash);
                }
            }

            const char *idadir = idadir_env != nullptr ? idadir_env : (detected_idadir.empty() ? nullptr : detected_idadir.c_str());

            if (idadir != nullptr && home != nullptr)
            {
                std::string real_idadir = idadir;
                m_fake_idadir_base = "/tmp/.ida_no_plugins_" + std::to_string(getpid());
                std::string fake_idadir = m_fake_idadir_base + "/ida";

                mkdir(m_fake_idadir_base.c_str(), 0755);
                mkdir(fake_idadir.c_str(), 0755);

                DIR *dir = opendir(real_idadir.c_str());
                if (dir != nullptr)
                {
                    struct dirent *entry;
                    while ((entry = readdir(dir)) != nullptr)
                    {
                        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
                            continue;
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

                auto symlink_user_dir_unique = [&](const char *subdir) {
                    std::string user_dir = real_idausr + "/" + subdir;
                    std::string fake_dir = fake_idausr + "/" + subdir;
                    std::string sys_dir = real_idadir + "/" + subdir;
                    mkdir(fake_dir.c_str(), 0755);
                    DIR *d = opendir(user_dir.c_str());
                    if (d == nullptr)
                        return;

                    struct dirent *e;
                    while ((e = readdir(d)) != nullptr)
                    {
                        if (e->d_name[0] == '.')
                            continue;

                        std::string sys_path = sys_dir + "/" + e->d_name;
                        struct stat st;
                        if (stat(sys_path.c_str(), &st) == 0)
                            continue;

                        std::string src = user_dir + "/" + e->d_name;
                        std::string dst = fake_dir + "/" + e->d_name;
                        symlink(src.c_str(), dst.c_str());
                    }
                    closedir(d);
                };

                DIR *udir = opendir(real_idausr.c_str());
                if (udir != nullptr)
                {
                    struct dirent *uentry;
                    while ((uentry = readdir(udir)) != nullptr)
                    {
                        if (strcmp(uentry->d_name, ".") == 0
                         || strcmp(uentry->d_name, "..") == 0
                         || strcmp(uentry->d_name, "plugins") == 0
                         || strcmp(uentry->d_name, "procs") == 0
                         || strcmp(uentry->d_name, "loaders") == 0)
                        {
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
                DIR *pdir = opendir(real_user_plugins.c_str());
                if (pdir != nullptr)
                {
                    struct dirent *pentry;
                    while ((pentry = readdir(pdir)) != nullptr)
                    {
                        for (const std::string &pattern : g_opts.plugin_patterns)
                        {
                            if (strstr(pentry->d_name, pattern.c_str()) != nullptr)
                            {
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

        if (init_library() != 0)
            throw std::runtime_error("Failed to initialize IDA library.");

        enable_console_messages(!g_opts.quiet);

        if (open_database(input_file, true) != 0)
            throw std::runtime_error(std::string("Failed to open: ") + input_file);

        if (!g_opts.quiet)
            std::cerr << "[*] Waiting for auto-analysis..." << std::endl;
        auto_wait();
        if (!g_opts.quiet)
            std::cerr << "[*] Analysis complete." << std::endl;

        if (init_hexrays_plugin())
            m_hexrays_available = true;
    }

    ~HeadlessIdaContext()
    {
        if (m_hexrays_available)
            term_hexrays_plugin();

        set_database_flag(DBFL_KILL);
        term_database();

        if (!m_fake_idadir_base.empty())
        {
            std::error_code ec;
            std::filesystem::remove_all(m_fake_idadir_base, ec);
        }
    }

    HeadlessIdaContext(const HeadlessIdaContext &) = delete;
    HeadlessIdaContext &operator=(const HeadlessIdaContext &) = delete;

private:
    bool m_hexrays_available = false;
    std::string m_fake_idadir_base;
};

//=============================================================================
// Usage
//=============================================================================

static void print_usage(const char *prog)
{
    std::cout << CLR(Bold) << "IDA Pro Lumina Metadata Debug Tool" << CLR(Reset) << "\n\n";
    std::cout << CLR(Cyan) << "Usage:" << CLR(Reset) << " " << prog << " [options] <binary_file>\n\n";
    std::cout << CLR(Cyan) << "Description:" << CLR(Reset) << "\n";
    std::cout << "  Analyze a binary and dump per-function Lumina hashes, RVAs/EAs, and\n";
    std::cout << "  summarized symbol metadata derived from calc_func_metadata().\n\n";
    std::cout << CLR(Cyan) << "Options:" << CLR(Reset) << "\n";
    std::cout << "  --csv                Emit CSV instead of human-readable text\n";
    std::cout << "  --bytes              Include hex-encoded function bytes, byte length,\n";
    std::cout << "                       and chunk ranges from IDA\n";
    std::cout << "  -o, --output <file>  Write output to a file\n";
    std::cout << "  -f, --filter <pat>   Filter functions by name (regex or substring)\n";
    std::cout << "  -F, --functions <l>  Comma or pipe-separated function names/addresses\n";
    std::cout << "  -a, --address <hex>  Dump only the function at the given address\n";
    std::cout << "  -q, --quiet          Suppress IDA console messages\n";
    std::cout << "  -v, --verbose        Show extra name detail in text mode\n";
    std::cout << "  --no-color           Disable colored headings\n";
    std::cout << "  --no-plugins         Don't load user plugins\n";
    std::cout << "  --plugin <pattern>   Load matching plugins only (implies --no-plugins)\n";
    std::cout << "  -h, --help           Show this help\n\n";
    std::cout << CLR(Cyan) << "Examples:" << CLR(Reset) << "\n";
    std::cout << "  " << prog << " sample.exe\n";
    std::cout << "  " << prog << " --csv sample.exe\n";
    std::cout << "  " << prog << " --bytes sample.exe\n";
    std::cout << "  " << prog << " --csv -o lumina.csv sample.exe\n";
    std::cout << "  " << prog << " -f main sample.exe\n";
    std::cout << "  " << prog << " -F \"main,0x140001000\" sample.exe\n";
}

static bool parse_args(int argc, char *argv[])
{
    for (int i = 1; i < argc; ++i)
    {
        std::string arg = argv[i];

        if (arg == "-h" || arg == "--help")
        {
            print_usage(argv[0]);
            exit(0);
        }
        else if (arg == "--csv")
        {
            g_opts.csv_output = true;
        }
        else if (arg == "--bytes" || arg == "--function-bytes")
        {
            g_opts.show_function_bytes = true;
        }
        else if (arg == "-o" || arg == "--output")
        {
            if (i + 1 >= argc)
            {
                std::cerr << "Error: " << arg << " requires a file path\n";
                return false;
            }
            g_opts.output_file = argv[++i];
        }
        else if (arg == "-f" || arg == "--filter")
        {
            if (i + 1 >= argc)
            {
                std::cerr << "Error: " << arg << " requires a pattern\n";
                return false;
            }
            g_opts.filter_pattern = argv[++i];
        }
        else if (arg == "-F" || arg == "--functions")
        {
            if (i + 1 >= argc)
            {
                std::cerr << "Error: " << arg << " requires a function list\n";
                return false;
            }
            std::vector<std::string> items = split_string(argv[++i]);
            g_opts.function_list.insert(g_opts.function_list.end(), items.begin(), items.end());
        }
        else if (arg == "-a" || arg == "--address")
        {
            if (i + 1 >= argc)
            {
                std::cerr << "Error: " << arg << " requires an address\n";
                return false;
            }
            g_opts.filter_address = parse_address(argv[++i]);
            if (g_opts.filter_address == BADADDR)
            {
                std::cerr << "Error: invalid address\n";
                return false;
            }
        }
        else if (arg == "-q" || arg == "--quiet")
        {
            g_opts.quiet = true;
        }
        else if (arg == "-v" || arg == "--verbose")
        {
            g_opts.verbose = true;
        }
        else if (arg == "--no-color")
        {
            Color::disable();
        }
        else if (arg == "--no-plugins")
        {
            g_opts.no_plugins = true;
        }
        else if (arg == "--plugin")
        {
            if (i + 1 >= argc)
            {
                std::cerr << "Error: --plugin requires a pattern\n";
                return false;
            }
            g_opts.plugin_patterns.push_back(argv[++i]);
            g_opts.no_plugins = true;
        }
        else if (!arg.empty() && arg[0] == '-')
        {
            std::cerr << "Unknown option: " << arg << "\n";
            return false;
        }
        else
        {
            if (!g_opts.input_file.empty())
            {
                std::cerr << "Error: Multiple input files specified\n";
                return false;
            }
            g_opts.input_file = arg;
        }
    }

    if (g_opts.input_file.empty())
    {
        std::cerr << "Error: No input file specified\n";
        return false;
    }

    if (g_opts.csv_output && g_opts.output_file.empty())
        g_opts.quiet = true;

    if (g_opts.csv_output || !g_opts.output_file.empty())
        Color::disable();

    return true;
}

//=============================================================================
// Main
//=============================================================================

int main(int argc, char *argv[])
{
    if (!parse_args(argc, argv))
    {
        std::cerr << "Use --help for usage information\n";
        return EXIT_FAILURE;
    }

    std::unique_ptr<std::ofstream> output_file;
    if (!g_opts.output_file.empty())
    {
        output_file = std::make_unique<std::ofstream>(g_opts.output_file, std::ios::out | std::ios::trunc);
        if (!output_file->is_open())
        {
            std::cerr << CLR(Red) << "[FATAL] " << CLR(Reset) << "Failed to open output file: " << g_opts.output_file << "\n";
            return EXIT_FAILURE;
        }
        g_output = output_file.get();
    }

    try
    {
        HeadlessIdaContext ctx(g_opts.input_file.c_str());

        AnalysisSummary summary;
        std::vector<FunctionRecord> records = collect_records(summary);

        if (g_opts.csv_output)
            emit_csv(*g_output, summary, records);
        else
            emit_text(*g_output, summary, records);

        if (!g_opts.quiet)
        {
            std::cerr << CLR(Green) << "[+] " << CLR(Reset)
                      << "Collected " << records.size() << " function record(s)"
                      << (g_opts.output_file.empty() ? "" : " into " + g_opts.output_file)
                      << std::endl;
        }
    }
    catch (const std::exception &e)
    {
        std::cerr << CLR(Red) << "[FATAL] " << CLR(Reset) << e.what() << std::endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
