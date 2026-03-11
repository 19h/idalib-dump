/**
 * IDA Pro Lumina Metadata Debug Tool
 *
 * Analyzes a binary and dumps per-function Lumina-relevant metadata,
 * including the calculated MD5 hash, EA/RVA, names, and summarized symbol
 * metadata derived through the public SDK APIs in lumina.hpp.
 */

#include <algorithm>
#include <cerrno>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
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
#include <sys/wait.h>
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

#ifndef _WIN32
static inline pid_t real_waitpid(pid_t pid, int *status, int options)
{
    return waitpid(pid, status, options);
}

static inline ssize_t real_read(int fd, void *buf, size_t count)
{
    return read(fd, buf, count);
}

static inline ssize_t real_write(int fd, const void *buf, size_t count)
{
    return write(fd, buf, count);
}

static inline int real_close(int fd)
{
    return close(fd);
}

static inline int real_pipe(int pipefd[2])
{
    return pipe(pipefd);
}

static inline pid_t real_fork()
{
    return fork();
}

static inline void real__exit(int status)
{
    _exit(status);
}
#endif

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
    bool recursive = false;
    bool csv_output = false;
    bool show_function_bytes = false;
    bool show_instruction_calcrel = false;
    bool quiet = false;
    bool no_plugins = false;
    bool verbose = false;
    unsigned int jobs = 0;
    bool jobs_specified = false;
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

static std::string bytes_to_hex(const uchar *data, size_t size)
{
    std::string out;
    out.reserve(size * 2);
    for (size_t i = 0; i < size; ++i)
        append_hex_byte(out, data[i]);
    return out;
}

static std::string relbits_to_hex(const bytevec_t &bits)
{
    if (bits.empty())
        return "";
    return bytes_to_hex(bits.begin(), bits.size());
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

struct InstructionCalcRelRecord
{
    ea_t ea = BADADDR;
    size_t size = 0;
    std::string bytes_hex;
    std::string relbits_hex;
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
    std::vector<InstructionCalcRelRecord> instruction_calcrel;
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

struct FileRunResult
{
    AnalysisSummary summary;
    size_t record_count = 0;
};

#ifndef _WIN32
constexpr size_t CHILD_ERROR_MESSAGE_SIZE = 512;

struct ChildRunHeader
{
    uint64_t total_functions = 0;
    uint64_t matched_functions = 0;
    uint64_t metadata_functions = 0;
    uint64_t typed_functions = 0;
    uint64_t record_count = 0;
    uint64_t output_size = 0;
    uint8_t success = 0;
    char error_message[CHILD_ERROR_MESSAGE_SIZE] = {};
};

struct WorkerProcess
{
    pid_t pid = -1;
    int read_fd = -1;
    std::string input_file;
};

struct BatchRunStats
{
    size_t files_total = 0;
    size_t files_succeeded = 0;
    size_t files_failed = 0;
    size_t total_functions = 0;
    size_t matched_functions = 0;
    size_t metadata_functions = 0;
    size_t typed_functions = 0;
    size_t record_count = 0;
};
#endif

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

static std::vector<InstructionCalcRelRecord> get_instruction_calcrel_info(const func_t *pfn)
{
    std::vector<InstructionCalcRelRecord> records;
    if (pfn == nullptr)
        return records;

    func_item_iterator_t item_iter;
    for (bool ok = item_iter.set(const_cast<func_t *>(pfn)); ok; ok = item_iter.next_head())
    {
        ea_t ea = item_iter.current();
        flags64_t flags = get_flags(ea);
        if (!is_code(flags))
            continue;

        bytevec_t relbits;
        size_t consumed = 0;
        ssize_t status = processor_t::calcrel(&relbits, &consumed, ea);
        if (consumed == 0 || status < 0)
            continue;

        qvector<uchar> bytes;
        bytes.resize(consumed);
        ssize_t read_size = get_bytes(bytes.begin(), static_cast<ssize_t>(consumed), ea, GMB_READALL);
        if (read_size < 0)
            throw std::runtime_error("Cancelled while reading instruction bytes for " + format_ea(ea));
        if (read_size == 0)
            continue;

        InstructionCalcRelRecord record;
        record.ea = ea;
        record.size = consumed;
        record.bytes_hex = bytes_to_hex(bytes.begin(), static_cast<size_t>(read_size));
        record.relbits_hex = relbits_to_hex(relbits);
        records.push_back(std::move(record));
    }

    return records;
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

    if (g_opts.show_instruction_calcrel)
        record.instruction_calcrel = get_instruction_calcrel_info(pfn);

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
    std::string instruction_calcrel;
    if (g_opts.show_instruction_calcrel)
    {
        std::ostringstream oss;
        for (size_t i = 0; i < record.instruction_calcrel.size(); ++i)
        {
            if (i != 0)
                oss << '|';
            const InstructionCalcRelRecord &insn = record.instruction_calcrel[i];
            oss << format_ea(insn.ea)
                << ':' << insn.size
                << ':' << insn.bytes_hex
                << ':' << insn.relbits_hex;
        }
        instruction_calcrel = oss.str();
    }

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

    if (g_opts.show_instruction_calcrel)
        out << ',' << csv_escape(instruction_calcrel);

    out << ','
        << csv_escape(format_md5(summary.input_md5)) << ','
        << csv_escape(summary.input_path)
        << '\n';
}

static void emit_csv_header(std::ostream &out)
{
    out << "ea,rva,segment,function_size,lumina_md5,db_name,lumina_name,demangled_name,metadata_bytes,metadata_keys,has_type,has_function_comment,has_repeatable_function_comment,has_insn_comments,has_insn_repeatable_comments,has_extra_comments,has_user_stack_points,has_frame_desc,has_operand_reprs,has_operand_reprs_ex";
    if (g_opts.show_function_bytes)
        out << ",function_bytes_len,function_byte_chunks,function_bytes_hex";
    if (g_opts.show_instruction_calcrel)
        out << ",instruction_calcrel";
    out << ",input_md5,input_path\n";
}

static void emit_csv(std::ostream &out, const AnalysisSummary &summary, const std::vector<FunctionRecord> &records, bool include_header = true)
{
    if (include_header)
        emit_csv_header(out);

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

        if (g_opts.show_instruction_calcrel)
        {
            out << "  calcrel_instructions=" << record.instruction_calcrel.size() << "\n";
            for (const InstructionCalcRelRecord &insn : record.instruction_calcrel)
            {
                out << "    " << format_ea(insn.ea)
                    << " size=" << insn.size
                    << " bytes=" << (insn.bytes_hex.empty() ? "-" : insn.bytes_hex)
                    << " relbits=" << (insn.relbits_hex.empty() ? "-" : insn.relbits_hex)
                    << "\n";
            }
        }
    }
}

//=============================================================================
// Resource Management
//=============================================================================

class HeadlessIdaContext
{
public:
    HeadlessIdaContext(const char *input_file, bool quiet_mode)
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

        enable_console_messages(!quiet_mode);

        if (open_database(input_file, true) != 0)
            throw std::runtime_error(std::string("Failed to open: ") + input_file);

        if (!quiet_mode)
            std::cerr << "[*] Waiting for auto-analysis..." << std::endl;
        auto_wait();
        if (!quiet_mode)
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

static unsigned int default_job_count()
{
#ifdef _WIN32
    SYSTEM_INFO info = {};
    GetSystemInfo(&info);
    return info.dwNumberOfProcessors == 0 ? 1u : info.dwNumberOfProcessors;
#else
    long count = sysconf(_SC_NPROCESSORS_ONLN);
    return count > 0 ? static_cast<unsigned int>(count) : 1u;
#endif
}

static bool parse_positive_uint(const std::string &value, unsigned int &parsed)
{
    try
    {
        size_t consumed = 0;
        unsigned long number = std::stoul(value, &consumed, 10);
        if (consumed != value.size()
         || number == 0
         || number > std::numeric_limits<unsigned int>::max())
        {
            return false;
        }

        parsed = static_cast<unsigned int>(number);
        return true;
    }
    catch (...)
    {
        return false;
    }
}

static void emit_records(std::ostream &out, const AnalysisSummary &summary, const std::vector<FunctionRecord> &records, bool include_csv_header)
{
    if (g_opts.csv_output)
        emit_csv(out, summary, records, include_csv_header);
    else
        emit_text(out, summary, records);
}

static FileRunResult run_single_file(std::ostream &out, const std::string &input_file, bool quiet_mode, bool include_csv_header)
{
    HeadlessIdaContext ctx(input_file.c_str(), quiet_mode);

    FileRunResult result;
    std::vector<FunctionRecord> records = collect_records(result.summary);
    result.record_count = records.size();
    emit_records(out, result.summary, records, include_csv_header);
    return result;
}

#ifndef _WIN32
static bool write_full(int fd, const void *data, size_t size)
{
    const uint8_t *ptr = static_cast<const uint8_t *>(data);
    size_t remaining = size;

    while (remaining > 0)
    {
        ssize_t written = real_write(fd, ptr, remaining);
        if (written <= 0)
        {
            if (errno == EINTR)
                continue;
            return false;
        }

        ptr += written;
        remaining -= static_cast<size_t>(written);
    }

    return true;
}

static bool read_full(int fd, void *data, size_t size)
{
    uint8_t *ptr = static_cast<uint8_t *>(data);
    size_t remaining = size;

    while (remaining > 0)
    {
        ssize_t nread = real_read(fd, ptr, remaining);
        if (nread == 0)
            return false;
        if (nread < 0)
        {
            if (errno == EINTR)
                continue;
            return false;
        }

        ptr += nread;
        remaining -= static_cast<size_t>(nread);
    }

    return true;
}

static bool read_string(int fd, size_t size, std::string &out)
{
    out.clear();
    if (size == 0)
        return true;

    out.resize(size);
    return read_full(fd, out.data(), size);
}

static void set_child_error_message(ChildRunHeader &header, const std::string &error_text)
{
    const size_t copy_size = std::min(error_text.size(), sizeof(header.error_message) - 1);
    std::memcpy(header.error_message, error_text.data(), copy_size);
    header.error_message[copy_size] = '\0';
}

static ChildRunHeader make_child_header(const FileRunResult &result, const std::string &rendered_output)
{
    ChildRunHeader header = {};
    header.total_functions = result.summary.total_functions;
    header.matched_functions = result.summary.matched_functions;
    header.metadata_functions = result.summary.metadata_functions;
    header.typed_functions = result.summary.typed_functions;
    header.record_count = result.record_count;
    header.output_size = rendered_output.size();
    header.success = 1;
    return header;
}

static std::string wait_status_message(int status)
{
    if (WIFEXITED(status))
        return "worker exited with status " + std::to_string(WEXITSTATUS(status));
    if (WIFSIGNALED(status))
        return "worker terminated by signal " + std::to_string(WTERMSIG(status));
    return "worker terminated unexpectedly";
}

static std::vector<std::string> collect_recursive_inputs(const std::string &root_dir)
{
    std::filesystem::path root_path(root_dir);
    std::error_code ec;

    if (!std::filesystem::exists(root_path, ec) || ec)
        throw std::runtime_error("Input path does not exist: " + root_dir);
    if (!std::filesystem::is_directory(root_path, ec) || ec)
        throw std::runtime_error("Recursive mode requires a directory input: " + root_dir);

    std::vector<std::string> files;
    const auto options = std::filesystem::directory_options::skip_permission_denied;
    std::filesystem::recursive_directory_iterator end;
    std::filesystem::recursive_directory_iterator it(root_path, options, ec);
    if (ec)
        throw std::runtime_error("Failed to scan directory: " + root_dir + ": " + ec.message());

    for (; it != end; it.increment(ec))
    {
        if (ec)
        {
            ec.clear();
            continue;
        }

        std::error_code status_ec;
        if (it->is_regular_file(status_ec) && !status_ec)
            files.push_back(it->path().string());
    }

    std::sort(files.begin(), files.end());
    return files;
}

static int run_recursive_mode(std::ostream &out)
{
    const std::vector<std::string> files = collect_recursive_inputs(g_opts.input_file);
    if (files.empty())
    {
        std::cerr << CLR(Yellow) << "[!] No regular files found under " << g_opts.input_file << CLR(Reset) << "\n";
        return EXIT_FAILURE;
    }

    const unsigned int requested_jobs = g_opts.jobs_specified ? g_opts.jobs : default_job_count();
    const size_t max_jobs = std::max<size_t>(1, std::min<size_t>(requested_jobs, files.size()));

    if (g_opts.csv_output)
        emit_csv_header(out);

    if (!g_opts.quiet)
    {
        std::cerr << "[*] Found " << files.size() << " files under " << g_opts.input_file
                  << "; running up to " << max_jobs << " worker processes." << std::endl;
    }

    BatchRunStats batch;
    batch.files_total = files.size();

    std::vector<WorkerProcess> running;
    size_t next_index = 0;
    bool scheduling_failed = false;
    std::string scheduling_error;
    bool wrote_text_output = false;

    while ((next_index < files.size() && !scheduling_failed) || !running.empty())
    {
        while (!scheduling_failed && running.size() < max_jobs && next_index < files.size())
        {
            int pipefd[2] = {-1, -1};
            if (real_pipe(pipefd) != 0)
            {
                scheduling_failed = true;
                scheduling_error = std::string("Failed to create worker pipe: ") + std::strerror(errno);
                break;
            }

            out.flush();
            std::cerr.flush();

            const std::string &input_file = files[next_index];
            pid_t pid = real_fork();
            if (pid < 0)
            {
                real_close(pipefd[0]);
                real_close(pipefd[1]);
                scheduling_failed = true;
                scheduling_error = std::string("Failed to fork worker: ") + std::strerror(errno);
                break;
            }

            if (pid == 0)
            {
                real_close(pipefd[0]);

                ChildRunHeader header = {};
                std::string rendered_output;
                int exit_code = EXIT_FAILURE;

                try
                {
                    std::ostringstream child_output;
                    FileRunResult result = run_single_file(child_output, input_file, true, false);
                    rendered_output = child_output.str();
                    header = make_child_header(result, rendered_output);
                    exit_code = EXIT_SUCCESS;
                }
                catch (const std::exception &e)
                {
                    set_child_error_message(header, e.what());
                }

                if (!write_full(pipefd[1], &header, sizeof(header)))
                    exit_code = EXIT_FAILURE;
                if (exit_code == EXIT_SUCCESS && !rendered_output.empty() && !write_full(pipefd[1], rendered_output.data(), rendered_output.size()))
                    exit_code = EXIT_FAILURE;

                real_close(pipefd[1]);
                real__exit(exit_code);
            }

            real_close(pipefd[1]);
            running.push_back(WorkerProcess{pid, pipefd[0], input_file});
            ++next_index;
        }

        if (running.empty())
            break;

        int status = 0;
        pid_t finished_pid = real_waitpid(-1, &status, 0);
        if (finished_pid < 0)
        {
            if (errno == EINTR)
                continue;
            throw std::runtime_error(std::string("waitpid failed: ") + std::strerror(errno));
        }

        auto worker_it = std::find_if(running.begin(), running.end(), [finished_pid](const WorkerProcess &worker) {
            return worker.pid == finished_pid;
        });
        if (worker_it == running.end())
            continue;

        ChildRunHeader header = {};
        const bool received_header = read_full(worker_it->read_fd, &header, sizeof(header));

        std::string rendered_output;
        bool received_output = false;
        if (received_header)
            received_output = read_string(worker_it->read_fd, static_cast<size_t>(header.output_size), rendered_output);

        real_close(worker_it->read_fd);

        std::string error_text;
        if (!received_header)
        {
            error_text = "worker exited without a result header";
        }
        else if (!received_output)
        {
            error_text = "worker exited before sending full output";
        }
        else if (header.error_message[0] != '\0')
        {
            error_text = header.error_message;
        }

        const bool worker_ok = received_header
                            && received_output
                            && WIFEXITED(status)
                            && WEXITSTATUS(status) == EXIT_SUCCESS
                            && header.success != 0;

        if (!worker_ok && error_text.empty())
            error_text = wait_status_message(status);

        if (worker_ok)
        {
            if (!rendered_output.empty())
            {
                if (!g_opts.csv_output && wrote_text_output)
                    out << '\n';
                out << rendered_output;
                wrote_text_output = true;
            }

            batch.files_succeeded++;
            batch.total_functions += static_cast<size_t>(header.total_functions);
            batch.matched_functions += static_cast<size_t>(header.matched_functions);
            batch.metadata_functions += static_cast<size_t>(header.metadata_functions);
            batch.typed_functions += static_cast<size_t>(header.typed_functions);
            batch.record_count += static_cast<size_t>(header.record_count);
        }
        else
        {
            batch.files_failed++;
        }

        if (!g_opts.quiet)
        {
            std::cerr << (worker_ok ? CLR(Green) : CLR(Red))
                      << (worker_ok ? "[+]" : "[-]")
                      << CLR(Reset) << ' ' << worker_it->input_file
                      << "  records=" << header.record_count
                      << " matched=" << header.matched_functions << '/' << header.total_functions
                      << " metadata=" << header.metadata_functions
                      << " types=" << header.typed_functions;
            if (!error_text.empty())
                std::cerr << "  (" << error_text << ')';
            std::cerr << std::endl;
        }

        running.erase(worker_it);
    }

    if (scheduling_failed)
    {
        batch.files_failed += files.size() - next_index;
        std::cerr << CLR(Red) << "[-] " << scheduling_error << CLR(Reset) << std::endl;
    }

    if (!g_opts.quiet)
    {
        std::cerr << CLR(Green) << "[+] " << CLR(Reset)
                  << "Collected " << batch.record_count << " function record(s) across "
                  << batch.files_succeeded << " file(s)"
                  << (g_opts.output_file.empty() ? std::string() : " into " + g_opts.output_file)
                  << std::endl;
        if (batch.files_failed > 0)
        {
            std::cerr << CLR(Yellow) << "[!] " << CLR(Reset)
                      << batch.files_failed << " file(s) failed during recursive analysis" << std::endl;
        }
    }

    return batch.files_failed == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
#endif

static void print_usage(const char *prog)
{
    std::cout << CLR(Bold) << "IDA Pro Lumina Metadata Debug Tool" << CLR(Reset) << "\n\n";
    std::cout << CLR(Cyan) << "Usage:" << CLR(Reset) << " " << prog << " [options] <input_path>\n\n";
    std::cout << CLR(Cyan) << "Description:" << CLR(Reset) << "\n";
    std::cout << "  Analyze a binary and dump per-function Lumina hashes, RVAs/EAs, and\n";
    std::cout << "  summarized symbol metadata derived from calc_func_metadata().\n";
    std::cout << "  With --recursive, scan a directory tree and process files in forked workers.\n\n";
    std::cout << CLR(Cyan) << "Options:" << CLR(Reset) << "\n";
    std::cout << "  --csv                Emit CSV instead of human-readable text\n";
    std::cout << "  --bytes              Include hex-encoded function bytes, byte length,\n";
    std::cout << "                       and chunk ranges from IDA\n";
    std::cout << "  --calcrel-insns      Include per-instruction CalcRel bytes/relbits\n";
    std::cout << "  -o, --output <file>  Write output to a file\n";
    std::cout << "  -f, --filter <pat>   Filter functions by name (regex or substring)\n";
    std::cout << "  -F, --functions <l>  Comma or pipe-separated function names/addresses\n";
    std::cout << "  -a, --address <hex>  Dump only the function at the given address\n";
    std::cout << "  -r, --recursive      Recursively process all files under <input_path>\n";
    std::cout << "  -j, --jobs <count>   Worker processes for --recursive (default: CPU count)\n";
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
    std::cout << "  " << prog << " --calcrel-insns sample.exe\n";
    std::cout << "  " << prog << " --csv -o lumina.csv sample.exe\n";
    std::cout << "  " << prog << " -f main sample.exe\n";
    std::cout << "  " << prog << " -F \"main,0x140001000\" sample.exe\n";
    std::cout << "  " << prog << " -r samples/\n";
    std::cout << "  " << prog << " -r -j 4 --csv -o lumina.csv samples/\n";
#ifdef _WIN32
    std::cout << "\nNote: recursive mode is unavailable on Windows because it requires fork().\n";
#endif
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
        else if (arg == "--calcrel-insns" || arg == "--relbits")
        {
            g_opts.show_instruction_calcrel = true;
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
        else if (arg == "-r" || arg == "--recursive")
        {
            g_opts.recursive = true;
        }
        else if (arg == "-j" || arg == "--jobs")
        {
            if (i + 1 >= argc)
            {
                std::cerr << "Error: " << arg << " requires a count\n";
                return false;
            }

            unsigned int jobs = 0;
            if (!parse_positive_uint(argv[++i], jobs))
            {
                std::cerr << "Error: --jobs expects a positive integer\n";
                return false;
            }

            g_opts.jobs = jobs;
            g_opts.jobs_specified = true;
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

    if (g_opts.jobs_specified && !g_opts.recursive)
    {
        std::cerr << "Error: --jobs requires --recursive\n";
        return false;
    }

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

    std::error_code input_ec;
    if (!g_opts.recursive && std::filesystem::is_directory(g_opts.input_file, input_ec) && !input_ec)
    {
        std::cerr << "Error: " << g_opts.input_file << " is a directory; use --recursive to process folders\n";
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
        if (g_opts.recursive)
        {
#ifdef _WIN32
            throw std::runtime_error("Recursive mode is not supported on Windows because ida_lumina_debug uses fork() workers.");
#else
            return run_recursive_mode(*g_output);
#endif
        }

        FileRunResult result = run_single_file(*g_output, g_opts.input_file, g_opts.quiet, true);

        if (!g_opts.quiet)
        {
            std::cerr << CLR(Green) << "[+] " << CLR(Reset)
                      << "Collected " << result.record_count << " function record(s)"
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
