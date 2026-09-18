/*
 * Magic-byte binary classification for the --type filter.
 *
 * The slugs below mirror the loaders shipped in ida/ldr and ida/sdk/src/ldr,
 * so `--type <slug>` selects the same files IDA's corresponding loader would
 * accept. Detection is deliberately header-only and seek-light: it must be
 * cheap enough to run over a whole corpus before any worker is spawned, so it
 * reproduces each loader's magic check but not its full structural validation.
 *
 * Loaders whose accept_file() is a content heuristic rather than a magic test
 * cannot be classified this way and land in "unknown": autoproc, bochsrc,
 * dump (hex text dumps), exp (Phar Lap), hexagon_mbn, omf166, qnx (LMF), rt11,
 * sbn, snes, vcsample, and the scripted loaders that scan for code patterns
 * (bios_image, clemency, cortex_m, dsp_lod, esp, gas_d, pdfldr's embedded
 * streams, wince).
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <algorithm>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

namespace ftdetect {

//--------------------------------------------------------------------------
// The slugs accepted by --type, in the order the usage text lists them.
inline const std::vector<std::string> &known_types() {
  static const std::vector<std::string> types = {
    // mainstream executables
    "pe", "elf", "mach-o", "coff", "exe", "ne", "lx", "le", "w32run", "dsc",
    // consoles and embedded targets
    "xex", "xbe", "psx", "psxobj", "n64", "spc", "prc", "epoc", "geos",
    // bytecode and container formats
    "dex", "vdex", "java", "wasm",
    // classic Unix / RISC workstation formats
    "aout", "aif", "aof", "amiga", "pef", "hpsom", "nlm", "os9", "osk",
    // object and library formats
    "omf", "intelomf", "mas", "is5x", "tmobj",
    // archives, images and dumps
    "ar", "aixar", "zip", "tar", "uimage", "bflt", "md1img", "pdf", "windmp",
    // textual ROM images
    "ihex", "mhex", "srec",
    "unknown",
  };
  return types;
}

//--------------------------------------------------------------------------
inline std::string to_lower_copy(std::string value) {
  std::transform(value.begin(), value.end(), value.begin(),
                 [](unsigned char c) { return static_cast<char>(::tolower(c)); });
  return value;
}

// Accept the spellings people actually type for a format.
inline std::string normalize_type(std::string value) {
  value = to_lower_copy(std::move(value));
  struct alias_t { const char *from; const char *to; };
  static const alias_t aliases[] = {
    { "mach",          "mach-o" }, { "macho",        "mach-o" },
    { "mach_o",        "mach-o" }, { "macho-fat",    "mach-o" },
    { "dos",           "exe"    }, { "mz",           "exe"    },
    { "xbox360",       "xex"    }, { "x360",         "xex"    },
    { "xex2",          "xex"    }, { "xbox",         "xbe"    },
    { "xbeh",          "xbe"    },
    { "dyld",          "dsc"    }, { "dyldcache",    "dsc"    },
    { "shared-cache",  "dsc"    },
    { "class",         "java"   }, { "javaclass",    "java"   },
    { "som",           "hpsom"  }, { "hp-ux",        "hpsom"  },
    { "snes-spc",      "spc"    }, { "spc700",       "spc"    },
    { "palm",          "prc"    }, { "pilot",        "prc"    },
    { "symbian",       "epoc"   },
    { "minidump",      "windmp" }, { "dmp",          "windmp" },
    { "hex",           "ihex"   }, { "intelhex",     "ihex"   },
    { "s-record",      "srec"   }, { "motorola",     "srec"   },
    { "z64",           "n64"    }, { "hunk",         "amiga"  },
    { "netware",       "nlm"    }, { "webassembly",  "wasm"   },
    { "arm-aif",       "aif"    }, { "arm-aof",      "aof"    },
  };
  for (const alias_t &alias : aliases) {
    if (value == alias.from) {
      return alias.to;
    }
  }
  return value;
}

inline bool is_valid_type(const std::string &value) {
  const std::vector<std::string> &types = known_types();
  return std::find(types.begin(), types.end(), value) != types.end();
}

// Comma-free, wrapped listing for --help.
inline std::string types_help_text(const char *indent) {
  std::string out;
  std::string line;
  for (const std::string &type : known_types()) {
    const std::string piece = line.empty() ? type : ", " + type;
    if (line.size() + piece.size() > 62) {
      out += (out.empty() ? "" : std::string("\n") + indent) + line + ",";
      line = type;
    }
    else {
      line += piece;
    }
  }
  out += (out.empty() ? "" : std::string("\n") + indent) + line;
  return out;
}

//--------------------------------------------------------------------------
namespace detail {

inline uint16_t rd16le(const uint8_t *p) {
  return static_cast<uint16_t>(p[0] | (p[1] << 8));
}
inline uint16_t rd16be(const uint8_t *p) {
  return static_cast<uint16_t>((p[0] << 8) | p[1]);
}
inline uint32_t rd32le(const uint8_t *p) {
  return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8)
       | (static_cast<uint32_t>(p[2]) << 16) | (static_cast<uint32_t>(p[3]) << 24);
}
inline uint32_t rd32be(const uint8_t *p) {
  return (static_cast<uint32_t>(p[0]) << 24) | (static_cast<uint32_t>(p[1]) << 16)
       | (static_cast<uint32_t>(p[2]) << 8) | static_cast<uint32_t>(p[3]);
}

// A file prefix plus the ability to fetch a header the prefix does not cover
// (the PE/NE/LX signature and the Watcom header both live at a file offset
// taken from the MZ header).
struct probe_t {
  std::vector<uint8_t> buf;
  uint64_t size = 0;
  std::ifstream file;

  size_t n() const { return buf.size(); }
  bool has(size_t off, size_t len) const { return off + len <= buf.size(); }
  const uint8_t *at(size_t off) const { return buf.data() + off; }

  bool eq(size_t off, const char *lit, size_t len) const {
    return has(off, len) && memcmp(buf.data() + off, lit, len) == 0;
  }

  // Read 'len' bytes at an arbitrary offset; returns false past EOF.
  bool read_at(uint64_t off, void *out, size_t len) {
    if (off + len > size) {
      return false;
    }
    file.clear();
    file.seekg(static_cast<std::streamoff>(off), std::ios::beg);
    return static_cast<bool>(file.read(reinterpret_cast<char *>(out),
                                       static_cast<std::streamsize>(len)));
  }
};

//--------------------------------------------------------------------------
// ldr/pe, ldr/ne, ldr/lx and sdk/src/ldr/w32run all start from an MZ stub and
// differ only in the extended header they point at.
inline std::string classify_mz(probe_t &p) {
  if (!p.has(0x40, 0)) {
    return "exe";
  }
  const uint32_t lfanew = rd32le(p.at(0x3c));
  uint8_t sig[4] = {};
  if (rd16le(p.at(0x18)) >= 0x40 && p.read_at(lfanew, sig, sizeof(sig))) {
    if (sig[0] == 'P' && sig[1] == 'E' && sig[2] == 0 && sig[3] == 0) {
      return "pe";
    }
    if (sig[0] == 'N' && sig[1] == 'E') {
      return "ne";
    }
    if (sig[0] == 'L' && sig[1] == 'X') {
      return "lx";
    }
    if (sig[0] == 'L' && sig[1] == 'E') {
      return "le";
    }
  }

  // Watcom DOS/32: the w32_hdr sits at paragraph offset e_cparhdr.
  const uint64_t w32_off = static_cast<uint64_t>(rd16le(p.at(0x08))) * 16;
  uint8_t ident[2] = {};
  if (w32_off != 0 && p.read_at(w32_off, ident, sizeof(ident))
      && ident[0] == 'C' && ident[1] == 'F') {
    return "w32run";
  }

  return "exe";
}

//--------------------------------------------------------------------------
// Mach-O fat and Java .class share the 0xCAFEBABE magic. A fat header follows
// it with nfat_arch (a small big-endian count); a class file follows it with
// minor/major version, where major is at least 45 (JDK 1.0).
inline bool looks_like_java_class(const probe_t &p) {
  if (!p.has(0, 8)) {
    return false;
  }
  const uint32_t nfat_arch = rd32be(p.at(4));
  if (nfat_arch >= 1 && nfat_arch <= 0x20) {
    return false;  // plausible fat binary
  }
  const uint16_t major = rd16be(p.at(6));
  return major >= 45 && major <= 0xFF;
}

//--------------------------------------------------------------------------
// ldr/coff accepts a file whose 16-bit machine id is in its table. The id
// space is dense and overlaps ordinary data, so require a sane file header
// (20 bytes: magic, nscns, timdat, symptr, nsyms, opthdr, flags) as well.
inline bool looks_like_coff(const probe_t &p, uint64_t base) {
  static const uint16_t machines[] = {
    0x0088, 0x0089, 0x0092, 0x0093, 0x00C1, 0x00C2, 0x0101, 0x0105, 0x0107,
    0x0108, 0x0109, 0x011F, 0x0140, 0x0142, 0x0143, 0x0144, 0x0145, 0x0146,
    0x0147, 0x0148, 0x0149, 0x014A, 0x014C, 0x014D, 0x014E, 0x014F, 0x0150,
    0x0151, 0x0152, 0x0154, 0x0155, 0x0158, 0x0159, 0x015A, 0x015B, 0x015C,
    0x015D, 0x0160, 0x0161, 0x0162, 0x0163, 0x0164, 0x0165, 0x0166, 0x0168,
    0x0169, 0x0170, 0x0171, 0x0172, 0x0175, 0x0178, 0x017D, 0x0183, 0x0184,
    0x0185, 0x0198, 0x019D, 0x019F, 0x01A2, 0x01A3, 0x01A6, 0x01A8, 0x01C0,
    0x01C2, 0x01C4, 0x01D8, 0x01DD, 0x01DF, 0x01E7, 0x01EF, 0x01F0, 0x01F1,
    0x01F2, 0x01F7, 0x0200, 0x0500, 0x0550, 0x0A00, 0x0C13, 0x0EBC, 0x521C,
    0x8000, 0x8001, 0x808C, 0x8180, 0x8300, 0x8301, 0x8302, 0x8380, 0x8462,
    0x8500, 0x8664, 0x8C00, 0x8C25, 0x8C50, 0x8E00, 0xA641, 0xAA64,
  };

  if (!p.has(static_cast<size_t>(base), 20)) {
    return false;
  }
  const uint8_t *h = p.at(static_cast<size_t>(base));
  for (int msb = 0; msb < 2; ++msb) {
    const uint16_t magic = msb ? rd16be(h) : rd16le(h);
    bool known = false;
    for (uint16_t candidate : machines) {
      known = known || magic == candidate;
    }
    if (!known) {
      continue;
    }

    // The same sanity rules coffcmn.cpp's sane_filhdr()/chk_fhdr_fields()
    // apply: the section table must fit in the file, and the symbol table
    // must either be absent or sit past the section table.
    const uint16_t nscns = msb ? rd16be(h + 2) : rd16le(h + 2);
    const uint32_t symptr = msb ? rd32be(h + 8) : rd32le(h + 8);
    const uint32_t nsyms = msb ? rd32be(h + 12) : rd32le(h + 12);
    const uint16_t opthdr = msb ? rd16be(h + 16) : rd16le(h + 16);
    const uint64_t hdrsize = base + 20 + opthdr;
    const uint64_t sectab_end = hdrsize + static_cast<uint64_t>(nscns) * 40;

    if (nscns == 0 || nscns >= 0xFF00 || hdrsize >= p.size) {
      continue;
    }
    if (nscns >= (p.size - hdrsize) / 40) {
      continue;
    }
    if (nsyms == 0) {
      if (symptr == 0) {
        return true;
      }
      continue;
    }
    if (symptr >= sectab_end && symptr < p.size
        && nsyms <= (p.size - symptr) / 18) {
      return true;
    }
  }
  return false;
}

//--------------------------------------------------------------------------
// sdk/src/ldr/aout: a_midmag packs flags, machine type and the magic word.
inline bool looks_like_aout(const probe_t &p) {
  if (!p.has(0, 32)) {
    return false;
  }
  for (int msb = 0; msb < 2; ++msb) {
    const uint32_t midmag = msb ? rd32be(p.at(0)) : rd32le(p.at(0));
    const uint16_t magic = static_cast<uint16_t>(midmag & 0xFFFF);
    const uint32_t mid = (midmag >> 16) & 0x03FF;
    const bool known_magic = magic == 0407 || magic == 0410 || magic == 0413
                          || magic == 0314 || magic == 0421;
    if (known_magic && mid <= 200) {
      return true;
    }
  }
  return false;
}

//--------------------------------------------------------------------------
// sdk/src/ldr/aif: the header ends with a fixed 15-word zero-init routine.
inline bool looks_like_aif(const probe_t &p) {
  static const uint32_t zero_code1[15] = {
    0xE04EC00F, 0xE08FC00C, 0xE99C000F, 0xE24CC010, 0xE59C2030,
    0xE3120C01, 0x159CC034, 0x008CC000, 0xE08CC001, 0xE3A00000,
    0xE3530000, 0xD1A0F00E, 0xE48C0004, 0xE2533004, 0xEAFFFFFB,
  };
  static const uint32_t zero_code2[15] = {
    0xE04EC00F, 0xE08FC00C, 0xE99C0017, 0xE24CC010, 0xE08CC000,
    0xE08CC001, 0xE3A00000, 0xE3A01000, 0xE3A02000, 0xE3A03000,
    0xE3540000, 0xD1A0F00E, 0xE8AC000F, 0xE2544010, 0xEAFFFFFB,
  };
  static const uint32_t *const codes[] = { zero_code1, zero_code2 };

  const size_t off = 18 * sizeof(uint32_t);  // fields preceding zero_code[]
  if (!p.has(off, sizeof(zero_code1))) {
    return false;
  }
  for (const uint32_t *code : codes) {
    for (int msb = 0; msb < 2; ++msb) {
      bool match = true;
      for (int i = 0; i < 15 && match; ++i) {
        const uint8_t *w = p.at(off + i * 4);
        match = (msb ? rd32be(w) : rd32le(w)) == code[i];
      }
      if (match) {
        return true;
      }
    }
  }
  return false;
}

//--------------------------------------------------------------------------
// sdk/src/ldr/hpsom: system_id and a_magic, both big-endian.
inline bool looks_like_hpsom(const probe_t &p) {
  if (!p.has(0, 4)) {
    return false;
  }
  const uint16_t system_id = rd16be(p.at(0));
  const uint16_t a_magic = rd16be(p.at(2));
  if (system_id != 0x20B && system_id != 0x210 && system_id != 0x214) {
    return false;
  }
  return a_magic == 0x104 || a_magic == 0x106 || a_magic == 0x107
      || a_magic == 0x108 || a_magic == 0x10B || a_magic == 0x10D
      || a_magic == 0x10E || a_magic == 0x619;
}

//--------------------------------------------------------------------------
// sdk/src/ldr/pilot: a Palm resource database. No magic, so lean on the
// structural invariants is_prc_file() checks.
inline bool looks_like_prc(const probe_t &p) {
  if (!p.has(0, 78)) {
    return false;
  }
  // The 32-byte name is NUL-terminated; requiring the terminator is what keeps
  // ordinary text files out.
  size_t name_len = 32;
  for (size_t i = 0; i < 32; ++i) {
    const uint8_t c = *p.at(i);
    if (c == 0) {
      name_len = i;
      break;
    }
    if (c < 0x20 || c >= 0x7F) {
      return false;
    }
  }
  if (name_len == 0 || name_len == 32) {
    return false;
  }

  const uint16_t attributes = rd16be(p.at(32));
  const uint16_t num_records = rd16be(p.at(76));
  if ((attributes & 0x0001) == 0 || num_records == 0 || num_records > 0x7FFF) {
    return false;  // dmHdrAttrResDB must be set
  }

  // Every resource map entry must point into the file, past the map itself.
  const uint64_t lowest = 78 + static_cast<uint64_t>(num_records) * 10;
  if (lowest > p.size || !p.has(78, static_cast<size_t>(num_records) * 10)) {
    return false;
  }
  for (uint16_t i = 0; i < num_records; ++i) {
    const uint32_t offset = rd32be(p.at(78 + i * 10 + 6));
    if (offset < lowest || offset >= p.size) {
      return false;
    }
  }
  return true;
}

//--------------------------------------------------------------------------
// ldr/dex: "dex\n" or "dey\n" followed by a NUL-terminated version.
inline bool looks_like_dex(const probe_t &p) {
  if (!p.has(0, 8)) {
    return false;
  }
  const uint8_t *m = p.at(0);
  if (m[0] != 'd' || m[1] != 'e' || m[3] != '\n') {
    return false;
  }
  if (m[2] != 'x' && m[2] != 'y') {
    return false;
  }
  return m[4] >= '0' && m[4] <= '9' && m[7] == 0;
}

//--------------------------------------------------------------------------
// sdk/src/ldr/hex: the first line decides between Intel HEX, MOS and S-records.
inline std::string classify_hex_text(const probe_t &p) {
  size_t i = 0;
  while (i < p.n() && *p.at(i) == ' ') {
    ++i;
  }
  if (!p.has(i, 3)) {
    return "";
  }
  const uint8_t lead = *p.at(i);
  const auto is_hex = [](uint8_t c) {
    return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f');
  };
  if (!is_hex(*p.at(i + 1)) || !is_hex(*p.at(i + 2))) {
    return "";
  }
  if (lead == ':') {
    return "ihex";
  }
  if (lead == ';') {
    return "mhex";
  }
  if (lead == 'S' && *p.at(i + 1) >= '0' && *p.at(i + 1) <= '9') {
    return "srec";
  }
  return "";
}

}  // namespace detail

//--------------------------------------------------------------------------
// Classify 'path' into one of known_types(). Never throws; anything the magic
// tests do not recognize is "unknown".
inline std::string detect_type(const std::filesystem::path &path) {
  using namespace detail;

  probe_t p;
  std::error_code ec;
  const uintmax_t fsize = std::filesystem::file_size(path, ec);
  if (ec) {
    return "unknown";
  }
  p.size = static_cast<uint64_t>(fsize);
  p.file.open(path, std::ios::binary);
  if (!p.file) {
    return "unknown";
  }
  p.buf.resize(static_cast<size_t>(std::min<uint64_t>(p.size, 4096)));
  if (!p.buf.empty()) {
    p.file.read(reinterpret_cast<char *>(p.buf.data()),
                static_cast<std::streamsize>(p.buf.size()));
    p.buf.resize(static_cast<size_t>(p.file.gcount()));
  }
  if (p.n() < 4) {
    return "unknown";
  }

  // --- archives and containers (unambiguous leading magic) ----------------
  if (p.eq(0, "!<arch>\n", 8) || p.eq(0, "!<bout>\n", 8) || p.eq(0, "!<elf_>\n", 8)) {
    return "ar";
  }
  if (p.eq(0, "<aiaff>\n", 8) || p.eq(0, "<bigaf>\n", 8)) {
    return "aixar";
  }
  if (p.eq(0, "PK\x03\x04", 4)) {
    return "zip";
  }
  if (p.eq(0, "%PDF", 4)) {
    return "pdf";
  }
  if (p.eq(257, "ustar", 5)) {
    return "tar";
  }

  // --- Xbox: PE-derived, but with their own container magic ---------------
  if (p.eq(0, "XEX", 3)) {
    const uint8_t v = *p.at(3);
    if (v == '2' || v == '1' || v == '0' || v == '%' || v == '-' || v == '?') {
      return "xex";
    }
  }
  if (p.eq(0, "XBEH", 4) || rd32le(p.at(0)) == 0x4558 /* "XE" */) {
    return "xbe";
  }

  // --- Unix and Apple -----------------------------------------------------
  if (p.eq(0, "\x7f" "ELF", 4)) {
    return "elf";
  }
  if (p.eq(0, "dyld_v", 6)) {
    return "dsc";
  }
  {
    const uint32_t le = rd32le(p.at(0));
    const uint32_t be = rd32be(p.at(0));
    if (le == 0xfeedface || le == 0xfeedfacf || le == 0xcefaedfe || le == 0xcffaedfe) {
      return "mach-o";
    }
    if (be == 0xcafebabe || be == 0xcafebabf) {
      return looks_like_java_class(p) ? "java" : "mach-o";
    }
  }

  // --- MZ family ----------------------------------------------------------
  if (p.eq(0, "MZ", 2) || p.eq(0, "ZM", 2)) {
    return classify_mz(p);
  }

  // --- fixed magics -------------------------------------------------------
  if (p.eq(0, "\0asm\x01\0\0\0", 8)) {
    return "wasm";
  }
  if (looks_like_dex(p)) {
    return "dex";
  }
  if (p.eq(0, "vdex", 4) || p.eq(0, "cdex", 4)) {
    return "vdex";
  }
  if (p.eq(0, "Joy!peff", 8)) {
    return "pef";
  }
  if (p.eq(0, "NetWare Loadable Module\x1a", 24)) {
    return "nlm";
  }
  if (p.eq(0, "SNES-SPC700 Sound File Data", 27)) {
    return "spc";
  }
  if (p.eq(0, "PS-X EXE", 8) || p.eq(0, "SCE EXE\0", 8)) {
    return "psx";
  }
  if (p.eq(0, "LNK\x02", 4)
      || (p.eq(0, "LIB", 3) && p.has(3, 1) && (*p.at(3) == 1 || *p.at(3) == 2))) {
    return "psxobj";
  }
  if (p.eq(0, "MDMP", 4) || p.eq(0, "PAGEDUMP", 8) || p.eq(0, "PAGEDU64", 8)) {
    return "windmp";
  }
  if (p.eq(0, "bFLT", 4)) {
    return "bflt";
  }

  {
    const uint32_t le = rd32le(p.at(0));
    const uint32_t be = rd32be(p.at(0));
    if (be == 0x27051956) {
      return "uimage";
    }
    if (le == 0x58881688 && p.has(0x30, 4) && rd32le(p.at(0x30)) == 0x58891689) {
      return "md1img";
    }
    if (be == 0x000003F3) {
      return "amiga";
    }
    if (le == 0xC3CBC6C5 || be == 0xC3CBC6C5) {
      return "aof";
    }
    if (le == 0x53CF45C7 || le == 0x53C145C7 || be == 0x53CF45C7 || be == 0x53C145C7) {
      return "geos";
    }
    if (le == 0x3C46F37A || be == 0x3C46F37A) {
      return "tmobj";
    }
    // ldr/n64: native byte order or the common byte-swapped dumps.
    if (be == 0x80371240 || be == 0x37804012 || be == 0x40123780) {
      return "n64";
    }
  }

  // --- EPOC/Symbian: E32 image, ROM image or SIS package -------------------
  if (p.has(0x14, 0)) {
    const uint32_t uid1 = rd32le(p.at(0));
    if (p.has(0x10, 4) && rd32le(p.at(0x10)) == 0x434F5045 /* 'EPOC' */) {
      return "epoc";
    }
    if (uid1 == 0x10000079 || uid1 == 0x1000007A) {
      return "epoc";
    }
    if (p.has(8, 4) && rd32le(p.at(8)) == 0x10000419 /* SIS UID3 */) {
      return "epoc";
    }
  }

  // --- small 16-bit magics ------------------------------------------------
  if (rd16be(p.at(0)) == 0x4AFC && p.has(2, 2) && rd16be(p.at(2)) == 0x0001) {
    return "osk";  // OS-9/68K module
  }
  if (rd16be(p.at(0)) == 0x87CD) {
    return "os9";  // OS-9/6809 module
  }
  if (rd16le(p.at(0)) == 0x1489) {
    return "mas";
  }
  if (rd16le(p.at(0)) == 0xC9B8) {
    return "is5x";
  }

  if (looks_like_hpsom(p)) {
    return "hpsom";
  }
  if (looks_like_aif(p)) {
    return "aif";
  }
  if (looks_like_aout(p)) {
    return "aout";
  }
  if (looks_like_coff(p, 0)) {
    return "coff";
  }
  if (looks_like_prc(p)) {
    return "prc";
  }

  // --- weak single-byte record leaders, kept last -------------------------
  if (*p.at(0) == 0xB0) {
    return "intelomf";
  }
  if (*p.at(0) == 0x80 || *p.at(0) == 0xF0) {
    return "omf";  // THEADR / library header
  }

  const std::string hex = classify_hex_text(p);
  if (!hex.empty()) {
    return hex;
  }

  return "unknown";
}

}  // namespace ftdetect
