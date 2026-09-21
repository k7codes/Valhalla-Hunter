#include "native_analyzer.h"
#include <vector>
#include <string>
#include <algorithm>
#include <map>
#include <cctype>

#pragma comment(lib, "advapi32.lib")

static int StringLengthA(const char* str) {
    int len = 0;
    while (str[len] != '\0') len++;
    return len;
}

static unsigned long ReadU32(const unsigned char* p) {
    return (unsigned long)p[0] | ((unsigned long)p[1] << 8) | ((unsigned long)p[2] << 16) | ((unsigned long)p[3] << 24);
}

static unsigned short ReadU16(const unsigned char* p) {
    return (unsigned short)(p[0] | (p[1] << 8));
}

static unsigned long long ReadU64(const unsigned char* p) {
    return (unsigned long long)ReadU32(p) | ((unsigned long long)ReadU32(p + 4) << 32);
}

static double CalculateEntropy(const unsigned char* data, size_t size) {
    if (size == 0) return 0.0;
    int freq[256] = {0};
    for (size_t i = 0; i < size; i++) freq[data[i]]++;
    double entropy = 0.0;
    for (int i = 0; i < 256; i++) {
        if (freq[i] == 0) continue;
        double p = (double)freq[i] / (double)size;
        entropy -= p * log2(p);
    }
    return entropy;
}

static int ExtractStrings(const unsigned char* data, size_t size, char (*strings)[MAX_STR_LEN], int maxStrings) {
    int count = 0;
    char current[MAX_STR_LEN];
    int curLen = 0;
    for (size_t i = 0; i < size && count < maxStrings; i++) {
        unsigned char c = data[i];
        if ((c >= 0x20 && c <= 0x7E)) {
            if (curLen < MAX_STR_LEN - 2) {
                current[curLen++] = (char)c;
            }
        } else {
            if (curLen >= 4) {
                current[curLen] = '\0';
                strncpy(strings[count], current, MAX_STR_LEN - 1);
                strings[count][MAX_STR_LEN - 1] = '\0';
                count++;
            }
            curLen = 0;
        }
    }
    if (curLen >= 4 && count < maxStrings) {
        current[curLen] = '\0';
        strncpy(strings[count], current, MAX_STR_LEN - 1);
        strings[count][MAX_STR_LEN - 1] = '\0';
        count++;
    }
    return count;
}

// ---------------------------------------------------------------------------
// PE structural helpers (both 32 and 64 bit)
// ---------------------------------------------------------------------------
struct PeLayout {
    IMAGE_FILE_HEADER* fileHeader;
    const unsigned char* optionalHeader;
    unsigned long optSize;
    IMAGE_SECTION_HEADER* sections;
    int sectionCount;
    BOOL is64;
};

static PeLayout GetPeLayout(const unsigned char* data, unsigned long fileSize, unsigned long peOffset) {
    PeLayout lay;
    memset(&lay, 0, sizeof(lay));
    if (peOffset + 24 > fileSize) return lay;
    const unsigned char* fileHdr = data + peOffset + 4; // skip "PE\0\0"
    lay.fileHeader = (IMAGE_FILE_HEADER*)fileHdr;
    unsigned short optSize = ReadU16(fileHdr + 16);
    if (peOffset + 24 + optSize > fileSize) return lay;
    lay.optionalHeader = fileHdr + 20;
    lay.optSize = optSize;
    unsigned short magic = ReadU16(lay.optionalHeader);
    lay.is64 = (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC);
    lay.sections = (IMAGE_SECTION_HEADER*)(lay.optionalHeader + optSize);
    unsigned int secCount = ReadU16(fileHdr + 2);
    if (secCount > MAX_SECTIONS) secCount = MAX_SECTIONS;
    int avail = (int)((fileSize - ((const unsigned char*)lay.sections - data)) / sizeof(IMAGE_SECTION_HEADER));
    if (avail < (int)secCount) secCount = avail;
    lay.sectionCount = (int)secCount;
    return lay;
}

static const unsigned char* DataDirPtr(const PeLayout& lay, int index) {
    if (index < 0 || index >= MAX_DATA_DIRS) return nullptr;
    unsigned long dirOff = lay.is64 ? 112 : 96;
    const unsigned char* dir = lay.optionalHeader + dirOff + index * 8;
    if (dir + 8 > lay.optionalHeader + lay.optSize) return nullptr;
    return dir;
}

static unsigned long DataDirRva(const PeLayout& lay, int index) {
    const unsigned char* d = DataDirPtr(lay, index);
    return d ? ReadU32(d) : 0;
}

static unsigned long DataDirSize(const PeLayout& lay, int index) {
    const unsigned char* d = DataDirPtr(lay, index);
    return d ? ReadU32(d + 4) : 0;
}

// Correct: for headers and any RVA lying in a section, translate to file offset.
static unsigned long RvaToOffset(const PeLayout& lay, unsigned long fileSize, unsigned long rva) {
    if (rva < lay.optSize || rva < ReadU32(lay.optionalHeader + 60)) {
        // falls in headers: the headers are at the start of file.
        return rva;
    }
    for (int i = 0; i < lay.sectionCount; i++) {
        IMAGE_SECTION_HEADER* sec = &lay.sections[i];
        unsigned long vsz = sec->Misc.VirtualSize;
        unsigned long rawSz = sec->SizeOfRawData;
        unsigned long va = sec->VirtualAddress;
        unsigned long span = vsz > rawSz ? vsz : rawSz;
        if (rva >= va && rva < va + span) {
            unsigned long delta = rva - va;
            if (delta < rawSz && sec->PointerToRawData + delta < fileSize) {
                return sec->PointerToRawData + delta;
            }
        }
    }
    return 0;
}

// ---------------------------------------------------------------------------
// Rich header (compiler fingerprint)
// ---------------------------------------------------------------------------
static const char* RichMsVersion(unsigned long id) {
    switch (id & 0xFFFF) {
        case 0x7F:  return "MSVC 6.0";
        case 0x64:  return "MSVC 7.0 (VS2002)";
        case 0x9E:  return "MSVC 7.1 (VS2003)";
        case 0xC9:  return "MSVC 8.0 (VS2005)";
        case 0xBE:  return "MSVC 8.0 (VS2005)";
        case 0x103: return "MSVC 9.0 (VS2008)";
        case 0x13C: return "MSVC 10.0 (VS2010)";
        case 0x16F: return "MSVC 11.0 (VS2012)";
        case 0x19D: return "MSVC 12.0 (VS2013)";
        case 0x1CB: return "MSVC 14.0 (VS2015)";
        case 0x1DB: return "MSVC 14.1 (VS2017)";
        case 0x20A: return "MSVC 14.2 (VS2019)";
        default:    return nullptr;
    }
}

static void DetectRichHeader(AnalysisResult* result, const unsigned char* data, unsigned long peOffset) {
    result->hasRichHeader = 0;
    result->compilerFingerprint[0] = '\0';
    if (peOffset < 16) return;

    // Search backwards from PE header for "Rich" marker in 4-byte steps.
    const unsigned int richMagic = 0x68636952; // "Rich"
    unsigned long richPos = 0;
    unsigned int key = 0;
    for (unsigned long i = peOffset; i >= 4; i -= 4) {
        unsigned int v = ReadU32(data + i - 4);
        if (v == richMagic) {
            richPos = i - 4;
            key = ReadU32(data + i); // dword right after "Rich"
            break;
        }
    }
    if (richPos == 0) return;

    // Validate XOR chain: first dword of rich header XOR key must be "DanS".
    unsigned int dans = 0x536e6144; // "DanS"
    // Find the beginning: walk data of rich header. The header layout is: "DanS" (xor key) then <prodid,build> pairs then "Rich" (plain) + key.
    int foundStart = 0;
    unsigned long start = 0;
    for (unsigned long i = 16; i <= richPos; i += 4) {
        unsigned int v = ReadU32(data + i);
        if ((v ^ key) == dans) {
            start = i;
            foundStart = 1;
            break;
        }
    }
    if (!foundStart) return;

    result->hasRichHeader = 1;

    // Collect distinct product IDs (first of each pair, XORed).
    std::map<unsigned long, unsigned long> products;
    for (unsigned long i = start + 4; i + 8 <= richPos; i += 8) {
        unsigned int prodId = ReadU32(data + i) ^ key;
        unsigned int build = ReadU32(data + i + 4) ^ key;
        products[prodId] = build;
    }

    // Fingerprint the compiler from known product IDs.
    std::string fp;
    int found = 0;
    for (auto const& kv : products) {
        const char* ver = nullptr;
        //
        // The compiler tool id encodes the tools that produced the binary:
        //   high-> low: 0x00 = link, 0x10 = cvtres, 0x20 = c2.dll compiler,
        //   0x30 gen? Actually known: 0x01 = util, 0x02 import...
        // The usual fingerprint is the "compiler" id (c2.dll) = prodid & 0xFFFF mapped above.
        ver = RichMsVersion(kv.first);
        if (ver) {
            if (!found) {
                fp = ver;
                found = 1;
            }
        }
    }
    if (!found) {
        unsigned long anyId = products.empty() ? 0 : products.begin()->first;
        if (products.size() > 0) {
            char buf[48];
            snprintf(buf, sizeof(buf), "MSVC (Rich, build %lu)", products.rbegin()->second);
            fp = buf;
        } else {
            fp = "MSVC (Rich header)";
        }
    }
    if (products.size() > 0) {
        fp += " + ";
        fp += std::to_string(products.size());
        fp += " tool signatures";
    }
    strncpy(result->compilerFingerprint, fp.c_str(), sizeof(result->compilerFingerprint) - 1);
    result->compilerFingerprint[sizeof(result->compilerFingerprint) - 1] = '\0';
}

// ---------------------------------------------------------------------------
// Entry point section
// ---------------------------------------------------------------------------
static void DetectEntrySection(AnalysisResult* result, const PeLayout& lay) {
    result->entrySection[0] = '\0';
    if (result->pe.entryPoint == 0) return;
    unsigned long epRva = result->pe.entryPoint;
    unsigned long off = RvaToOffset(lay, 0, epRva);
    for (int i = 0; i < lay.sectionCount; i++) {
        IMAGE_SECTION_HEADER* sec = &lay.sections[i];
        unsigned long vsz = sec->Misc.VirtualSize;
        unsigned long rawSz = sec->SizeOfRawData;
        unsigned long span = vsz > rawSz ? vsz : rawSz;
        if (epRva >= sec->VirtualAddress && epRva < sec->VirtualAddress + span) {
            char nm[9] = {0};
            memcpy(nm, sec->Name, 8);
            strncpy(result->entrySection, nm, 8);
            result->entrySection[8] = '\0';
            if (strcmp(nm, ".text") != 0 && strcmp(nm, "CODE") != 0) {
                result->suspiciousFlags |= 0x40;
            }
            break;
        }
    }
}

// ---------------------------------------------------------------------------
// Exports
// ---------------------------------------------------------------------------
static void CheckExports(AnalysisResult* result, const unsigned char* data, const PeLayout& lay, unsigned long fileSize) {
    result->exportCount = 0;
    unsigned long expRva = DataDirRva(lay, 0);
    unsigned long expSize = DataDirSize(lay, 0);
    if (expRva == 0 || expSize == 0) return;

    unsigned long off = RvaToOffset(lay, fileSize, expRva);
    if (off == 0 || off + 40 > fileSize) return;

    unsigned long nameCount = ReadU32(data + off + 24);
    unsigned long namePtrRva = ReadU32(data + off + 32);
    if (nameCount == 0 || namePtrRva == 0) return;

    unsigned long namePtrOff = RvaToOffset(lay, fileSize, namePtrRva);
    if (namePtrOff == 0) return;

    unsigned long dllNameRva = ReadU32(data + off + 12);
    unsigned long dllNameOff = RvaToOffset(lay, fileSize, dllNameRva);
    char dllExport[128] = "?";
    if (dllNameOff != 0) {
        strncpy(dllExport, (const char*)(data + dllNameOff), sizeof(dllExport) - 1);
        dllExport[sizeof(dllExport) - 1] = '\0';
    }

    unsigned long max = nameCount;
    if (max > MAX_EXPORTS) max = MAX_EXPORTS;
    for (unsigned long i = 0; i < max; i++) {
        unsigned long fnRva = ReadU32(data + namePtrOff + i * 4);
        unsigned long fnOff = RvaToOffset(lay, fileSize, fnRva);
        if (fnOff == 0 || fnOff >= fileSize) continue;
        snprintf(result->exports[i].name, MAX_API_STR, "%s!%s", dllExport,
                 strlen((const char*)(data + fnOff)) ? (const char*)(data + fnOff) : "?");
        result->exportCount++;
    }
}

// ---------------------------------------------------------------------------
// TLS callbacks
// ---------------------------------------------------------------------------
static void CheckTlsCallbacks(AnalysisResult* result, const unsigned char* data, const PeLayout& lay, unsigned long fileSize) {
    result->hasTlsCallbacks = 0;
    result->tlsCallbackCount = 0;
    unsigned long tlsRva = DataDirRva(lay, 9);
    if (tlsRva == 0) return;

    unsigned long off = RvaToOffset(lay, fileSize, tlsRva);
    if (off == 0 || off + 40 > fileSize) return;

    unsigned long long cbRva = lay.is64 ? ReadU64(data + off + 24) : ReadU32(data + off + 12);
    if (cbRva == 0) return;

    unsigned long cbOff = RvaToOffset(lay, fileSize, (unsigned long)cbRva);
    if (cbOff == 0 || cbOff + 8 > fileSize) return;

    result->hasTlsCallbacks = 1;
    int stride = lay.is64 ? 8 : 4;
    int count = 0;
    for (int i = 0; i < 64; i++) {
        unsigned long long cb = lay.is64 ? ReadU64(data + cbOff + (size_t)i * stride) : ReadU32(data + cbOff + (size_t)i * stride);
        if (cb == 0) break;
        count++;
    }
    result->tlsCallbackCount = count;
    if (count > 0) result->suspiciousFlags |= 0x80;
}

// ---------------------------------------------------------------------------
// Import table
// ---------------------------------------------------------------------------
static int IsSuspiciousApi(const char* name) {
    // The name is "<dll>!<func>" in lower-case comparison.
    const char* pats[] = {
        "createremotethread", "writeprocessmemory", "virtualallocex", "virtualprotectex",
        "setwindowshookex", "regsetvalueex", "regcreatekeyex", "shellexecute", "winexec",
        "urldownloadtofile", "urlmon", "winhttp", "wsasocket", "connect", "send", "recv",
        "internetopen", "accept", "listen", "bind", "getaddrinfo", "dnsquery",
        "deletefile", "process32first", "createtoolhelp32snapshot", "openprocess",
        "ntunmapviewofsection", "rtlcreateuserthread", "setthreadcontext", "getthreadcontext",
        "queueuserapc", "loadlibrarya", "loadlibraryw", "getprocaddress", "createservice",
        "openscmanager", "startservice", "lookupprivilegevalue", "adjusttokenprivileges",
        "smart.tsl", "schtasks", "bitsadmin", "certutil", "curl", "wget", "vssadmin",
        "regsvr32", "rundll32", "mshta", "powershell", "cmd", "cscript", "wscript",
        "getsystemdirectory", "writefile", "mapviewoffile", "scmr",
    };
    for (size_t i = 0; i < sizeof(pats) / sizeof(pats[0]); i++) {
        if (strstr(name, pats[i]) != NULL) {
            // "send"/"recv"/"connect" without a base like netapi can be misleading;
            // keep them (network IO is still an indicator).
            return 1;
        }
    }
    return 0;
}

static void CheckImports(AnalysisResult* result, const unsigned char* data, const PeLayout& lay, unsigned long fileSize) {
    result->importCount = 0;
    result->dangerousImportCount = 0;

    unsigned long importRva = DataDirRva(lay, 1);
    if (importRva == 0 || DataDirSize(lay, 1) == 0) return;

    unsigned long off = RvaToOffset(lay, fileSize, importRva);
    if (off == 0 || off + sizeof(IMAGE_IMPORT_DESCRIPTOR) > fileSize) return;

    IMAGE_IMPORT_DESCRIPTOR* descs = (IMAGE_IMPORT_DESCRIPTOR*)(data + off);
    int stride = lay.is64 ? 8 : 4;
    int idx = 0;
    for (int d = 0; ; d++) {
        if (idx >= MAX_IMPORTS) break;
        // Bounds-guard the descriptor walk.
        size_t dpos = (size_t)off + (size_t)d * sizeof(IMAGE_IMPORT_DESCRIPTOR);
        if (dpos + sizeof(IMAGE_IMPORT_DESCRIPTOR) > fileSize) break;
        IMAGE_IMPORT_DESCRIPTOR* desc = (IMAGE_IMPORT_DESCRIPTOR*)(data + dpos);
        if (desc->Name == 0) break;

        unsigned long nameOff = RvaToOffset(lay, fileSize, desc->Name);
        if (nameOff == 0 || nameOff >= fileSize) continue;
        char dllName[128] = {0};
        strncpy(dllName, (const char*)(data + nameOff), sizeof(dllName) - 1);

        unsigned long thunkRva = desc->OriginalFirstThunk != 0 ? desc->OriginalFirstThunk : desc->FirstThunk;
        if (thunkRva == 0) continue;
        unsigned long thunkOff = RvaToOffset(lay, fileSize, thunkRva);
        if (thunkOff == 0 || thunkOff >= fileSize) continue;

        for (int t = 0; t < 512; t++) {
            if (idx >= MAX_IMPORTS) break;
            ULONGLONG thunkVal = 0;
            size_t thunkPos = (size_t)thunkOff + (size_t)t * stride;
            if (thunkPos + (size_t)stride > fileSize) break;
            memcpy(&thunkVal, data + thunkPos, stride);
            if (thunkVal == 0) break;

            ULONGLONG ordinalFlag = lay.is64 ? 0x8000000000000000ULL : 0x80000000ULL;
            if (thunkVal & ordinalFlag) continue;

            ULONG byNameRva = (ULONG)(thunkVal & 0x7FFFFFFF);
            ULONG byNameOff = RvaToOffset(lay, fileSize, byNameRva);
            if (byNameOff == 0 || byNameOff + 3 > fileSize) continue;

            const char* fn = (const char*)(data + byNameOff + 2);
            snprintf(result->imports[idx].name, MAX_API_STR, "%s!%s", dllName, fn);

            // dangerous import heuristic
            char lower[MAX_API_STR];
            strncpy(lower, result->imports[idx].name, MAX_API_STR - 1);
            lower[MAX_API_STR - 1] = '\0';
            for (int c = 0; lower[c]; c++) lower[c] = (char)tolower((unsigned char)lower[c]);
            if (IsSuspiciousApi(lower)) result->dangerousImportCount++;

            idx++;
        }
    }
    result->importCount = idx;
}

// ---------------------------------------------------------------------------
// Packer / compiler detection (extended)
// ---------------------------------------------------------------------------
static void DetectPacker(AnalysisResult* result) {
    result->detectedPacker[0] = '\0';

    // 1) Signature from sections
    const char* packSigs[] = {
        ".upx", "upx", ".themida", "themida", ".vmtr", ".vmp0", ".aspack", ".petite",
        ".ncompress", ".mpress1", ".mpress2", ".enigma1", ".enigma2", ".pelock", ".pec1",
        ".pec2", ".bse", ".mew", ".fsg", ".packed", "packed", ".kkrunchy", ".lz1",
        ".crunch", ".jinja", ".shallpol", ".wirefus"
    };
    for (int i = 0; i < result->sectionCount; i++) {
        const char* name = result->sections[i].name;
        for (size_t s = 0; s < sizeof(packSigs) / sizeof(packSigs[0]); s++) {
            if (strcmp(name, packSigs[s]) == 0) {
                // map to readable
                if (strstr(name, "mpress")) strncpy(result->detectedPacker, "MPRESS", 63);
                else if (strstr(name, "enigma")) strncpy(result->detectedPacker, "Enigma Protector", 63);
                else if (strstr(name, "pelock")) strncpy(result->detectedPacker, "PELock", 63);
                else if (strstr(name, "pec")) strncpy(result->detectedPacker, "PECompact", 63);
                else if (strstr(name, "bse")) strncpy(result->detectedPacker, "BSE", 63);
                else if (strstr(name, "mew")) strncpy(result->detectedPacker, "MEW", 63);
                else if (strstr(name, "fsg")) strncpy(result->detectedPacker, "FSG", 63);
                else if (strstr(name, "kkrunchy")) strncpy(result->detectedPacker, "kkrunchy", 63);
                else if (strstr(name, "lz1")) strncpy(result->detectedPacker, "Stealth PE", 63);
                else if (strcmp(name, ".packed") == 0 || strcmp(name, "packed") == 0) strncpy(result->detectedPacker, "Custom Packed", 63);
                else {
                    strncpy(result->detectedPacker, name, 63);
                    result->detectedPacker[63] = 0;
                }
                return;
            }
        }
        // `.upx` handled above; also check "$$" style, resources flg.
    }

    // 2) .NET check
    if (result->pe.machine == 0) return;

    // 3) High entropy whole-file
    if (result->overallEntropy > 7.4) {
        strncpy(result->detectedPacker, "High Entropy (likely packed/obfuscated)", 63);
        return;
    }

    // 4) overlay is a sign of dopestuff
    if (result->overlaySize > 1 * 1024 * 1024) {
        strncpy(result->detectedPacker, "Large overlay present (possible bundled data)", 63);
        return;
    }
}

// ---------------------------------------------------------------------------
// Suspicious string heuristics
// ---------------------------------------------------------------------------
static int IsSuspiciousString(const char* s) {
    const char* pats[] = {
        "http://", "https://", "hxxp", "ftp://", ".onion", "powershell", "cmd.exe",
        "cmd /c", "/c ", "cscript", "wscript", "regsvr32", "mshta", "rundll32",
        "certutil", "bitsadmin", "schtasks", "vssadmin", "curl ", "wget", "chm",
        "javascript:", "vbscript:", "data:text", "base64", " -enc", "-enc ", "-e ", "-nop",
        "hidden", "--hidden", "bypass", "\\AppData\\", "\\ProgramData\\", "\\Temp\\",
        "HKCU\\", "HKLM\\", "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        "AddSecPackage", "rundll32", "RunDll32", "kernel32", "CreateProcess", "VirtualAlloc"
    };
    for (size_t i = 0; i < sizeof(pats) / sizeof(pats[0]); i++) {
        if (strstr(s, pats[i]) != NULL) return 1;
    }
    // URL-ish pattern with "://"
    if (strstr(s, "://") != NULL) return 1;
    return 0;
}

static void CountSuspiciousStrings(AnalysisResult* result) {
    result->suspiciousStringCount = 0;
    for (int i = 0; i < result->strings.count; i++) {
        if (IsSuspiciousString(result->strings.string_data[i])) result->suspiciousStringCount++;
    }
}

// ---------------------------------------------------------------------------
// Main entry
// ---------------------------------------------------------------------------
NATIVE_API AnalysisResult* AnalyzePE(const wchar_t* filePath) {
    AnalysisResult* result = (AnalysisResult*)calloc(1, sizeof(AnalysisResult));
    if (!result) return nullptr;
    result->strings.count = 0;
    result->sectionCount = 0;
    result->importCount = 0;
    result->overallEntropy = 0.0;
    result->detectedPacker[0] = '\0';
    result->errorMessage[0] = '\0';
    result->suspiciousFlags = 0;

    HANDLE hFile = CreateFileW(filePath, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        strncpy(result->errorMessage, "Cannot open file", 255);
        return result;
    }

    DWORD fileSize = GetFileSize(hFile, nullptr);
    if (fileSize == 0 || fileSize == INVALID_FILE_SIZE) {
        strncpy(result->errorMessage, "Empty file", 255);
        CloseHandle(hFile);
        return result;
    }

    unsigned char* data = (unsigned char*)calloc(1, fileSize); // calloc zero-fills for generic safety
    if (!data) {
        strncpy(result->errorMessage, "Memory allocation failed", 255);
        CloseHandle(hFile);
        return result;
    }

    DWORD bytesRead = 0;
    if (!ReadFile(hFile, data, fileSize, &bytesRead, nullptr)) {
        strncpy(result->errorMessage, "Read failed", 255);
        free(data);
        CloseHandle(hFile);
        return result;
    }
    CloseHandle(hFile);
    if (bytesRead < fileSize) fileSize = bytesRead;
    if (fileSize < 64) { strncpy(result->errorMessage, "Too small to be a PE", 255); free(data); return result; }

    if (data[0] != 'M' || data[1] != 'Z') {
        strncpy(result->errorMessage, "Not a valid PE file (no MZ)", 255);
        free(data);
        return result;
    }

    unsigned long peOffset = ReadU32(data + 0x3C);
    if (peOffset + 32 >= fileSize) {
        strncpy(result->errorMessage, "Invalid PE header offset", 255);
        free(data);
        return result;
    }
    if (ReadU32(data + peOffset) != 0x00004550) { // "PE\0\0"
        strncpy(result->errorMessage, "Invalid PE signature", 255);
        free(data);
        return result;
    }

    PeLayout lay = GetPeLayout(data, fileSize, peOffset);
    if (!lay.fileHeader || lay.optSize < 96 || lay.sectionCount == 0) {
        strncpy(result->errorMessage, "Malformed or non-standard PE headers", 255);
        free(data);
        return result;
    }

    const unsigned char* opt = lay.optionalHeader;
    const unsigned char* fh = (const unsigned char*)lay.fileHeader;

    // --- Core metadata (Pemetadata fields kept for ABI compat) ---
    result->pe.machine = ReadU16(fh);
    result->pe.entryPoint = ReadU32(opt + 16);
    result->pe.baseOfCode = ReadU32(opt + 20);
    result->pe.baseOfData = lay.is64 ? 0 : ReadU32(opt + 24);
    result->pe.imageBase = (unsigned long)(lay.is64 ? ReadU64(opt + 24) : ReadU32(opt + 28));
    result->pe.sectionCount = (unsigned long)lay.sectionCount;
    result->pe.sizeOfImage = ReadU32(opt + 56);
    result->pe.sizeOfHeaders = ReadU32(opt + 60);
    result->pe.characteristics = ReadU32(fh + 18);
    result->pe.subsystem = ReadU32(opt + 68);
    result->pe.numberOfSymbols = ReadU32(fh + 8);
    result->pe.timeDateStamp = ReadU32(fh + 4);
    result->pe.sizeOfOptionalHeader = lay.optSize;
    result->pe.isDll = (result->pe.characteristics & IMAGE_FILE_DLL) != 0;
    result->pe.is64Bit = lay.is64;

    // --- Deep metadata ---
    result->imageBase64 = lay.is64 ? ReadU64(opt + 24) : ReadU32(opt + 28);
    result->dllCharacteristics = ReadU32(opt + 70);
    result->checksum = ReadU32(opt + 64);
    unsigned short subMaj = ReadU16(opt + 48), subMin = ReadU16(opt + 50);
    result->subsystemVersion = ((unsigned long)subMaj << 16) | subMin;

    // --- Sections ---
    double totalEntropy = 0.0;
    unsigned long long totalBytes = 0;
    unsigned long lastRawEnd = 0;
    for (int i = 0; i < lay.sectionCount; i++) {
        IMAGE_SECTION_HEADER* sec = &lay.sections[i];
        char secName[9] = {0};
        memcpy(secName, sec->Name, 8);

        unsigned long rawSz = sec->SizeOfRawData;
        unsigned long rawPtr = sec->PointerToRawData;
        // clamp raw range into file
        unsigned long entN = rawSz;
        unsigned long entStart = rawPtr;
        if (entStart >= fileSize) { entN = 0; entStart = fileSize; }
        if (entN > fileSize - entStart) entN = fileSize - entStart;
        double ent = CalculateEntropy(data + entStart, entN);

        strncpy(result->sections[i].name, secName, 8);
        result->sections[i].name[8] = '\0';
        result->sections[i].virtualSize = sec->Misc.VirtualSize;
        result->sections[i].virtualAddress = sec->VirtualAddress;
        result->sections[i].sizeOfRawData = rawSz;
        result->sections[i].pointerToRawData = rawPtr;
        result->sections[i].characteristics = sec->Characteristics;
        result->sections[i].entropy = ent;

        int suspicious = 0;
        if (ent > 7.0) suspicious |= 0x01;
        const char* known[] = { ".text", ".data", ".rdata", ".rsrc", ".reloc", ".idata", ".bss", ".tls", "CODE", "DATA", "BSS", ".pdata", "EDATA", ".gfids", ".00cfg", ".CRT", ".tls$", ".rtc", ".xdata" };
        bool knownName = false;
        for (int k = 0; k < (int)(sizeof(known) / sizeof(known[0])); k++) {
            if (strcmp(secName, known[k]) == 0) { knownName = true; break; }
        }
        if (!knownName && rawSz > 0) suspicious |= 0x02;
        if ((sec->Characteristics & IMAGE_SCN_MEM_EXECUTE) && !(sec->Characteristics & IMAGE_SCN_CNT_CODE)) {
            suspicious |= 0x04;
        }
        // Size anomaly: raw data much larger than file-remaining or misc mismatch
        if (sec->Misc.VirtualSize > 0 && rawSz > 0 && rawSz > (unsigned long)1.5 * sec->Misc.VirtualSize) {
            suspicious |= 0x08;
        }
        result->sections[i].suspicious = suspicious;
        if (suspicious) result->suspiciousFlags |= (suspicious & 0x0F);

        totalEntropy += ent * (double)entN;
        totalBytes += entN;
        unsigned long rawEnd = rawPtr + rawSz;
        if (rawEnd > lastRawEnd && rawEnd <= fileSize) lastRawEnd = rawEnd;
    }

    if (totalBytes > 0) result->overallEntropy = totalEntropy / (double)totalBytes;
    result->sectionCount = lay.sectionCount;

    // --- Strings across all sections (pooled) ---
    std::vector<std::pair<const unsigned char*, unsigned long>> blocks;
    for (int i = 0; i < lay.sectionCount; i++) {
        unsigned long rawPtr = lay.sections[i].PointerToRawData;
        unsigned long rawSz = lay.sections[i].SizeOfRawData;
        if (rawPtr >= fileSize) continue;
        if (rawSz > fileSize - rawPtr) rawSz = fileSize - rawPtr;
        if (rawSz == 0) continue;
        blocks.push_back(std::make_pair(data + rawPtr, rawSz));
    }
    result->strings.count = 0;
    int strCap = MAX_STRINGS / (int)(blocks.size() ? blocks.size() : 1);
    if (strCap < 1) strCap = 1;
    for (size_t b = 0; b < blocks.size() && result->strings.count < MAX_STRINGS; b++) {
        int got = ExtractStrings(blocks[b].first, blocks[b].second,
                                 result->strings.string_data + result->strings.count,
                                 MAX_STRINGS - result->strings.count);
        result->strings.count += got;
        if (result->strings.count >= MAX_STRINGS) break;
    }
    CountSuspiciousStrings(result);

    // --- Overlay (data after last section raw end) ---
    result->overlaySize = 0;
    result->overlayEntropy = 0.0;
    if (lastRawEnd > 0 && lastRawEnd < fileSize) {
        result->overlaySize = fileSize - lastRawEnd;
        if (result->overlaySize > 0) {
            result->overlayEntropy = CalculateEntropy(data + lastRawEnd, result->overlaySize);
            if (result->overlaySize > 256 * 1024) result->suspiciousFlags |= 0x100;
        }
    }

    // --- Rich header ---
    DetectRichHeader(result, data, peOffset);

    // --- Exports / TLS / Imports ---
    CheckExports(result, data, lay, fileSize);
    CheckTlsCallbacks(result, data, lay, fileSize);
    CheckImports(result, data, lay, fileSize);

    // --- Data directory mask ---
    {
        unsigned long mask = 0;
        for (int i = 0; i < MAX_DATA_DIRS; i++) {
            if (DataDirRva(lay, i) != 0 && DataDirSize(lay, i) != 0) mask |= (1UL << i);
        }
        result->dataDirectoryMask = (int)mask;
    }

    // Authenticode
    result->hasCertificate = 0;
    result->certificateSize = 0;
    if (DataDirRva(lay, 4) && DataDirSize(lay, 4)) {
        // Security directory: VirtualAddress is a file offset.
        unsigned long certOff = DataDirRva(lay, 4);
        unsigned long certSz = DataDirSize(lay, 4);
        if (certOff + certSz <= fileSize) {
            result->hasCertificate = 1;
            result->certificateSize = certSz;
        }
    }

    // --- Entry point section ---
    DetectEntrySection(result, lay);

    // --- Compiler fallback (no Rich header) from imports ---
    if (!result->hasRichHeader) {
        bool mingw = false, msvc = false, delphi = false;
        for (int i = 0; i < result->importCount && !delphi; i++) {
            const char* n = result->imports[i].name;
            if (strstr(n, "libgcc") || strstr(n, "libstdc++") || strstr(n, "__mingw")) mingw = true;
            if (strstr(n, "msvcrt.dll") || strstr(n, "ucrtbase.dll") || strstr(n, "vcruntime")) msvc = true;
            if (strstr(n, "rtl") && strstr(n, ".bpl")) delphi = true;
        }
        if (delphi) strncpy(result->compilerFingerprint, "Borland Delphi", sizeof(result->compilerFingerprint) - 1);
        else if (mingw) strncpy(result->compilerFingerprint, "MinGW GCC", sizeof(result->compilerFingerprint) - 1);
        else if (msvc) strncpy(result->compilerFingerprint, "MSVC (runtime detected)", sizeof(result->compilerFingerprint) - 1);
        else if (result->importCount == 0) {
            // Possibly a make or a compiled stub with no imports
            const unsigned char* rsrc = data + RvaToOffset(lay, fileSize, DataDirRva(lay, 2));
            strncpy(result->compilerFingerprint, "Unknown compiler (no imports)", sizeof(result->compilerFingerprint) - 1);
        } else {
            strncpy(result->compilerFingerprint, "Unknown compiler", sizeof(result->compilerFingerprint) - 1);
        }
    }

    DetectPacker(result);

    if (result->pe.entryPoint == 0) result->suspiciousFlags |= 0x10;
    if (result->pe.subsystem == 0) result->suspiciousFlags |= 0x20;

    free(data);
    return result;
}

NATIVE_API void FreeResult(AnalysisResult* result) {
    if (result) free(result);
}

NATIVE_API const wchar_t* GetAnalyzerVersion() {
    static wchar_t ver[] = L"2.0.0.0";
    return ver;
}