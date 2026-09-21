#define HOOKENGINE_EXPORTS
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include "hook_engine.h"
#include <stdio.h>
#include <stdlib.h>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "ws2_32.lib")

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================
// x64 instruction length decoder (prefix/rex/vend/modrm/sib/imm)
// Returns instruction byte length at p, up to maxScan, or -1.
// If ripOff is non-NULL it receives the byte offset (within the
// instruction) of a rel32/rip-relative displacement needing rebase.
// ============================================================
static int x64_instr(const BYTE* p, int maxScan, int* ripOff) {
    int i = 0, pref66 = 0, rex_w = 0;
    if (ripOff) *ripOff = -1;
    while (i < 15) {
        BYTE b = p[i];
        if (b == 0x66) { pref66 = 1; i++; continue; }
        if (b == 0x67 || b == 0xF0 || b == 0xF2 || b == 0xF3) { i++; continue; }
        if (b >= 0x40 && b <= 0x4F) { if ((b & 8) != 0) rex_w = 1; i++; continue; }
        break;
    }
    if (i + 1 > maxScan) return -1;
    int pfx = i;                  // prefix byte count (indices below are absolute in p)
    int opi = i;                  // opcode index
    int op = p[i];
    int group = 0;
    if (op == 0x0F) {
        group = 1;
        opi = i + 1;
        if (opi + 1 > maxScan) return -1;
        op = p[opi];
        if (op == 0x38 || op == 0x3A) { group = 2; opi = i + 2; if (opi + 1 > maxScan) return -1; op = p[opi]; }
    }

    int hasModrm = 0, immBytes = 0, modrmPos = 0;

    if (group == 0) {
        BYTE g = (BYTE)op;
        if ((g >= 0x70 && g <= 0x7F) || g == 0xEB) return pfx + 2;               // jcc/jmp rel8
        if (g == 0xE8 || g == 0xE9) { if (ripOff) *ripOff = opi; return pfx + 5; } // rel32
        if (g == 0xEA) return pfx + 6;                                          // jmp far (invalid)
        if (g == 0x68) return pfx + 5;                                          // push imm32
        if (g == 0x6A) return pfx + 2;                                          // push imm8
        if (g >= 0xB0 && g <= 0xB7) return pfx + 2;                             // mov r8, imm8
        if (g >= 0xB8 && g <= 0xBF) return pfx + 1 + (rex_w ? 8 : (pref66 ? 2 : 4)); // mov r64/r32, imm
        if (g >= 0xA0 && g <= 0xA3) return pfx + 9;                             // mov moffs64
        if (g == 0xC2 || g == 0xCA) return pfx + 3;                             // ret imm16
        if (g == 0xCD) return pfx + 2;                                          // int imm8
        if (g == 0xE4 || g == 0xE5 || g == 0xE6 || g == 0xE7) return pfx + 2;   // in/out imm8
        if (g == 0xC4 || g == 0xC5) {
            if (i + 3 > maxScan) return -1;
            if (g == 0xC4 && (p[i + 1] & 0x80)) { i += 3; modrmPos = i; hasModrm = 1; } // VEX3
            else if (g == 0xC5 && !(p[i + 1] & 0x80)) { i += 2; modrmPos = i; hasModrm = 1; } // VEX2
            else return pfx + 2;                                                // LES/LDS (rare)
        } else {
            if ((g >= 0x00 && g <= 0x03) || (g >= 0x08 && g <= 0x0B) ||
                (g >= 0x10 && g <= 0x13) || (g >= 0x18 && g <= 0x1B) ||
                (g >= 0x20 && g <= 0x23) || (g >= 0x28 && g <= 0x2B) ||
                (g >= 0x30 && g <= 0x33) || (g >= 0x38 && g <= 0x3B) ||
                g == 0x62 || g == 0x63 || g == 0x69 || g == 0x6B ||
                (g >= 0x80 && g <= 0x8D) || g == 0x8F || g == 0xC0 || g == 0xC1 ||
                g == 0xC6 || g == 0xC7 || (g >= 0xD0 && g <= 0xD3) ||
                (g >= 0xD8 && g <= 0xDF) || g == 0xF6 || g == 0xF7 || g == 0xFE || g == 0xFF) {
                hasModrm = 1;
                modrmPos = opi + 1;
            }
            if (g == 0x80 || g == 0x83 || g == 0x6B || g == 0xC0 || g == 0xC1) immBytes = 1;
            else if (g == 0x81 || g == 0x69 || g == 0xC7) immBytes = pref66 ? 2 : 4;
        }
    } else if (group == 1) {
        BYTE g = (BYTE)op;
        if (g >= 0x70 && g <= 0x7F) { if (ripOff) *ripOff = opi + 1; return pfx + 6; } // 0F 8x jcc rel32
        switch (g) {
            case 0x05: case 0x06: case 0x07: case 0x08: case 0x09:
            case 0x0B: case 0x0C: case 0x0E: case 0x30: case 0x31:
            case 0x32: case 0x33: case 0x34: case 0x35: case 0x37:
            case 0xA0: case 0xA1: case 0xA2: case 0xA8: case 0xA9:
            case 0xAA:
                return pfx + 2;                                // 0F xx no-modrm system/push/pop forms
            default: break;
        }
        if (g >= 0xC8 && g <= 0xCF) return pfx + 2;            // bswap
        hasModrm = 1;
        modrmPos = opi + 1;
        if (g == 0xA4 || g == 0xBA || g == 0xC2 || g == 0xC4 || g == 0xC5 || g == 0xC6) immBytes = 1;
    } else {
        hasModrm = 1;                                          // 0F 38 / 0F 3A: modrm nearly universal
        modrmPos = opi + 1;
    }

    // ---- modrm path ----
    if (hasModrm) {
        if (modrmPos + 1 > maxScan) return -1;
        BYTE modrm = p[modrmPos];
        int mod = (modrm >> 6) & 3;
        int rm  = modrm & 7;
        int reg = (modrm >> 3) & 7;
        int disp = 0;
        int dispPos = modrmPos + 1;
        if (mod != 3 && rm == 4) {                              // SIB
            if (dispPos + 1 > maxScan) return -1;
            BYTE sib = p[dispPos];
            int base = sib & 7;
            dispPos++;
            if (mod == 0 && base == 5) { disp = 4; }             // absolute disp32, NOT rip-relative
            else if (mod == 1) disp = 1;
            else if (mod == 2) disp = 4;
        } else if (mod == 0 && rm == 5) {                       // rip-relative disp32 (no SIB)
            disp = 4; if (ripOff) *ripOff = dispPos;
        } else if (mod == 1) disp = 1;
        else if (mod == 2) disp = 4;

        if (group == 0) {
            BYTE g = (BYTE)op;
            if (g == 0xF6) immBytes = reg <= 1 ? 1 : 0;
            else if (g == 0xF7) immBytes = reg <= 1 ? (pref66 ? 2 : 4) : 0;
            else if (g == 0xC7) immBytes = reg == 0 ? (pref66 ? 2 : 4) : 0;
            else if (g == 0xC6) immBytes = 1;
        }
        int end = dispPos + disp + immBytes;
        if (end > maxScan) return -1;
        return end;
    }

    return pfx + ((opi == pfx) ? 1 : 2);
}

typedef struct { int off; int len; int ripRel; } HE_IX;

// Disassembles the prologue at fn instruction-by-instruction until at least
// minTotal bytes are covered. Returns instruction count or -1 on failure.
static int disasm_prologue(const BYTE* fn, HE_IX* ins, int cap, int minTotal, int maxScan) {
    int total = 0, n = 0;
    while (total < minTotal && n < cap) {
        int rip = -1;
        int l = x64_instr(fn + total, maxScan - total, &rip);
        if (l <= 0) return -1;
        ins[n].off = total; ins[n].len = l; ins[n].ripRel = rip;
        total += l; n++;
    }
    return total >= minTotal ? n : -1;
}

// ============================================================
// Ring buffers - two independent channels (hook + network)
// ============================================================
static HANDLE   g_ringMap = NULL;
static BYTE*    g_ring    = NULL;
static HERingHeader* g_hdr = NULL;
static HEHookEvent*  g_evt = NULL;

static HANDLE   g_netRingMap = NULL;
static BYTE*    g_netRing    = NULL;
static HERingHeader* g_netHdr = NULL;
static HEHookEvent*  g_netEvt = NULL;

static LARGE_INTEGER g_qpf;

static void ring_ensure_timer(void) {
    if (g_qpf.QuadPart == 0) {
        QueryPerformanceFrequency(&g_qpf);
        if (g_qpf.QuadPart == 0) g_qpf.QuadPart = 1;
    }
}

static ULONGLONG ring_now_for(const HERingHeader* hdr) {
    LARGE_INTEGER li;
    QueryPerformanceCounter(&li);
    return (ULONGLONG)((li.QuadPart * 10000000ULL) / g_qpf.QuadPart -
                       (hdr ? (ULONGLONG)hdr->openTicks : 0ULL));
}

static BOOL ring_map_open(BYTE** ringVar, HERingHeader** hdrVar, HEHookEvent** evtVar,
                          HANDLE* mapVar, const wchar_t* name, const wchar_t* moduleName) {
    if (*ringVar) return TRUE;
    ring_ensure_timer();
    ULONG evSize = (ULONG)sizeof(HEHookEvent);
    ULONG mapSize = sizeof(HERingHeader) + evSize * HE_MAX_EVENTS;
    *mapVar = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE,
                                 0, mapSize, name);
    if (!*mapVar) return FALSE;
    *ringVar = (BYTE*)MapViewOfFile(*mapVar, FILE_MAP_ALL_ACCESS, 0, 0, 0);
    if (!*ringVar) { CloseHandle(*mapVar); *mapVar = NULL; return FALSE; }
    *hdrVar = (HERingHeader*)(*ringVar);
    if ((*hdrVar)->magic != 0x56484F4B) {
        LARGE_INTEGER li;
        QueryPerformanceCounter(&li);
        (*hdrVar)->openTicks = (ULONGLONG)(li.QuadPart * 10000000ULL / g_qpf.QuadPart);
        (*hdrVar)->magic = 0x56484F4B;
        (*hdrVar)->version = 1;
        (*hdrVar)->eventSize = evSize;
        (*hdrVar)->capacity = HE_MAX_EVENTS;
        (*hdrVar)->head = 0;
        (*hdrVar)->tail = 0;
        (*hdrVar)->committed = 0;
        (*hdrVar)->overflowDrop = 0;
        (*hdrVar)->pidWriter = GetCurrentProcessId();
        if (moduleName) {
            ZeroMemory((*hdrVar)->moduleName, sizeof((*hdrVar)->moduleName));
            wcstombs((*hdrVar)->moduleName, moduleName, sizeof((*hdrVar)->moduleName)-1);
        }
    }
    *evtVar = (HEHookEvent*)((*ringVar) + sizeof(HERingHeader));
    return TRUE;
}

BOOL HE_API he_open_ring(const wchar_t* moduleName) {
    return ring_map_open(&g_ring, &g_hdr, &g_evt, &g_ringMap, HE_RING_NAME, moduleName);
}

BOOL HE_API he_net_open(void) {
    return ring_map_open(&g_netRing, &g_netHdr, &g_netEvt, &g_netRingMap, HE_NET_RING_NAME, L"Valhalla Net");
}

void HE_API he_close_ring(void) {
    if (g_ring) UnmapViewOfFile(g_ring);
    if (g_ringMap) CloseHandle(g_ringMap);
    g_ring = NULL; g_hdr = NULL; g_evt = NULL; g_ringMap = NULL;
}

void HE_API he_net_close(void) {
    if (g_netRing) UnmapViewOfFile(g_netRing);
    if (g_netRingMap) CloseHandle(g_netRingMap);
    g_netRing = NULL; g_netHdr = NULL; g_netEvt = NULL; g_netRingMap = NULL;
}

static void ring_emit_to(HERingHeader* hdr, HEHookEvent* evt,
                         ULONG apiId, ULONG argCount, const ULONG_PTR* args,
                         ULONG_PTR ret, const char* text, const char* retText,
                         int direction, const BYTE* payload, ULONG payloadLen) {
    if (!hdr) return;
    LONG cap = (LONG)hdr->capacity;
    LONG tail = InterlockedExchangeAdd(&hdr->tail, 1);
    if (tail - hdr->head >= cap) {
        InterlockedIncrement(&hdr->overflowDrop);
        InterlockedExchangeAdd(&hdr->tail, -1);
        return;
    }
    int idx = tail % cap;
    HEHookEvent* e = &evt[idx];
    ZeroMemory(e, sizeof(HEHookEvent));
    e->ts = ring_now_for(hdr);
    e->pid = GetCurrentProcessId();
    e->tid = GetCurrentThreadId();
    e->apiId = apiId;
    e->argCount = argCount > HE_MAX_ARGS ? HE_MAX_ARGS : argCount;
    for (ULONG i = 0; i < e->argCount; i++) e->args[i] = args[i];
    e->ret = ret;
    if (text) {
        strncpy(e->text, text, HE_ARG_TEXT - 1);
        e->text[HE_ARG_TEXT - 1] = 0;
    }
    if (retText) {
        strncpy(e->retText, retText, HE_RET_TEXT - 1);
        e->retText[HE_RET_TEXT - 1] = 0;
    }
    e->direction = direction;
    if (payload && payloadLen > 0) {
        ULONG n = payloadLen > HE_PAYLOAD_MAX ? HE_PAYLOAD_MAX : payloadLen;
        __try {
            CopyMemory(e->payload, payload, n);
            e->payloadLen = n;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            e->payloadLen = 0;
        }
    }
    MemoryBarrier();
    InterlockedExchangeAdd(&hdr->committed, 1);  // publish slot
}

static void ring_emit(ULONG apiId, ULONG argCount, const ULONG_PTR* args,
                      ULONG_PTR ret, const char* text, const char* retText,
                      int direction, const BYTE* payload = NULL, ULONG payloadLen = 0) {
    ring_emit_to(g_hdr, g_evt, apiId, argCount, args, ret, text, retText, direction, payload, payloadLen);
}

static void net_emit(ULONG apiId, ULONG argCount, const ULONG_PTR* args,
                     ULONG_PTR ret, const char* text, const char* retText,
                     int direction, const BYTE* payload = NULL, ULONG payloadLen = 0) {
    ring_emit_to(g_netHdr, g_netEvt, apiId, argCount, args, ret, text, retText, direction, payload, payloadLen);
}

static ULONG ring_available(const HERingHeader* hdr) {
    if (!hdr) return 0;
    return (ULONG)(hdr->committed - hdr->head);
}

static ULONG ring_read(HERingHeader* hdr, HEHookEvent* evt, HEHookEvent* out, ULONG maxCount) {
    if (!hdr || !evt || !out || maxCount == 0) return 0;
    LONG cap = (LONG)hdr->capacity;
    ULONG n = 0, avail = ring_available(hdr);
    if (avail > maxCount) avail = maxCount;
    LONG first = hdr->head;
    for (ULONG i = 0; i < avail; i++) {
        int idx = (int)((first + i) % cap);
        out[i] = evt[idx];
        n++;
    }
    InterlockedExchangeAdd(&hdr->head, (LONG)n);
    return n;
}

static void ring_clear(HERingHeader* hdr) {
    if (!hdr) return;
    InterlockedExchange(&hdr->head, hdr->committed);
}

ULONG HE_API he_events_available(void) {
    return ring_available(g_hdr);
}

ULONG HE_API he_read_events(HEHookEvent* out, ULONG maxCount) {
    return ring_read(g_hdr, g_evt, out, maxCount);
}

void HE_API he_clear_events(void) {
    ring_clear(g_hdr);
}

ULONG HE_API he_net_events_available(void) {
    return ring_available(g_netHdr);
}

ULONG HE_API he_net_read_events(HEHookEvent* out, ULONG maxCount) {
    return ring_read(g_netHdr, g_netEvt, out, maxCount);
}

void HE_API he_net_clear_events(void) {
    ring_clear(g_netHdr);
}

// ============================================================
// Catalog + inline hooking
// ============================================================
static ULONG g_hookFlags[256];
static ULONG g_callCount[256];
static HMODULE g_self;   // set in DllMain

typedef ULONG_PTR (*HeReadFunc)(ULONG apiId, ULONG argIndex);
typedef struct {
    HMODULE      hMod;
    const char*  dll;
    const char*  func;
    void*        origAddr;
    void*        trampoline;
    BYTE         origBytes[16];
    int          origLen;
    HEApiInfo    info;
    int          is64;
} HookSlot;

#define HE_CAT 64
static HookSlot g_slots[HE_CAT];
static int      g_slotCount = 0;
static ULONG    g_version = 0x00010001;

static HMODULE get_dll(const char* name) {
    HMODULE m = GetModuleHandleA(name);
    if (!m) m = LoadLibraryA(name);
    return m;
}

// ---------------- formatting helpers ----------------
static void fmt_wstr(char* out, size_t cap, const void* p) {
    if (!p) { strncpy(out, "(null)", cap - 1); return; }
    __try {
        const wchar_t* w = (const wchar_t*)p;
        char tmp[128];
        size_t n = 0;
        for (size_t i = 0; i < 63 && w[i] && n < sizeof(tmp) - 1; i++) {
            char uc = (char)w[i];
            if (uc < 32 || (BYTE)uc >= 0x7F) tmp[n++] = '?';
            else tmp[n++] = uc;
        }
        tmp[n] = 0;
        snprintf(out, cap, "\"%s\"", tmp);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        strncpy(out, "(bad ptr)", cap - 1);
    }
}

static void fmt_astr(char* out, size_t cap, const void* p) {
    if (!p) { strncpy(out, "(null)", cap - 1); return; }
    __try {
        const char* c = (const char*)p;
        char tmp[128];
        size_t n = 0;
        for (size_t i = 0; i < 127 && c[i] && n < sizeof(tmp) - 1; i++) {
            char ch = c[i];
            if ((BYTE)ch < 32 || (BYTE)ch >= 0x7F) tmp[n++] = '?';
            else tmp[n++] = ch;
        }
        tmp[n] = 0;
        snprintf(out, cap, "\"%s\"", tmp);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        strncpy(out, "(bad ptr)", cap - 1);
    }
}

static void fmt_buf(char* out, size_t cap, const void* p, ULONG len) {
    if (!p || len > 512) { snprintf(out, cap, "0x%p,len=%lu%s", p, len, len>512?"+":" "); return; }
    __try {
        const BYTE* b = (const BYTE*)p;
        char tmp[160];
        size_t n = 0;
        for (ULONG i = 0; i < len && n < sizeof(tmp) - 1; i++) {
            BYTE ch = b[i];
            if (ch >= 0x20 && ch < 0x7F) tmp[n++] = (char)ch;
            else tmp[n++] = '.';
        }
        tmp[n] = 0;
        snprintf(out, cap, "len=%lu \"%s\"", len, tmp);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        snprintf(out, cap, "0x%p,len=%lu", p, len);
    }
}

// ============================================================
// Catalog entries & typed shims
// ============================================================

static void fill_slot(int idx, const char* dll, const char* func,
                      const char* retKind, const char* argKinds, ULONG risk,
                      BOOL net, void* shim) {
    HookSlot* s = &g_slots[idx];
    ZeroMemory(s, sizeof(HookSlot));
    s->dll = dll; s->func = func;
    strncpy(s->info.module, dll, sizeof(s->info.module) - 1);
    strncpy(s->info.name, func, sizeof(s->info.name) - 1);
    strncpy(s->info.retKind, retKind, sizeof(s->info.retKind) - 1);
    s->info.argCount = 0;
    if (argKinds) {
        int kc = 0;
        const char* p = argKinds;
        while (*p && kc < HE_MAX_ARGS) {
            if (*p != ',') {
                char* dst = s->info.argKinds[kc];
                const char* cs = strchr(p, ',');
                size_t kl = cs ? (size_t)(cs - p) : 7;
                if (kl > 7) kl = 7;
                strncpy(dst, p, kl);
                dst[kl] = 0;
                kc++;
            }
            const char* cs = strchr(p, ',');
            if (!cs) break;
            p = cs + 1;
        }
        s->info.argCount = (ULONG)kc;
    }
    s->info.risk = risk;
    s->info.netRelated = net;
    s->is64 = 1;   // x64 engine only
    s->hMod = NULL;
    s->origAddr = NULL;
    s->trampoline = NULL;
    g_slotCount = idx + 1;
}

// forward decls of shims
typedef void* (WINAPI *pCreateFileW)(const wchar_t*, DWORD, DWORD, void*, DWORD, DWORD, void*);
typedef BOOL (WINAPI *pReadFile)(void*, void*, DWORD, DWORD*, void*);
typedef BOOL (WINAPI *pWriteFile)(void*, const void*, DWORD, DWORD*, void*);
typedef BOOL (WINAPI *pCreateProcessW)(const wchar_t*, wchar_t*, void*, void*, BOOL, DWORD,
                                       void*, const wchar_t*, void*, void*);
typedef void* (WINAPI *pVirtualAlloc)(void*, SIZE_T, DWORD, DWORD);
typedef BOOL (WINAPI *pVirtualProtect)(void*, SIZE_T, DWORD, DWORD*);
typedef HMODULE (WINAPI *pLoadLibraryW)(const wchar_t*);
typedef FARPROC (WINAPI *pGetProcAddress)(HMODULE, const char*);
typedef void* (WINAPI *pOpenProcess)(DWORD, BOOL, DWORD);
typedef BOOL (WINAPI *pTerminateProcess)(void*, UINT);
typedef void* (WINAPI *pCreateRemoteThread)(void*, void*, SIZE_T, void*, void*, DWORD, void*);
typedef BOOL (WINAPI *pWriteProcessMemory)(void*, void*, const void*, SIZE_T, SIZE_T*);
typedef BOOL (WINAPI *pReadProcessMemory)(void*, void*, void*, SIZE_T, SIZE_T*);
typedef BOOL (WINAPI *pDeleteFileW)(const wchar_t*);
typedef BOOL (WINAPI *pCopyFileW)(const wchar_t*, const wchar_t*, BOOL);
typedef void (WINAPI *pSleep)(DWORD);
typedef LONG (WINAPI *pRegOpenKeyExW)(void*, const wchar_t*, DWORD, DWORD, void*);
typedef LONG (WINAPI *pRegSetValueExW)(void*, const wchar_t*, DWORD, DWORD, const BYTE*, DWORD);
typedef void* (WINAPI *pOpenSCManagerW)(const wchar_t*, const wchar_t*, DWORD);
typedef void* (WINAPI *pCreateServiceW)(void*, const wchar_t*, const wchar_t*, DWORD, DWORD, DWORD,
                                        const wchar_t*, void*, void*, const wchar_t*, const wchar_t*, const wchar_t*);
typedef BOOL (WINAPI *pStartServiceW)(void*, DWORD, const wchar_t* const*);
typedef int (WINAPI *pSend)(void*, const char*, int, int);
typedef int (WINAPI *pRecv)(void*, char*, int, int);
typedef int (WINAPI *pSendTo)(void*, const char*, int, int, const void*, int);
typedef int (WINAPI *pRecvFrom)(void*, char*, int, int, void*, int*);
typedef int (WINAPI *pClosesocket)(void*);
typedef int (WINAPI *pWsaSend)(void*, void*, DWORD, DWORD*, DWORD, void*, void*);
typedef int (WINAPI *pWsaRecv)(void*, void*, DWORD, DWORD*, DWORD*, void*, void*);
typedef int (WINAPI *pConnect)(void*, const void*, int);
typedef void* (WINAPI *pFindWindowW)(const wchar_t*, const wchar_t*);
typedef LONG (WINAPI *pRegCreateKeyExW)(void*, const wchar_t*, DWORD, wchar_t*, DWORD, DWORD, void*,
                                        void*, DWORD*);

// ntdll / user32 / kernel32 / wininet / urlmon / ws2_32 additions
typedef LONG (WINAPI *pNtCreateFile)(void*, ULONG, void*, void*, void*, ULONG, ULONG, ULONG, ULONG, void*, ULONG);
typedef LONG (WINAPI *pNtWriteVirtualMemory)(void*, void*, const void*, SIZE_T, SIZE_T*);
typedef LONG (WINAPI *pNtProtectVirtualMemory)(void*, void*, SIZE_T*, ULONG, ULONG*);
typedef LONG (WINAPI *pNtAllocateVirtualMemory)(void*, void*, ULONG_PTR, SIZE_T*, ULONG, ULONG);
typedef LONG (WINAPI *pNtCreateThreadEx)(void*, ULONG, void*, void*, void*, void*, ULONG, SIZE_T, SIZE_T, SIZE_T, ULONG*);
typedef SHORT (WINAPI *pGetAsyncKeyState)(int);
typedef SHORT (WINAPI *pGetKeyState)(int);
typedef void* (WINAPI *pSetWindowsHookExW)(int, void*, void*, DWORD);
typedef void* (WINAPI *pGetClipboardData)(UINT);
typedef void (WINAPI *pKeybdEvent)(BYTE, BYTE, DWORD, ULONG_PTR);
typedef LONG_PTR (WINAPI *pSendMessageW)(void*, UINT, WPARAM, LPARAM);
typedef void* (WINAPI *pCreateThread)(void*, SIZE_T, void*, void*, DWORD, void*);
typedef BOOL (WINAPI *pMoveFileW)(const wchar_t*, const wchar_t*);
typedef void* (WINAPI *pVirtualAllocEx)(void*, void*, SIZE_T, DWORD, DWORD);
typedef void* (WINAPI *pInternetOpenW)(const wchar_t*, DWORD, const wchar_t*, const wchar_t*, DWORD);
typedef BOOL (WINAPI *pHttpSendRequestW)(void*, const wchar_t*, DWORD, void*, DWORD);
typedef LONG (WINAPI *pUrlDownloadToFileW)(void*, const wchar_t*, const wchar_t*, DWORD, void*);
typedef int (WINAPI *pGetAddrInfo)(const char*, const char*, const struct addrinfo*, struct addrinfo**);

// ---------- shims ----------
static void* WINAPI sh_CreateFileW(const wchar_t* p1, DWORD p2, DWORD p3, void* p4, DWORD p5, DWORD p6, void* p7);
static BOOL  WINAPI sh_ReadFile(void* h, void* buf, DWORD n, DWORD* read, void* ov);
static BOOL  WINAPI sh_WriteFile(void* h, const void* buf, DWORD n, DWORD* wr, void* ov);
static BOOL  WINAPI sh_CreateProcessW(const wchar_t* a, wchar_t* b, void* c, void* d, BOOL e, DWORD f, void* g, const wchar_t* h, void* i, void* j);
static void* WINAPI sh_VirtualAlloc(void* a, SIZE_T b, DWORD c, DWORD d);
static BOOL  WINAPI sh_VirtualProtect(void* a, SIZE_T b, DWORD c, DWORD* d);
static HMODULE WINAPI sh_LoadLibraryW(const wchar_t* a);
static FARPROC WINAPI sh_GetProcAddress(HMODULE a, const char* b);
static void* WINAPI sh_OpenProcess(DWORD a, BOOL b, DWORD c);
static BOOL  WINAPI sh_TerminateProcess(void* a, UINT b);
static void* WINAPI sh_CreateRemoteThread(void* a, void* b, SIZE_T c, void* d, void* e, DWORD f, void* g);
static BOOL  WINAPI sh_WriteProcessMemory(void* a, void* b, const void* c, SIZE_T d, SIZE_T* e);
static BOOL  WINAPI sh_ReadProcessMemory(void* a, void* b, void* c, SIZE_T d, SIZE_T* e);
static BOOL  WINAPI sh_DeleteFileW(const wchar_t* a);
static BOOL  WINAPI sh_CopyFileW(const wchar_t* a, const wchar_t* b, BOOL c);
static void  WINAPI sh_Sleep(DWORD a);
static LONG  WINAPI sh_RegOpenKeyExW(void* a, const wchar_t* b, DWORD c, DWORD d, void* e);
static LONG  WINAPI sh_RegSetValueExW(void* a, const wchar_t* b, DWORD c, DWORD d, const BYTE* e, DWORD f);
static void* WINAPI sh_OpenSCManagerW(const wchar_t* a, const wchar_t* b, DWORD c);
static void* WINAPI sh_CreateServiceW(void* a, const wchar_t* b, const wchar_t* c, DWORD d, DWORD e, DWORD f, const wchar_t* g, void* h, void* i, const wchar_t* j, const wchar_t* k, const wchar_t* l);
static BOOL  WINAPI sh_StartServiceW(void* a, DWORD b, const wchar_t* const* c);
static int   WINAPI sh_send(void* s, const char* buf, int len, int flags);
static int   WINAPI sh_recv(void* s, char* buf, int len, int flags);
static int   WINAPI sh_sendto(void* s, const char* buf, int len, int flags, const void* to, int tolen);
static int   WINAPI sh_recvfrom(void* s, char* buf, int len, int flags, void* from, int* fromlen);
static int   WINAPI sh_closesocket(void* s);
static int   WINAPI sh_WsaSend(void* s, void* lpBuffers, DWORD count, DWORD* sent, DWORD flags, void* ov, void* comp);
static int   WINAPI sh_WsaRecv(void* s, void* lpBuffers, DWORD count, DWORD* recvd, DWORD* flags, void* ov, void* comp);
static int   WINAPI sh_connect(void* s, const void* name, int namelen);
static void* WINAPI sh_FindWindowW(const wchar_t* a, const wchar_t* b);
static LONG  WINAPI sh_RegCreateKeyExW(void* a, const wchar_t* b, DWORD c, wchar_t* d, DWORD e, DWORD f, void* g, void* h, DWORD* i);
static LONG  WINAPI sh_NtCreateFile(void* a, ULONG b, void* c, void* d, void* e, ULONG f, ULONG g, ULONG h, ULONG i, void* j, ULONG k);
static LONG  WINAPI sh_NtWriteVirtualMemory(void* a, void* b, const void* c, SIZE_T d, SIZE_T* e);
static LONG  WINAPI sh_NtProtectVirtualMemory(void* a, void* b, SIZE_T* c, ULONG d, ULONG* e);
static LONG  WINAPI sh_NtAllocateVirtualMemory(void* a, void* b, ULONG_PTR c, SIZE_T* d, ULONG e, ULONG f);
static LONG  WINAPI sh_NtCreateThreadEx(void* a, ULONG b, void* c, void* d, void* e, void* f, ULONG g, SIZE_T h, SIZE_T i, SIZE_T j, ULONG* k);
static SHORT WINAPI sh_GetAsyncKeyState(int a);
static SHORT WINAPI sh_GetKeyState(int a);
static void* WINAPI sh_SetWindowsHookExW(int a, void* b, void* c, DWORD d);
static void* WINAPI sh_GetClipboardData(UINT a);
static void  WINAPI sh_keybd_event(BYTE a, BYTE b, DWORD c, ULONG_PTR d);
static LONG_PTR WINAPI sh_SendMessageW(void* a, UINT b, WPARAM c, LPARAM d);
static void* WINAPI sh_CreateThread(void* a, SIZE_T b, void* c, void* d, DWORD e, void* f);
static BOOL  WINAPI sh_MoveFileW(const wchar_t* a, const wchar_t* b);
static void* WINAPI sh_VirtualAllocEx(void* a, void* b, SIZE_T c, DWORD d, DWORD e);
static void* WINAPI sh_InternetOpenW(const wchar_t* a, DWORD b, const wchar_t* c, const wchar_t* d, DWORD e);
static BOOL  WINAPI sh_HttpSendRequestW(void* a, const wchar_t* b, DWORD c, void* d, DWORD e);
static LONG  WINAPI sh_UrlDownloadToFileW(void* a, const wchar_t* b, const wchar_t* c, DWORD d, void* e);
static int   WINAPI sh_getaddrinfo(const char* a, const char* b, const struct addrinfo* c, struct addrinfo** d);

// trampoline slots
static pCreateFileW        tp_CreateFileW;
static pReadFile           tp_ReadFile;
static pWriteFile          tp_WriteFile;
static pCreateProcessW     tp_CreateProcessW;
static pVirtualAlloc       tp_VirtualAlloc;
static pVirtualProtect     tp_VirtualProtect;
static pLoadLibraryW       tp_LoadLibraryW;
static pGetProcAddress     tp_GetProcAddress;
static pOpenProcess        tp_OpenProcess;
static pTerminateProcess   tp_TerminateProcess;
static pCreateRemoteThread tp_CreateRemoteThread;
static pWriteProcessMemory tp_WriteProcessMemory;
static pReadProcessMemory  tp_ReadProcessMemory;
static pDeleteFileW        tp_DeleteFileW;
static pCopyFileW          tp_CopyFileW;
static pSleep              tp_Sleep;
static pRegOpenKeyExW      tp_RegOpenKeyExW;
static pRegSetValueExW     tp_RegSetValueExW;
static pOpenSCManagerW     tp_OpenSCManagerW;
static pCreateServiceW     tp_CreateServiceW;
static pStartServiceW      tp_StartServiceW;
static pSend               tp_send;
static pRecv               tp_recv;
static pSendTo             tp_sendto;
static pRecvFrom           tp_recvfrom;
static pClosesocket        tp_closesocket;
static pWsaSend            tp_WsaSend;
static pWsaRecv            tp_WsaRecv;
static pConnect            tp_connect;
static pFindWindowW        tp_FindWindowW;
static pRegCreateKeyExW    tp_RegCreateKeyExW;
static pNtCreateFile       tp_NtCreateFile;
static pNtWriteVirtualMemory tp_NtWriteVirtualMemory;
static pNtProtectVirtualMemory tp_NtProtectVirtualMemory;
static pNtAllocateVirtualMemory tp_NtAllocateVirtualMemory;
static pNtCreateThreadEx   tp_NtCreateThreadEx;
static pGetAsyncKeyState   tp_GetAsyncKeyState;
static pGetKeyState        tp_GetKeyState;
static pSetWindowsHookExW  tp_SetWindowsHookExW;
static pGetClipboardData   tp_GetClipboardData;
static pKeybdEvent         tp_keybd_event;
static pSendMessageW       tp_SendMessageW;
static pCreateThread       tp_CreateThread;
static pMoveFileW          tp_MoveFileW;
static pVirtualAllocEx     tp_VirtualAllocEx;
static pInternetOpenW      tp_InternetOpenW;
static pHttpSendRequestW   tp_HttpSendRequestW;
static pUrlDownloadToFileW tp_UrlDownloadToFileW;
static pGetAddrInfo        tp_getaddrinfo;

static ULONG g_netCaptureMask = HE_NET_CAPTURE_SEND | HE_NET_CAPTURE_RECV |
                                HE_NET_CAPTURE_SENDTO | HE_NET_CAPTURE_RECVFROM;
static HEModRule g_modRules[HE_MAX_MOD_RULES];
static BOOL g_rulesInit = FALSE;

static void rules_apply(BYTE* ioBuf, ULONG* ioLen, int direction) {
    if (!g_rulesInit) {
        ZeroMemory(g_modRules, sizeof(g_modRules));
        g_rulesInit = TRUE;
    }
    for (int r = 0; r < HE_MAX_MOD_RULES; r++) {
        HEModRule* m = &g_modRules[r];
        if (!m->active || m->findLen == 0 || m->findLen > *ioLen) continue;
        if ((m->direction < 0 && direction > 0) || (m->direction > 0 && direction < 0)) continue;
        // find & replace first occurrence
        for (ULONG i = 0; i + m->findLen <= *ioLen; i++) {
            int eq = 1;
            for (ULONG j = 0; j < m->findLen; j++) {
                if (ioBuf[i + j] != m->find[j]) { eq = 0; break; }
            }
            if (eq) {
                ULONG dLen = m->replaceLen;
                if (dLen > m->findLen) dLen = m->findLen;
                CopyMemory(ioBuf + i, m->replace, dLen);
                // padding
                for (ULONG j = dLen; j < m->findLen; j++) ioBuf[i + j] = m->replace[dLen - 1];
                break;
            }
        }
    }
}

static void log_net(const HEHookEvent* e, const char* netText) {
    // netText appended to text already done in shim; nothing to do here
}

// implement shims; log args BEFORE calling original (data may be mutated)
static void* WINAPI sh_CreateFileW(const wchar_t* p1, DWORD p2, DWORD p3, void* p4, DWORD p5, DWORD p6, void* p7) {
    ULONG_PTR a[6] = { (ULONG_PTR)p1, p2, p3, (ULONG_PTR)p4, p5, (ULONG_PTR)p7 };
    char txt[HE_ARG_TEXT] = {0};
    fmt_wstr(txt, sizeof(txt), p1);
    ULONG id = 0;
    if (tp_CreateFileW) {
        interlocked:
        {
            static ULONG cnt; (void)cnt;
        }
        void* r = tp_CreateFileW(p1, p2, p3, p4, p5, p6, p7);
        char rt[32]; if ((ULONG_PTR)r == (ULONG_PTR)INVALID_HANDLE_VALUE) sprintf(rt, "INVALID_HANDLE"); else sprintf(rt, "0x%p", r);
        ring_emit(id, 6, a, (ULONG_PTR)r, txt, rt, 0);
        g_callCount[id]++;
        return r;
    }
    return INVALID_HANDLE_VALUE;
}

static BOOL WINAPI sh_ReadFile(void* h, void* buf, DWORD n, DWORD* read, void* ov) {
    ULONG id = 1;
    ULONG_PTR a[6] = { (ULONG_PTR)h, (ULONG_PTR)buf, n, (ULONG_PTR)read, (ULONG_PTR)ov, 0 };
    char txt[HE_ARG_TEXT] = {0};
    sprms: { char hh[32]; sprintf(hh, "h=0x%p ", h); strcat(txt, hh); char nn[24]; sprintf(nn, "n=%lu", n); strcat(txt, nn); }
    BOOL r = tp_ReadFile(h, buf, n, read, ov);
    char rt[32]; sprintf(rt, "%s", r ? "TRUE" : "FALSE");
    char post[HE_RET_TEXT];
    if (r && read) sprintf(post, "TRUE read=%lu", *read); else sprintf(post, "%s", rt);
    ring_emit(id, 5, a, (ULONG_PTR)r, txt, post, 0);
    g_callCount[id]++;
    return r;
}

static BOOL WINAPI sh_WriteFile(void* h, const void* buf, DWORD n, DWORD* wr, void* ov) {
    ULONG id = 2;
    ULONG_PTR a[6] = { (ULONG_PTR)h, (ULONG_PTR)buf, n, (ULONG_PTR)wr, (ULONG_PTR)ov, 0 };
    char txt[HE_ARG_TEXT] = {0};
    { char hh[32]; sprintf(hh, "h=0x%p ", h); strcat(txt, hh); fmt_buf(txt + strlen(txt), sizeof(txt) - strlen(txt), buf, n); }
    BOOL r = tp_WriteFile(h, buf, n, wr, ov);
    char post[HE_RET_TEXT] = {0};
    if (r && wr) sprintf(post, "TRUE written=%lu", *wr); else sprintf(post, "FALSE");
    ring_emit(id, 5, a, (ULONG_PTR)r, txt, post, 0);
    g_callCount[id]++;
    return r;
}

static BOOL WINAPI sh_CreateProcessW(const wchar_t* a, wchar_t* b, void* c, void* d, BOOL e, DWORD f, void* g, const wchar_t* h, void* i, void* j) {
    ULONG id = 3;
    ULONG_PTR arg[6] = { (ULONG_PTR)a, (ULONG_PTR)b, (ULONG_PTR)h, f, (ULONG_PTR)i, (ULONG_PTR)j };
    char txt[HE_ARG_TEXT] = {0};
    fmt_wstr(txt, sizeof(txt), a);
    if (b) { strcat(txt, " argv="); fmt_wstr(txt + strlen(txt), sizeof(txt) - strlen(txt), b); }
    BOOL r = tp_CreateProcessW(a, b, c, d, e, f, g, h, i, j);
    char post[HE_RET_TEXT] = {0};
    if (r && i) {
        void* pi = *(void**)i;
        if (pi) {
            DWORD pid = *(DWORD*)((BYTE*)pi + 8);
            sprintf(post, "TRUE pid=%lu", pid);
        } else sprintf(post, "TRUE");
    } else sprintf(post, "FALSE");
    ring_emit(id, 6, arg, (ULONG_PTR)r, txt, post, 0);
    g_callCount[id]++;
    return r;
}

static void* WINAPI sh_VirtualAlloc(void* a, SIZE_T b, DWORD c, DWORD d) {
    ULONG id = 4;
    ULONG_PTR arg[6] = { (ULONG_PTR)a, (ULONG_PTR)b, c, d, 0, 0 };
    char txt[HE_ARG_TEXT] = {0};
    sprintf(txt, "size=0x%zx flags=0x%x prot=0x%x", b, d, c);
    void* r = tp_VirtualAlloc(a, b, c, d);
    char post[HE_RET_TEXT] = {0}; sprintf(post, "0x%p", r);
    ring_emit(id, 4, arg, (ULONG_PTR)r, txt, post, 0);
    g_callCount[id]++;
    return r;
}

static BOOL WINAPI sh_VirtualProtect(void* a, SIZE_T b, DWORD c, DWORD* d) {
    ULONG id = 5;
    ULONG_PTR arg[6] = { (ULONG_PTR)a, (ULONG_PTR)b, c, (ULONG_PTR)d, 0, 0 };
    char txt[HE_ARG_TEXT] = {0};
    sprintf(txt, "addr=0x%p size=0x%zx new_prot=0x%x", a, b, c);
    BOOL r = tp_VirtualProtect(a, b, c, d);
    char post[HE_RET_TEXT] = {0};
    sprintf(post, "%s old_prot=0x%x", r ? "TRUE" : "FALSE", d ? *d : 0);
    ring_emit(id, 4, arg, (ULONG_PTR)r, txt, post, 0);
    g_callCount[id]++;
    return r;
}

static HMODULE WINAPI sh_LoadLibraryW(const wchar_t* a) {
    ULONG id = 6;
    ULONG_PTR arg[6] = { (ULONG_PTR)a, 0, 0, 0, 0, 0 };
    char txt[HE_ARG_TEXT] = {0}; fmt_wstr(txt, sizeof(txt), a);
    HMODULE r = tp_LoadLibraryW(a);
    char post[HE_RET_TEXT] = {0}; sprintf(post, "0x%p", r);
    ring_emit(id, 1, arg, (ULONG_PTR)r, txt, post, 0);
    g_callCount[id]++;
    return r;
}

static FARPROC WINAPI sh_GetProcAddress(HMODULE a, const char* b) {
    ULONG id = 7;
    ULONG_PTR arg[6] = { (ULONG_PTR)a, (ULONG_PTR)b, 0, 0, 0, 0 };
    char txt[HE_ARG_TEXT] = {0};
    char hh[32]; sprintf(hh, "m=0x%p ", a); strcat(txt, hh); fmt_astr(txt + strlen(txt), sizeof(txt) - strlen(txt), b);
    FARPROC r = tp_GetProcAddress(a, b);
    char post[HE_RET_TEXT] = {0}; sprintf(post, "0x%p", r);
    ring_emit(id, 2, arg, (ULONG_PTR)r, txt, post, 0);
    g_callCount[id]++;
    return r;
}

static void* WINAPI sh_OpenProcess(DWORD a, BOOL b, DWORD c) {
    ULONG id = 8;
    ULONG_PTR arg[6] = { a, (ULONG_PTR)b, c, 0, 0, 0 };
    char txt[HE_ARG_TEXT] = {0};
    sprintf(txt, "access=0x%x inherit=%s pid=%lu", a, b ? "true" : "false", c);
    void* r = tp_OpenProcess(a, b, c);
    char post[HE_RET_TEXT] = {0}; sprintf(post, "0x%p", r);
    ring_emit(id, 3, arg, (ULONG_PTR)r, txt, post, 0);
    g_callCount[id]++;
    return r;
}

static BOOL WINAPI sh_TerminateProcess(void* a, UINT b) {
    ULONG id = 9;
    ULONG_PTR arg[6] = { (ULONG_PTR)a, b, 0, 0, 0, 0 };
    char txt[HE_ARG_TEXT] = {0}; sprintf(txt, "h=0x%p exit=%u", a, b);
    BOOL r = tp_TerminateProcess(a, b);
    char post[HE_RET_TEXT] = {0}; sprintf(post, "%s", r ? "TRUE" : "FALSE");
    ring_emit(id, 2, arg, (ULONG_PTR)r, txt, post, 0);
    g_callCount[id]++;
    return r;
}

static void* WINAPI sh_CreateRemoteThread(void* a, void* b, SIZE_T c, void* d, void* e, DWORD f, void* g) {
    ULONG id = 10;
    ULONG_PTR arg[6] = { (ULONG_PTR)a, (ULONG_PTR)b, (ULONG_PTR)c, (ULONG_PTR)d, (ULONG_PTR)e, (ULONG_PTR)g };
    char txt[HE_ARG_TEXT] = {0};
    sprintf(txt, "h=0x%p start=0x%p param=0x%p flags=0x%x", a, d, e, f);
    void* r = tp_CreateRemoteThread(a, b, c, d, e, f, g);
    char post[HE_RET_TEXT] = {0}; sprintf(post, "0x%p", r);
    ring_emit(id, 6, arg, (ULONG_PTR)r, txt, post, 0);
    g_callCount[id]++;
    return r;
}

static BOOL WINAPI sh_WriteProcessMemory(void* a, void* b, const void* c, SIZE_T d, SIZE_T* e) {
    ULONG id = 11;
    ULONG_PTR arg[6] = { (ULONG_PTR)a, (ULONG_PTR)b, (ULONG_PTR)c, (ULONG_PTR)d, (ULONG_PTR)e, 0 };
    char txt[HE_ARG_TEXT] = {0};
    char hh[40]; sprintf(hh, "h=0x%p addr=0x%p size=%zu", a, b, d); strcat(txt, hh);
    BOOL r = tp_WriteProcessMemory(a, b, c, d, e);
    char post[HE_RET_TEXT] = {0};
    if (r && e) sprintf(post, "TRUE written=%zu", *e); else sprintf(post, "FALSE");
    ring_emit(id, 5, arg, (ULONG_PTR)r, txt, post, 0);
    g_callCount[id]++;
    return r;
}

static BOOL WINAPI sh_ReadProcessMemory(void* a, void* b, void* c, SIZE_T d, SIZE_T* e) {
    ULONG id = 12;
    ULONG_PTR arg[6] = { (ULONG_PTR)a, (ULONG_PTR)b, (ULONG_PTR)c, (ULONG_PTR)d, (ULONG_PTR)e, 0 };
    char txt[HE_ARG_TEXT] = {0};
    sprintf(txt, "h=0x%p addr=0x%p size=%zu", a, b, d);
    BOOL r = tp_ReadProcessMemory(a, b, c, d, e);
    char post[HE_RET_TEXT] = {0};
    if (r && e) sprintf(post, "TRUE read=%zu", *e); else sprintf(post, "FALSE");
    ring_emit(id, 5, arg, (ULONG_PTR)r, txt, post, 0);
    g_callCount[id]++;
    return r;
}

static BOOL WINAPI sh_DeleteFileW(const wchar_t* a) {
    ULONG id = 13;
    ULONG_PTR arg[6] = { (ULONG_PTR)a, 0, 0, 0, 0, 0 };
    char txt[HE_ARG_TEXT] = {0}; fmt_wstr(txt, sizeof(txt), a);
    BOOL r = tp_DeleteFileW(a);
    char post[HE_RET_TEXT] = {0}; sprintf(post, "%s", r ? "TRUE" : "FALSE");
    ring_emit(id, 1, arg, (ULONG_PTR)r, txt, post, 0);
    g_callCount[id]++;
    return r;
}

static BOOL WINAPI sh_CopyFileW(const wchar_t* a, const wchar_t* b, BOOL c) {
    ULONG id = 14;
    ULONG_PTR arg[6] = { (ULONG_PTR)a, (ULONG_PTR)b, (ULONG_PTR)c, 0, 0, 0 };
    char txt[HE_ARG_TEXT] = {0};
    fmt_wstr(txt, sizeof(txt), a); strcat(txt, " -> "); fmt_wstr(txt + strlen(txt), sizeof(txt) - strlen(txt), b);
    BOOL r = tp_CopyFileW(a, b, c);
    char post[HE_RET_TEXT] = {0}; sprintf(post, "%s", r ? "TRUE" : "FALSE");
    ring_emit(id, 3, arg, (ULONG_PTR)r, txt, post, 0);
    g_callCount[id]++;
    return r;
}

static void WINAPI sh_Sleep(DWORD a) {
    ULONG id = 15;
    ULONG_PTR arg[6] = { a, 0, 0, 0, 0, 0 };
    char txt[HE_ARG_TEXT] = {0}; sprintf(txt, "ms=%lu", a);
    tp_Sleep(a);
    ring_emit(id, 1, arg, 0, txt, "void", 0);
    g_callCount[id]++;
}

static LONG WINAPI sh_RegOpenKeyExW(void* a, const wchar_t* b, DWORD c, DWORD d, void* e) {
    ULONG id = 16;
    ULONG_PTR arg[6] = { (ULONG_PTR)a, (ULONG_PTR)b, c, d, (ULONG_PTR)e, 0 };
    char txt[HE_ARG_TEXT] = {0};
    char hh[32]; sprintf(hh, "h=0x%p ", a); strcat(txt, hh); fmt_wstr(txt + strlen(txt), sizeof(txt) - strlen(txt), b);
    LONG r = tp_RegOpenKeyExW(a, b, c, d, e);
    char post[HE_RET_TEXT] = {0}; sprintf(post, "0x%lx", (ULONG)r);
    ring_emit(id, 5, arg, (ULONG_PTR)(LONG)r, txt, post, 0);
    g_callCount[id]++;
    return r;
}

static LONG WINAPI sh_RegSetValueExW(void* a, const wchar_t* b, DWORD c, DWORD d, const BYTE* e, DWORD f) {
    ULONG id = 17;
    ULONG_PTR arg[6] = { (ULONG_PTR)a, (ULONG_PTR)b, c, d, (ULONG_PTR)e, f };
    char txt[HE_ARG_TEXT] = {0};
    char hh[32]; sprintf(hh, "h=0x%p ", a); strcat(txt, hh); fmt_wstr(txt + strlen(txt), sizeof(txt) - strlen(txt), b);
    strcat(txt, " type=0x"); char tt[16]; sprintf(tt, "%x", d); strcat(txt, tt);
    LONG r = tp_RegSetValueExW(a, b, c, d, e, f);
    char post[HE_RET_TEXT] = {0}; sprintf(post, "0x%lx", (ULONG)r);
    ring_emit(id, 6, arg, (ULONG_PTR)(LONG)r, txt, post, 0);
    g_callCount[id]++;
    return r;
}

static void* WINAPI sh_OpenSCManagerW(const wchar_t* a, const wchar_t* b, DWORD c) {
    ULONG id = 18;
    ULONG_PTR arg[6] = { (ULONG_PTR)a, (ULONG_PTR)b, c, 0, 0, 0 };
    char txt[HE_ARG_TEXT] = {0};
    if (a) { fmt_wstr(txt, sizeof(txt), a); } else sprintf(txt, "(svc)");
    void* r = tp_OpenSCManagerW(a, b, c);
    char post[HE_RET_TEXT] = {0}; sprintf(post, "0x%p", r);
    ring_emit(id, 3, arg, (ULONG_PTR)r, txt, post, 0);
    g_callCount[id]++;
    return r;
}

static void* WINAPI sh_CreateServiceW(void* a, const wchar_t* b, const wchar_t* c, DWORD d, DWORD e, DWORD f, const wchar_t* g, void* h, void* i, const wchar_t* j, const wchar_t* k, const wchar_t* l) {
    ULONG id = 19;
    ULONG_PTR arg[6] = { (ULONG_PTR)a, (ULONG_PTR)b, (ULONG_PTR)c, d, f, 0 };
    char txt[HE_ARG_TEXT] = {0};
    fmt_wstr(txt, sizeof(txt), b); strcat(txt, " exe=");
    if (g) fmt_wstr(txt + strlen(txt), sizeof(txt) - strlen(txt), g); else strcat(txt, "(null)");
    void* r = tp_CreateServiceW(a, b, c, d, e, f, g, h, i, j, k, l);
    char post[HE_RET_TEXT] = {0}; sprintf(post, "0x%p", r);
    ring_emit(id, 6, arg, (ULONG_PTR)r, txt, post, 0);
    g_callCount[id]++;
    return r;
}

static BOOL WINAPI sh_StartServiceW(void* a, DWORD b, const wchar_t* const* c) {
    ULONG id = 20;
    ULONG_PTR arg[6] = { (ULONG_PTR)a, b, (ULONG_PTR)c, 0, 0, 0 };
    char txt[HE_ARG_TEXT] = {0}; sprintf(txt, "h=0x%p argc=%lu", a, b);
    BOOL r = tp_StartServiceW(a, b, c);
    char post[HE_RET_TEXT] = {0}; sprintf(post, "%s", r ? "TRUE" : "FALSE");
    ring_emit(id, 3, arg, (ULONG_PTR)r, txt, post, 0);
    g_callCount[id]++;
    return r;
}

// network shims with in-flight modification on send, post-read on recv
static int WINAPI sh_send(void* s, const char* buf, int len, int flags) {
    ULONG id = 21;
    BYTE stack[2048];
    auto bufPtr = (const char*)buf;
    ULONG modLen = len < 0 ? 0 : (ULONG)len;
    if (g_netHdr && (g_netCaptureMask & HE_NET_CAPTURE_SEND) && len > 0 && len <= (int)sizeof(stack)) {
        CopyMemory(stack, buf, (size_t)len);
        rules_apply(stack, &modLen, +1);
        bufPtr = (const char*)stack;
    }
    ULONG_PTR arg[6] = { (ULONG_PTR)s, (ULONG_PTR)buf, (ULONG)len, (ULONG)flags, 0, 0 };
    char txt[HE_ARG_TEXT] = {0};
    int r = tp_send(s, bufPtr, (int)(g_netCaptureMask & HE_NET_CAPTURE_SEND ? modLen : len), flags);
    char post[HE_RET_TEXT] = {0}; sprintf(post, "sent=%d", r);
    if (len > 0 && (g_netCaptureMask & HE_NET_CAPTURE_SEND)) {
        char b[96]; snprintf(b, sizeof(b), " OUT len=%d ", len); strcat(txt, b);
        fmt_buf(txt + strlen(txt), sizeof(txt) - strlen(txt), bufPtr, r > 0 ? (ULONG)r : (ULONG)len);
    }
    net_emit(id, 4, arg, (ULONG_PTR)r, txt, post, +1, (const BYTE*)bufPtr, r > 0 ? (ULONG)r : (ULONG)len);
    g_callCount[id]++;
    return r;
}

static int WINAPI sh_recv(void* s, char* buf, int len, int flags) {
    ULONG id = 22;
    ULONG_PTR arg[6] = { (ULONG_PTR)s, (ULONG_PTR)buf, (ULONG)len, (ULONG)flags, 0, 0 };
    int r = tp_recv(s, buf, len, flags);
    if (r > 0 && g_netHdr && (g_netCaptureMask & HE_NET_CAPTURE_RECV)) {
        ULONG l = (ULONG)r;
        rules_apply((BYTE*)buf, &l, -1);
    }
    char txt[HE_ARG_TEXT] = {0};
    char post[HE_RET_TEXT] = {0}; sprintf(post, "recv=%d", r);
    if (r > 0 && (g_netCaptureMask & HE_NET_CAPTURE_RECV)) {
        snprintf(txt, sizeof(txt), " IN len=%d ", r);
        fmt_buf(txt + strlen(txt), sizeof(txt) - strlen(txt), buf, (ULONG)r);
        strcat(post, " (shown post-modify)");
    }
    net_emit(id, 4, arg, (ULONG_PTR)r, txt, post, -1, r > 0 ? (const BYTE*)buf : NULL, r > 0 ? (ULONG)r : 0);
    g_callCount[id]++;
    return r;
}

static int WINAPI sh_sendto(void* s, const char* buf, int len, int flags, const void* to, int tolen) {
    ULONG id = 23;
    BYTE stack[2048];
    auto bufPtr = buf;
    if (g_netHdr && (g_netCaptureMask & HE_NET_CAPTURE_SENDTO) && len > 0 && len <= (int)sizeof(stack)) {
        CopyMemory(stack, buf, (size_t)len);
        ULONG ml = (ULONG)len; rules_apply(stack, &ml, +1);
        bufPtr = (const char*)stack;
    }
    ULONG_PTR arg[6] = { (ULONG_PTR)s, (ULONG_PTR)buf, (ULONG)len, (ULONG)tolen, 0, 0 };
    char txt[HE_ARG_TEXT] = {0};
    int r = tp_sendto(s, bufPtr, len, flags, to, tolen);
    char post[HE_RET_TEXT] = {0}; sprintf(post, "sentto=%d", r);
    if (len > 0 && (g_netCaptureMask & HE_NET_CAPTURE_SENDTO)) {
        snprintf(txt, sizeof(txt), " UDP OUT len=%d ", len);
        fmt_buf(txt + strlen(txt), sizeof(txt) - strlen(txt), bufPtr, (ULONG)len);
    }
    net_emit(id, 4, arg, (ULONG_PTR)r, txt, post, +1, (const BYTE*)bufPtr, (ULONG)len);
    g_callCount[id]++;
    return r;
}

static int WINAPI sh_recvfrom(void* s, char* buf, int len, int flags, void* from, int* fromlen) {
    ULONG id = 24;
    ULONG_PTR arg[6] = { (ULONG_PTR)s, (ULONG_PTR)buf, (ULONG)len, (ULONG_PTR)from, 0, 0 };
    int r = tp_recvfrom(s, buf, len, flags, from, fromlen);
    char txt[HE_ARG_TEXT] = {0};
    char post[HE_RET_TEXT] = {0}; sprintf(post, "recvfrom=%d", r);
    if (r > 0 && (g_netCaptureMask & HE_NET_CAPTURE_RECVFROM)) {
        snprintf(txt, sizeof(txt), " UDP IN len=%d ", r);
        fmt_buf(txt + strlen(txt), sizeof(txt) - strlen(txt), buf, (ULONG)r);
    }
    net_emit(id, 4, arg, (ULONG_PTR)r, txt, post, -1, r > 0 ? (const BYTE*)buf : NULL, r > 0 ? (ULONG)r : 0);
    g_callCount[id]++;
    return r;
}

static int WINAPI sh_closesocket(void* s) {
    ULONG id = 25;
    ULONG_PTR arg[6] = { (ULONG_PTR)s, 0, 0, 0, 0, 0 };
    char txt[HE_ARG_TEXT] = {0}; sprintf(txt, "s=0x%p", s);
    int r = tp_closesocket(s);
    char post[HE_RET_TEXT] = {0}; sprintf(post, "%d", r);
    net_emit(id, 1, arg, (ULONG_PTR)r, txt, post, 0);
    g_callCount[id]++;
    return r;
}

static int WINAPI sh_WsaSend(void* s, void* lpBuffers, DWORD count, DWORD* sent, DWORD flags, void* ov, void* comp) {
    ULONG id = 26;
    ULONG_PTR arg[6] = { (ULONG_PTR)s, (ULONG_PTR)lpBuffers, count, flags, (ULONG_PTR)ov, 0 };
    char txt[HE_ARG_TEXT] = {0}; sprintf(txt, "s=0x%p bufs=%lu", s, count);
    int r = tp_WsaSend(s, lpBuffers, count, sent, flags, ov, comp);
    char post[HE_RET_TEXT] = {0}; sprintf(post, "%d sent=%lu", r, sent ? *sent : 0);
    static BYTE payload[HE_PAYLOAD_MAX];
    ULONG plen = 0;
    if (r > 0 && count > 0) {
        __try {
            const WSABUF* wsa = (const WSABUF*)lpBuffers;
            ULONG cap = wsa->len < HE_PAYLOAD_MAX ? wsa->len : (ULONG)sizeof(payload);
            if (cap > 0) { CopyMemory(payload, wsa->buf, cap); plen = cap; }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
        }
    }
    net_emit(id, 5, arg, (ULONG_PTR)r, txt, post, +1, plen ? payload : NULL, plen);
    g_callCount[id]++;
    return r;
}

static int WINAPI sh_WsaRecv(void* s, void* lpBuffers, DWORD count, DWORD* recvd, DWORD* flags, void* ov, void* comp) {
    ULONG id = 27;
    ULONG_PTR arg[6] = { (ULONG_PTR)s, (ULONG_PTR)lpBuffers, count, (ULONG_PTR)flags, (ULONG_PTR)ov, 0 };
    char txt[HE_ARG_TEXT] = {0}; sprintf(txt, "s=0x%p bufs=%lu", s, count);
    int r = tp_WsaRecv(s, lpBuffers, count, recvd, flags, ov, comp);
    char post[HE_RET_TEXT] = {0}; sprintf(post, "%d recvd=%lu", r, recvd ? *recvd : 0);
    static BYTE payload[HE_PAYLOAD_MAX];
    ULONG plen = 0;
    if (r > 0 && count > 0) {
        __try {
            const WSABUF* wsa = (const WSABUF*)lpBuffers;
            ULONG cap = wsa->len < HE_PAYLOAD_MAX ? wsa->len : (ULONG)sizeof(payload);
            if (cap > 0) { CopyMemory(payload, wsa->buf, cap); plen = cap; }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
        }
    }
    net_emit(id, 5, arg, (ULONG_PTR)r, txt, post, -1, plen ? payload : NULL, plen);
    g_callCount[id]++;
    return r;
}

static int WINAPI sh_connect(void* s, const void* name, int namelen) {
    ULONG id = 28;
    ULONG_PTR arg[6] = { (ULONG_PTR)s, (ULONG_PTR)name, (ULONG)namelen, 0, 0, 0 };
    char txt[HE_ARG_TEXT] = {0};
    if (name) {
        __try {
            const struct sockaddr_in* si = (const struct sockaddr_in*)name;
            sprintf(txt, "s=0x%p -> %d.%d.%d.%d:%u", s,
                    (int)((BYTE*)&si->sin_addr)[0], (int)((BYTE*)&si->sin_addr)[1],
                    (int)((BYTE*)&si->sin_addr)[2], (int)((BYTE*)&si->sin_addr)[3],
                    (unsigned)ntohs(si->sin_port));
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            sprintf(txt, "s=0x%p", s);
        }
    } else sprintf(txt, "s=0x%p", s);
    int r = tp_connect(s, name, namelen);
    char post[HE_RET_TEXT] = {0}; sprintf(post, "%d", r);
    net_emit(id, 3, arg, (ULONG_PTR)r, txt, post, 0);
    g_callCount[id]++;
    return r;
}

static void* WINAPI sh_FindWindowW(const wchar_t* a, const wchar_t* b) {
    ULONG id = 29;
    ULONG_PTR arg[6] = { (ULONG_PTR)a, (ULONG_PTR)b, 0, 0, 0, 0 };
    char txt[HE_ARG_TEXT] = {0};
    if (a) { fmt_wstr(txt, sizeof(txt), a); strcat(txt, " "); }
    if (b) fmt_wstr(txt + strlen(txt), sizeof(txt) - strlen(txt), b);
    void* r = tp_FindWindowW(a, b);
    char post[HE_RET_TEXT] = {0}; sprintf(post, "0x%p", r);
    ring_emit(id, 2, arg, (ULONG_PTR)r, txt, post, 0);
    g_callCount[id]++;
    return r;
}

static LONG WINAPI sh_RegCreateKeyExW(void* a, const wchar_t* b, DWORD c, wchar_t* d, DWORD e, DWORD f, void* g, void* h, DWORD* i) {
    ULONG id = 30;
    ULONG_PTR arg[6] = { (ULONG_PTR)a, (ULONG_PTR)b, c, f, (ULONG_PTR)h, 0 };
    char txt[HE_ARG_TEXT] = {0};
    char hh[32]; sprintf(hh, "h=0x%p ", a); strcat(txt, hh); fmt_wstr(txt + strlen(txt), sizeof(txt) - strlen(txt), b);
    LONG r = tp_RegCreateKeyExW(a, b, c, d, e, f, g, h, i);
    char post[HE_RET_TEXT] = {0}; sprintf(post, "0x%lx", (ULONG)r);
    ring_emit(id, 6, arg, (ULONG_PTR)(LONG)r, txt, post, 0);
    g_callCount[id]++;
    return r;
}

// ---------------- ntdll NT-layer (deeper visibility than kernel32) ----------------
typedef struct { USHORT Length; USHORT MaximumLength; PWSTR Buffer; } HE_UNICODE_STRING;
typedef struct {
    ULONG Length;
    void* RootDirectory;
    HE_UNICODE_STRING* ObjectName;
    ULONG Attributes;
    void* SecurityDescriptor;
    void* SecurityQualityOfService;
} HE_OBJECT_ATTRIBUTES;

static LONG WINAPI sh_NtCreateFile(void* a, ULONG b, void* c, void* d, void* e, ULONG f, ULONG g, ULONG h, ULONG i, void* j, ULONG k) {
    ULONG id = 31;
    ULONG_PTR arg[6] = { (ULONG_PTR)a, b, (ULONG_PTR)c, (ULONG_PTR)d, (ULONG_PTR)e, f };
    char txt[HE_ARG_TEXT] = {0};
    sprintf(txt, "ph=0x%p access=0x%x ", a, b);
    if (c) {
        __try {
            HE_OBJECT_ATTRIBUTES* oa = (HE_OBJECT_ATTRIBUTES*)c;
            if (oa->ObjectName && oa->ObjectName->Buffer) {
                HE_UNICODE_STRING* un = oa->ObjectName;
                if (un->Buffer[0]) { strcat(txt, "name="); fmt_wstr(txt + strlen(txt), sizeof(txt) - strlen(txt), un->Buffer); }
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
        }
    }
    LONG r = tp_NtCreateFile(a, b, c, d, e, f, g, h, i, j, k);
    char post[HE_RET_TEXT] = {0}; sprintf(post, "0x%lx", (ULONG)r);
    ring_emit(id, 6, arg, (ULONG_PTR)(LONG)r, txt, post, 0);
    g_callCount[id]++;
    return r;
}

static LONG WINAPI sh_NtWriteVirtualMemory(void* a, void* b, const void* c, SIZE_T d, SIZE_T* e) {
    ULONG id = 32;
    ULONG_PTR arg[6] = { (ULONG_PTR)a, (ULONG_PTR)b, (ULONG_PTR)c, (ULONG_PTR)d, (ULONG_PTR)e, 0 };
    char txt[HE_ARG_TEXT] = {0};
    sprintf(txt, "h=0x%p addr=0x%p size=%zu buf=0x%p", a, b, d, c);
    LONG r = tp_NtWriteVirtualMemory(a, b, c, d, e);
    char post[HE_RET_TEXT] = {0};
    if (r == 0 && e) sprintf(post, "OK written=%zu", *e); else sprintf(post, "0x%lx", (ULONG)r);
    ring_emit(id, 5, arg, (ULONG_PTR)(LONG)r, txt, post, 0);
    g_callCount[id]++;
    return r;
}

static LONG WINAPI sh_NtProtectVirtualMemory(void* a, void* b, SIZE_T* c, ULONG d, ULONG* e) {
    ULONG id = 33;
    ULONG_PTR arg[6] = { (ULONG_PTR)a, (ULONG_PTR)b, (ULONG_PTR)c, d, (ULONG_PTR)e, 0 };
    char txt[HE_ARG_TEXT] = {0};
    sprintf(txt, "h=0x%p addr=0x%p size=%zu prot=0x%x", a, b, c ? *c : 0, d);
    LONG r = tp_NtProtectVirtualMemory(a, b, c, d, e);
    char post[HE_RET_TEXT] = {0};
    if (r == 0 && e) { ULONG ov = 0; __try { ov = *e; } __except (EXCEPTION_EXECUTE_HANDLER) {} sprintf(post, "0x%lx old_prot=0x%lx", (ULONG)r, ov); }
    else sprintf(post, "0x%lx", (ULONG)r);
    ring_emit(id, 5, arg, (ULONG_PTR)(LONG)r, txt, post, 0);
    g_callCount[id]++;
    return r;
}

static LONG WINAPI sh_NtAllocateVirtualMemory(void* a, void* b, ULONG_PTR c, SIZE_T* d, ULONG e, ULONG f) {
    ULONG id = 34;
    ULONG_PTR arg[6] = { (ULONG_PTR)a, (ULONG_PTR)b, (ULONG_PTR)d, e, f, 0 };
    char txt[HE_ARG_TEXT] = {0};
    sprintf(txt, "h=0x%p size=%zu type=0x%x prot=0x%x", a, d ? *d : 0, e, f);
    LONG r = tp_NtAllocateVirtualMemory(a, b, c, d, e, f);
    char post[HE_RET_TEXT] = {0};
    size_t block = 0;
    __try { if (b && *(void**)b) block = (size_t)*(void**)b; } __except (EXCEPTION_EXECUTE_HANDLER) {}
    if (r == 0 && block) sprintf(post, "alloc=0x%p", (void*)block); else sprintf(post, "0x%lx", (ULONG)r);
    ring_emit(id, 5, arg, (ULONG_PTR)(LONG)r, txt, post, 0);
    g_callCount[id]++;
    return r;
}

static LONG WINAPI sh_NtCreateThreadEx(void* a, ULONG b, void* c, void* d, void* e, void* f, ULONG g, SIZE_T h, SIZE_T i, SIZE_T j, ULONG* k) {
    ULONG id = 35;
    ULONG_PTR arg[6] = { (ULONG_PTR)a, b, (ULONG_PTR)d, (ULONG_PTR)e, (ULONG_PTR)f, g };
    char txt[HE_ARG_TEXT] = {0};
    sprintf(txt, "h=0x%p proc=0x%p start=0x%p param=0x%p flags=0x%x", a, d, e, f, g);
    LONG r = tp_NtCreateThreadEx(a, b, c, d, e, f, g, h, i, j, k);
    char post[HE_RET_TEXT] = {0};
    if (r == 0 && a && *(void**)a) sprintf(post, "thread=0x%p", *(void**)a); else sprintf(post, "0x%lx", (ULONG)r);
    ring_emit(id, 6, arg, (ULONG_PTR)(LONG)r, txt, post, 0);
    g_callCount[id]++;
    return r;
}

// ---------------- user32 ----------------
static SHORT WINAPI sh_GetAsyncKeyState(int a) {
    ULONG id = 36;
    ULONG_PTR arg[6] = { (ULONG)a, 0, 0, 0, 0, 0 };
    char txt[HE_ARG_TEXT] = {0};
    if (a >= 0 && a < 256) sprintf(txt, "vk=0x%02x", (DWORD)a); else sprintf(txt, "vk=%d", a);
    SHORT r = tp_GetAsyncKeyState(a);
    char post[HE_RET_TEXT] = {0}; sprintf(post, "0x%04hx", (unsigned short)r);
    ring_emit(id, 1, arg, (ULONG_PTR)(SHORT)r, txt, post, 0);
    g_callCount[id]++;
    return r;
}

static SHORT WINAPI sh_GetKeyState(int a) {
    ULONG id = 37;
    ULONG_PTR arg[6] = { (ULONG)a, 0, 0, 0, 0, 0 };
    char txt[HE_ARG_TEXT] = {0};
    if (a >= 0 && a < 256) sprintf(txt, "vk=0x%02x", (DWORD)a); else sprintf(txt, "vk=%d", a);
    SHORT r = tp_GetKeyState(a);
    char post[HE_RET_TEXT] = {0}; sprintf(post, "0x%04hx", (unsigned short)r);
    ring_emit(id, 1, arg, (ULONG_PTR)(SHORT)r, txt, post, 0);
    g_callCount[id]++;
    return r;
}

static void* WINAPI sh_SetWindowsHookExW(int a, void* b, void* c, DWORD d) {
    ULONG id = 38;
    ULONG_PTR arg[6] = { (ULONG)a, (ULONG_PTR)b, (ULONG_PTR)c, d, 0, 0 };
    char txt[HE_ARG_TEXT] = {0}; sprintf(txt, "hook=%d proc=0x%p tid=%lu", a, b, d);
    void* r = tp_SetWindowsHookExW(a, b, c, d);
    char post[HE_RET_TEXT] = {0}; sprintf(post, "0x%p", r);
    ring_emit(id, 4, arg, (ULONG_PTR)r, txt, post, 0);
    g_callCount[id]++;
    return r;
}

static void* WINAPI sh_GetClipboardData(UINT a) {
    ULONG id = 39;
    ULONG_PTR arg[6] = { a, 0, 0, 0, 0, 0 };
    char txt[HE_ARG_TEXT] = {0}; sprintf(txt, "fmt=%u", a);
    void* r = tp_GetClipboardData(a);
    char post[HE_RET_TEXT] = {0}; sprintf(post, "0x%p", r);
    ring_emit(id, 1, arg, (ULONG_PTR)r, txt, post, 0);
    g_callCount[id]++;
    return r;
}

static void WINAPI sh_keybd_event(BYTE a, BYTE b, DWORD c, ULONG_PTR d) {
    ULONG id = 40;
    ULONG_PTR arg[6] = { a, b, c, d, 0, 0 };
    char txt[HE_ARG_TEXT] = {0}; sprintf(txt, "vk=0x%02x scan=0x%02x flags=0x%x", a, b, c);
    tp_keybd_event(a, b, c, d);
    ring_emit(id, 4, arg, 0, txt, "void", 0);
    g_callCount[id]++;
}

static LONG_PTR WINAPI sh_SendMessageW(void* a, UINT b, WPARAM c, LPARAM d) {
    ULONG id = 41;
    ULONG_PTR arg[6] = { (ULONG_PTR)a, b, (ULONG_PTR)c, (ULONG_PTR)d, 0, 0 };
    char txt[HE_ARG_TEXT] = {0}; sprintf(txt, "hwnd=0x%p msg=0x%x w=%Iu l=%Iu", a, b, (uintptr_t)c, (uintptr_t)d);
    LONG_PTR r = tp_SendMessageW(a, b, c, d);
    char post[HE_RET_TEXT] = {0}; sprintf(post, "%Iu", (uintptr_t)r);
    ring_emit(id, 4, arg, (ULONG_PTR)r, txt, post, 0);
    g_callCount[id]++;
    return r;
}

// ---------------- kernel32 extra ----------------
static void* WINAPI sh_CreateThread(void* a, SIZE_T b, void* c, void* d, DWORD e, void* f) {
    ULONG id = 42;
    ULONG_PTR arg[6] = { (ULONG_PTR)a, (ULONG_PTR)b, (ULONG_PTR)c, (ULONG_PTR)d, e, (ULONG_PTR)f };
    char txt[HE_ARG_TEXT] = {0};
    sprintf(txt, "start=0x%p param=0x%p flags=0x%x", c, d, e);
    void* r = tp_CreateThread(a, b, c, d, e, f);
    char post[HE_RET_TEXT] = {0}; sprintf(post, "0x%p", r);
    ring_emit(id, 6, arg, (ULONG_PTR)r, txt, post, 0);
    g_callCount[id]++;
    return r;
}

static BOOL WINAPI sh_MoveFileW(const wchar_t* a, const wchar_t* b) {
    ULONG id = 43;
    ULONG_PTR arg[6] = { (ULONG_PTR)a, (ULONG_PTR)b, 0, 0, 0, 0 };
    char txt[HE_ARG_TEXT] = {0};
    fmt_wstr(txt, sizeof(txt), a); strcat(txt, " -> "); fmt_wstr(txt + strlen(txt), sizeof(txt) - strlen(txt), b);
    BOOL r = tp_MoveFileW(a, b);
    char post[HE_RET_TEXT] = {0}; sprintf(post, "%s", r ? "TRUE" : "FALSE");
    ring_emit(id, 2, arg, (ULONG_PTR)r, txt, post, 0);
    g_callCount[id]++;
    return r;
}

static void* WINAPI sh_VirtualAllocEx(void* a, void* b, SIZE_T c, DWORD d, DWORD e) {
    ULONG id = 44;
    ULONG_PTR arg[6] = { (ULONG_PTR)a, (ULONG_PTR)b, (ULONG_PTR)c, d, e, 0 };
    char txt[HE_ARG_TEXT] = {0};
    sprintf(txt, "h=0x%p addr=0x%p size=0x%zx type=0x%x prot=0x%x", a, b, c, d, e);
    void* r = tp_VirtualAllocEx(a, b, c, d, e);
    char post[HE_RET_TEXT] = {0}; sprintf(post, "0x%p", r);
    ring_emit(id, 5, arg, (ULONG_PTR)r, txt, post, 0);
    g_callCount[id]++;
    return r;
}

// ---------------- wininet / urlmon (C2 / dropper) ----------------
static void* WINAPI sh_InternetOpenW(const wchar_t* a, DWORD b, const wchar_t* c, const wchar_t* d, DWORD e) {
    ULONG id = 45;
    ULONG_PTR arg[6] = { (ULONG_PTR)a, b, (ULONG_PTR)c, (ULONG_PTR)d, e, 0 };
    char txt[HE_ARG_TEXT] = {0};
    if (a) { fmt_wstr(txt, sizeof(txt), a); } else sprintf(txt, "(agent)");
    void* r = tp_InternetOpenW(a, b, c, d, e);
    char post[HE_RET_TEXT] = {0}; sprintf(post, "0x%p", r);
    ring_emit(id, 5, arg, (ULONG_PTR)r, txt, post, 0);
    g_callCount[id]++;
    return r;
}

static BOOL WINAPI sh_HttpSendRequestW(void* a, const wchar_t* b, DWORD c, void* d, DWORD e) {
    ULONG id = 46;
    ULONG_PTR arg[6] = { (ULONG_PTR)a, (ULONG_PTR)b, c, (ULONG_PTR)d, e, 0 };
    char txt[HE_ARG_TEXT] = {0};
    sprintf(txt, "req=0x%p hdrlen=%lu bodylen=%lu", a, c, e);
    if (b && b[0]) { strcat(txt, " hdr="); fmt_wstr(txt + strlen(txt), sizeof(txt) - strlen(txt), b); }
    BOOL r = tp_HttpSendRequestW(a, b, c, d, e);
    char post[HE_RET_TEXT] = {0}; sprintf(post, "%s", r ? "TRUE" : "FALSE");
    ring_emit(id, 5, arg, (ULONG_PTR)r, txt, post, 0);
    g_callCount[id]++;
    return r;
}

static LONG WINAPI sh_UrlDownloadToFileW(void* a, const wchar_t* b, const wchar_t* c, DWORD d, void* e) {
    ULONG id = 47;
    ULONG_PTR arg[6] = { (ULONG_PTR)b, (ULONG_PTR)c, d, 0, 0, 0 };
    char txt[HE_ARG_TEXT] = {0};
    fmt_wstr(txt, sizeof(txt), b); strcat(txt, " -> "); fmt_wstr(txt + strlen(txt), sizeof(txt) - strlen(txt), c);
    LONG r = tp_UrlDownloadToFileW(a, b, c, d, e);
    char post[HE_RET_TEXT] = {0}; sprintf(post, "0x%08lx", (ULONG)r);
    ring_emit(id, 3, arg, (ULONG_PTR)(LONG)r, txt, post, 0);
    g_callCount[id]++;
    return r;
}

static int WINAPI sh_getaddrinfo(const char* a, const char* b, const struct addrinfo* c, struct addrinfo** d) {
    ULONG id = 48;
    ULONG_PTR arg[6] = { (ULONG_PTR)a, (ULONG_PTR)b, (ULONG_PTR)d, 0, 0, 0 };
    char txt[HE_ARG_TEXT] = {0};
    if (a) { fmt_astr(txt, sizeof(txt), a); strcat(txt, " "); }
    else strcat(txt, "(host) ");
    if (b) fmt_astr(txt + strlen(txt), sizeof(txt) - strlen(txt), b);
    int r = tp_getaddrinfo(a, b, c, d);
    char post[HE_RET_TEXT] = {0}; sprintf(post, "%d", r);
    ring_emit(id, 3, arg, (ULONG_PTR)r, txt, post, 0);
    g_callCount[id]++;
    return r;
}

static void bind_trampolines(void);

// ============================================================
// Slot table registration + hooking
// ============================================================
static void register_catalog(void) {
    fill_slot(0,  "kernel32.dll", "CreateFileW",      "hnd",  "wstr,u32,u32,ptr,u32,u32,hnd", 1, FALSE, (void*)sh_CreateFileW);
    fill_slot(1,  "kernel32.dll", "ReadFile",         "bool", "hnd,ptr,u32,ptr,ptr",          0, FALSE, (void*)sh_ReadFile);
    fill_slot(2,  "kernel32.dll", "WriteFile",        "bool", "hnd,ptr,u32,ptr,ptr",          0, FALSE, (void*)sh_WriteFile);
    fill_slot(3,  "kernel32.dll", "CreateProcessW",   "bool", "wstr,wstr,ptr,ptr,bool,u32,ptr,wstr,ptr,ptr", 2, FALSE, (void*)sh_CreateProcessW);
    fill_slot(4,  "kernel32.dll", "VirtualAlloc",     "ptr",  "ptr,size,u32,u32",             1, FALSE, (void*)sh_VirtualAlloc);
    fill_slot(5,  "kernel32.dll", "VirtualProtect",   "bool", "ptr,size,u32,ptr",             2, FALSE, (void*)sh_VirtualProtect);
    fill_slot(6,  "kernel32.dll", "LoadLibraryW",     "hnd",  "wstr",                         1, FALSE, (void*)sh_LoadLibraryW);
    fill_slot(7,  "kernel32.dll", "GetProcAddress",   "ptr",  "hnd,astr",                     0, FALSE, (void*)sh_GetProcAddress);
    fill_slot(8,  "kernel32.dll", "OpenProcess",      "hnd",  "u32,bool,u32",                 2, FALSE, (void*)sh_OpenProcess);
    fill_slot(9,  "kernel32.dll", "TerminateProcess", "bool", "hnd,u32",                      3, FALSE, (void*)sh_TerminateProcess);
    fill_slot(10, "kernel32.dll", "CreateRemoteThread","hnd", "hnd,ptr,size,ptr,ptr,u32,ptr", 3, FALSE, (void*)sh_CreateRemoteThread);
    fill_slot(11, "kernel32.dll", "WriteProcessMemory","bool","hnd,ptr,ptr,size,ptr",         3, FALSE, (void*)sh_WriteProcessMemory);
    fill_slot(12, "kernel32.dll", "ReadProcessMemory", "bool","hnd,ptr,ptr,size,ptr",         2, FALSE, (void*)sh_ReadProcessMemory);
    fill_slot(13, "kernel32.dll", "DeleteFileW",      "bool", "wstr",                         1, FALSE, (void*)sh_DeleteFileW);
    fill_slot(14, "kernel32.dll", "CopyFileW",        "bool", "wstr,wstr,bool",               1, FALSE, (void*)sh_CopyFileW);
    fill_slot(15, "kernel32.dll", "Sleep",            "void", "u32",                          0, FALSE, (void*)sh_Sleep);
    fill_slot(16, "advapi32.dll", "RegOpenKeyExW",    "i32",  "hnd,wstr,u32,u32,ptr",         2, FALSE, (void*)sh_RegOpenKeyExW);
    fill_slot(17, "advapi32.dll", "RegSetValueExW",   "i32",  "hnd,wstr,u32,u32,ptr,u32",     2, FALSE, (void*)sh_RegSetValueExW);
    fill_slot(18, "advapi32.dll", "OpenSCManagerW",   "hnd",  "wstr,wstr,u32",                2, FALSE, (void*)sh_OpenSCManagerW);
    fill_slot(19, "advapi32.dll", "CreateServiceW",   "hnd",  "hnd,wstr,wstr,u32,u32,u32,wstr,ptr,ptr,wstr,wstr,wstr", 3, FALSE, (void*)sh_CreateServiceW);
    fill_slot(20, "advapi32.dll", "StartServiceW",    "bool", "hnd,u32,ptr",                  2, FALSE, (void*)sh_StartServiceW);
    fill_slot(21, "ws2_32.dll",   "send",             "i32",  "sock,ptr,i32,i32",             0, TRUE,  (void*)sh_send);
    fill_slot(22, "ws2_32.dll",   "recv",             "i32",  "sock,ptr,i32,i32",             0, TRUE,  (void*)sh_recv);
    fill_slot(23, "ws2_32.dll",   "sendto",           "i32",  "sock,ptr,i32,i32,ptr,i32",     0, TRUE,  (void*)sh_sendto);
    fill_slot(24, "ws2_32.dll",   "recvfrom",         "i32",  "sock,ptr,i32,i32,ptr,ptr",     0, TRUE,  (void*)sh_recvfrom);
    fill_slot(25, "ws2_32.dll",   "closesocket",      "i32",  "sock",                         0, TRUE,  (void*)sh_closesocket);
    fill_slot(26, "ws2_32.dll",   "WSASend",          "i32",  "sock,ptr,u32,ptr,u32,ptr,ptr", 0, TRUE,  (void*)sh_WsaSend);
    fill_slot(27, "ws2_32.dll",   "WSARecv",          "i32",  "sock,ptr,u32,ptr,ptr,ptr,ptr", 0, TRUE,  (void*)sh_WsaRecv);
    fill_slot(28, "ws2_32.dll",   "connect",          "i32",  "sock,ptr,i32",                 1, TRUE,  (void*)sh_connect);
    fill_slot(29, "user32.dll",   "FindWindowW",      "hnd",  "wstr,wstr",                    1, FALSE, (void*)sh_FindWindowW);
    fill_slot(30, "advapi32.dll", "RegCreateKeyExW",  "i32",  "hnd,wstr,u32,wstr,u32,u32,ptr,ptr,ptr", 2, FALSE, (void*)sh_RegCreateKeyExW);
    fill_slot(31, "ntdll.dll",    "NtCreateFile",     "i32",  "ptr,u32,ptr,ptr,ptr,u32,u32,u32,u32,ptr,u32", 2, FALSE, (void*)sh_NtCreateFile);
    fill_slot(32, "ntdll.dll",    "NtWriteVirtualMemory","i32","hnd,ptr,ptr,size,ptr",       3, FALSE, (void*)sh_NtWriteVirtualMemory);
    fill_slot(33, "ntdll.dll",    "NtProtectVirtualMemory","i32","hnd,ptr,ptr,u32,ptr",      3, FALSE, (void*)sh_NtProtectVirtualMemory);
    fill_slot(34, "ntdll.dll",    "NtAllocateVirtualMemory","i32","hnd,ptr,u64,ptr,u32,u32", 2, FALSE, (void*)sh_NtAllocateVirtualMemory);
    fill_slot(35, "ntdll.dll",    "NtCreateThreadEx", "i32",  "ptr,u32,ptr,hnd,ptr,ptr,u32,size,size,size,ptr", 3, FALSE, (void*)sh_NtCreateThreadEx);
    fill_slot(36, "user32.dll",   "GetAsyncKeyState", "i16",  "i32",                         3, FALSE, (void*)sh_GetAsyncKeyState);
    fill_slot(37, "user32.dll",   "GetKeyState",      "i16",  "i32",                         2, FALSE, (void*)sh_GetKeyState);
    fill_slot(38, "user32.dll",   "SetWindowsHookExW","hnd",  "i32,ptr,hnd,u32",             3, FALSE, (void*)sh_SetWindowsHookExW);
    fill_slot(39, "user32.dll",   "GetClipboardData", "hnd",  "u32",                         2, FALSE, (void*)sh_GetClipboardData);
    fill_slot(40, "user32.dll",   "keybd_event",      "void", "u32,u32,u32,u64",             2, FALSE, (void*)sh_keybd_event);
    fill_slot(41, "user32.dll",   "SendMessageW",     "i64",  "ptr,u32,u64,u64",             0, FALSE, (void*)sh_SendMessageW);
    fill_slot(42, "kernel32.dll", "CreateThread",     "hnd",  "ptr,size,ptr,ptr,u32,ptr",    1, FALSE, (void*)sh_CreateThread);
    fill_slot(43, "kernel32.dll", "MoveFileW",        "bool", "wstr,wstr",                   1, FALSE, (void*)sh_MoveFileW);
    fill_slot(44, "kernel32.dll", "VirtualAllocEx",   "ptr",  "hnd,ptr,size,u32,u32",        3, FALSE, (void*)sh_VirtualAllocEx);
    fill_slot(45, "wininet.dll",  "InternetOpenW",    "hnd",  "wstr,u32,wstr,wstr,u32",      0, TRUE,  (void*)sh_InternetOpenW);
    fill_slot(46, "wininet.dll",  "HttpSendRequestW", "bool", "hnd,wstr,u32,ptr,u32",        2, TRUE,  (void*)sh_HttpSendRequestW);
    fill_slot(47, "urlmon.dll",   "URLDownloadToFileW","i32", "ptr,wstr,wstr,u32,ptr",       3, TRUE,  (void*)sh_UrlDownloadToFileW);
    fill_slot(48, "ws2_32.dll",   "getaddrinfo",      "i32",  "astr,astr,ptr,ptr",           0, TRUE,  (void*)sh_getaddrinfo);
}

static void* g_shim[HE_CAT];
static const char* g_dllName[HE_CAT];
static const char* g_funcName[HE_CAT];

static BOOL install_hook(int idx) {
    HookSlot* s = &g_slots[idx];
    if (s->origAddr) return TRUE;             // already
    HMODULE m = get_dll(s->dll);
#ifdef HE_DEBUG
    fprintf(stderr, "[HE] install %s!%s m=%p\n", s->dll, s->func, m);
#endif
    if (!m) return FALSE;
    BYTE* fn = (BYTE*)GetProcAddress(m, s->func);
#ifdef HE_DEBUG
    fprintf(stderr, "[HE]   fn=%p\n", fn);
#endif
    if (!fn) return FALSE;

    // decode prologue into instruction table (>=14 bytes)
    HE_IX ins[24];
    int nins = disasm_prologue(fn, ins, 24, 14, 48);
#ifdef HE_DEBUG
    fprintf(stderr, "[HE]   nins=%d\n", nins);
    for (int k = 0; k < nins; k++) fprintf(stderr, "[HE]     ix[%d] off=%d len=%d rip=%d\n", k, ins[k].off, ins[k].len, ins[k].ripRel);
#endif
    if (nins <= 0) return FALSE;

    // allocate trampoline (emitted instr bytes + absolute jmp-back)
    BYTE* tramp = (BYTE*)VirtualAlloc(NULL, 96, MEM_COMMIT | MEM_RESERVE,
                                     PAGE_EXECUTE_READWRITE);
#ifdef HE_DEBUG
    fprintf(stderr, "[HE]   tramp=%p err=%lu\n", tramp, tramp ? 0 : GetLastError());
#endif
    if (!tramp) return FALSE;
    int emitted = 0;
    int nstop = -1;
    for (int k = 0; k < nins; k++) {
        HE_IX* ix = &ins[k];
        BYTE* src = fn + ix->off;
        ULONG_PTR stubTarget = 0;
        // FF 25 [rip+disp] hotpatch stub (possibly REX-prefixed): rewrite as
        // absolute jmp 48 B8 <imm64> FF E0 so the trampoline works at any distance.
        if (ix->len == 6 && src[0] == 0xFF && src[1] == 0x25)
            stubTarget = (ULONG_PTR)(fn + ix->off + 6) + (ULONG)(*(LONG*)(src + 2));
        else if (ix->len == 7 && (src[0] & 0xC0) == 0x40 && src[1] == 0xFF && src[2] == 0x25)
            stubTarget = (ULONG_PTR)(fn + ix->off + 7) + (ULONG)(*(LONG*)(src + 3));
        if (stubTarget) {
            // FF 25 [rip+disp] points at an IAT slot holding the real target
            __try { stubTarget = *(ULONG_PTR*)stubTarget; }
            __except (EXCEPTION_EXECUTE_HANDLER) { stubTarget = 0; }
        }
        if (stubTarget) {
            tramp[emitted] = 0x48; tramp[emitted + 1] = 0xB8;    // mov rax, imm64
            *(ULONG_PTR*)(tramp + emitted + 2) = stubTarget;
            tramp[emitted + 10] = 0xFF; tramp[emitted + 11] = 0xE0; // jmp rax
            emitted += 12;
            nstop = k;                                          // terminal: never returns
            break;
        }
        memcpy(tramp + emitted, src, ix->len);
        if (ix->ripRel >= 0) {                                  // in-range rel32 rebase
            LONG_PTR relDelta = (LONG_PTR)(tramp + emitted) - (LONG_PTR)(fn + ix->off);
            LONG* d = (LONG*)(tramp + emitted + ix->ripRel);
            *d = (LONG)((LONG)(*d) + relDelta);
        }
        emitted += ix->len;
    }
    (void)nstop;

    // absolute jmp-back to fn+emitted (unreachable for terminal stubs).
    // Use r11 (mov r11,imm64; jmp r11) so eax/rax is preserved: Nt* prologues
    // carry the syscall number in eax up to the trailing 'syscall'.
    BYTE* back = tramp + emitted;
    ULONG_PTR cont = (ULONG_PTR)fn + emitted;
    back[0] = 0x49; back[1] = 0xBB;
    *(ULONG_PTR*)(back + 2) = cont;
    back[10] = 0x41; back[11] = 0xFF; back[12] = 0xE3;
#ifdef HE_DEBUG
    fprintf(stderr, "[HE]   emit[%d]:", emitted);
    for (int kk = 0; kk < emitted + 13; kk++) fprintf(stderr, " %02x", tramp[kk]);
    fprintf(stderr, "\n");
#endif

    // publish this slot's fields BEFORE binding: the restore VirtualProtect
    // below would otherwise re-enter the shim with a NULL tp
    s->origAddr = fn;
    s->origLen = emitted;
    s->trampoline = tramp;
    s->hMod = m;
    bind_trampolines();

    // patch function entry to shim (mov rax,imm64; jmp rax)
    ULONG_PTR target = (ULONG_PTR)g_shim[idx];
    BYTE patch[14];
    patch[0] = 0x48; patch[1] = 0xB8;                       // mov rax, imm64
    memcpy(patch + 2, &target, 8);
    patch[10] = 0xFF; patch[11] = 0xE0;                     // jmp rax
    for (int i = 12; i < 14; i++) patch[i] = 0x90;          // NOP fill

    DWORD old;
    VirtualProtect(fn, 14, PAGE_EXECUTE_READWRITE, &old);
    memcpy(s->origBytes, fn, 14);
    memcpy(fn, patch, 14);
    VirtualProtect(fn, 14, old, &old);
    FlushInstructionCache(GetCurrentProcess(), fn, 14);

    return TRUE;
}

static BOOL uninstall_hook(int idx) {
    HookSlot* s = &g_slots[idx];
    if (!s->origAddr) return TRUE;
    DWORD old;
    VirtualProtect(s->origAddr, 14, PAGE_EXECUTE_READWRITE, &old);
    memcpy(s->origAddr, s->origBytes, 14);
    VirtualProtect(s->origAddr, 14, old, &old);
    FlushInstructionCache(GetCurrentProcess(), s->origAddr, 14);
    if (s->trampoline) { VirtualFree(s->trampoline, 0, MEM_RELEASE); s->trampoline = NULL; }
    s->origAddr = NULL;
    return TRUE;
}

static void bind_trampolines(void) {
    tp_CreateFileW        = (pCreateFileW)       g_slots[0].trampoline;
    tp_ReadFile           = (pReadFile)          g_slots[1].trampoline;
    tp_WriteFile          = (pWriteFile)         g_slots[2].trampoline;
    tp_CreateProcessW     = (pCreateProcessW)    g_slots[3].trampoline;
    tp_VirtualAlloc       = (pVirtualAlloc)      g_slots[4].trampoline;
    tp_VirtualProtect     = (pVirtualProtect)    g_slots[5].trampoline;
    tp_LoadLibraryW       = (pLoadLibraryW)      g_slots[6].trampoline;
    tp_GetProcAddress     = (pGetProcAddress)    g_slots[7].trampoline;
    tp_OpenProcess        = (pOpenProcess)       g_slots[8].trampoline;
    tp_TerminateProcess   = (pTerminateProcess)  g_slots[9].trampoline;
    tp_CreateRemoteThread = (pCreateRemoteThread) g_slots[10].trampoline;
    tp_WriteProcessMemory = (pWriteProcessMemory) g_slots[11].trampoline;
    tp_ReadProcessMemory  = (pReadProcessMemory) g_slots[12].trampoline;
    tp_DeleteFileW        = (pDeleteFileW)       g_slots[13].trampoline;
    tp_CopyFileW          = (pCopyFileW)         g_slots[14].trampoline;
    tp_Sleep              = (pSleep)             g_slots[15].trampoline;
    tp_RegOpenKeyExW      = (pRegOpenKeyExW)     g_slots[16].trampoline;
    tp_RegSetValueExW     = (pRegSetValueExW)    g_slots[17].trampoline;
    tp_OpenSCManagerW     = (pOpenSCManagerW)    g_slots[18].trampoline;
    tp_CreateServiceW     = (pCreateServiceW)    g_slots[19].trampoline;
    tp_StartServiceW      = (pStartServiceW)     g_slots[20].trampoline;
    tp_send               = (pSend)              g_slots[21].trampoline;
    tp_recv               = (pRecv)              g_slots[22].trampoline;
    tp_sendto             = (pSendTo)            g_slots[23].trampoline;
    tp_recvfrom           = (pRecvFrom)          g_slots[24].trampoline;
    tp_closesocket        = (pClosesocket)       g_slots[25].trampoline;
    tp_WsaSend            = (pWsaSend)           g_slots[26].trampoline;
    tp_WsaRecv            = (pWsaRecv)           g_slots[27].trampoline;
    tp_connect            = (pConnect)           g_slots[28].trampoline;
    tp_FindWindowW        = (pFindWindowW)       g_slots[29].trampoline;
    tp_RegCreateKeyExW    = (pRegCreateKeyExW)   g_slots[30].trampoline;
    tp_NtCreateFile       = (pNtCreateFile)      g_slots[31].trampoline;
    tp_NtWriteVirtualMemory = (pNtWriteVirtualMemory) g_slots[32].trampoline;
    tp_NtProtectVirtualMemory = (pNtProtectVirtualMemory) g_slots[33].trampoline;
    tp_NtAllocateVirtualMemory = (pNtAllocateVirtualMemory) g_slots[34].trampoline;
    tp_NtCreateThreadEx   = (pNtCreateThreadEx)  g_slots[35].trampoline;
    tp_GetAsyncKeyState   = (pGetAsyncKeyState)  g_slots[36].trampoline;
    tp_GetKeyState        = (pGetKeyState)       g_slots[37].trampoline;
    tp_SetWindowsHookExW  = (pSetWindowsHookExW) g_slots[38].trampoline;
    tp_GetClipboardData   = (pGetClipboardData)  g_slots[39].trampoline;
    tp_keybd_event        = (pKeybdEvent)        g_slots[40].trampoline;
    tp_SendMessageW       = (pSendMessageW)      g_slots[41].trampoline;
    tp_CreateThread       = (pCreateThread)      g_slots[42].trampoline;
    tp_MoveFileW          = (pMoveFileW)         g_slots[43].trampoline;
    tp_VirtualAllocEx     = (pVirtualAllocEx)    g_slots[44].trampoline;
    tp_InternetOpenW      = (pInternetOpenW)     g_slots[45].trampoline;
    tp_HttpSendRequestW   = (pHttpSendRequestW)  g_slots[46].trampoline;
    tp_UrlDownloadToFileW = (pUrlDownloadToFileW) g_slots[47].trampoline;
    tp_getaddrinfo        = (pGetAddrInfo)       g_slots[48].trampoline;
}

static void init_shim_ptr(void) {
    g_shim[0] = (void*)sh_CreateFileW;
    g_shim[1] = (void*)sh_ReadFile;
    g_shim[2] = (void*)sh_WriteFile;
    g_shim[3] = (void*)sh_CreateProcessW;
    g_shim[4] = (void*)sh_VirtualAlloc;
    g_shim[5] = (void*)sh_VirtualProtect;
    g_shim[6] = (void*)sh_LoadLibraryW;
    g_shim[7] = (void*)sh_GetProcAddress;
    g_shim[8] = (void*)sh_OpenProcess;
    g_shim[9] = (void*)sh_TerminateProcess;
    g_shim[10] = (void*)sh_CreateRemoteThread;
    g_shim[11] = (void*)sh_WriteProcessMemory;
    g_shim[12] = (void*)sh_ReadProcessMemory;
    g_shim[13] = (void*)sh_DeleteFileW;
    g_shim[14] = (void*)sh_CopyFileW;
    g_shim[15] = (void*)sh_Sleep;
    g_shim[16] = (void*)sh_RegOpenKeyExW;
    g_shim[17] = (void*)sh_RegSetValueExW;
    g_shim[18] = (void*)sh_OpenSCManagerW;
    g_shim[19] = (void*)sh_CreateServiceW;
    g_shim[20] = (void*)sh_StartServiceW;
    g_shim[21] = (void*)sh_send;
    g_shim[22] = (void*)sh_recv;
    g_shim[23] = (void*)sh_sendto;
    g_shim[24] = (void*)sh_recvfrom;
    g_shim[25] = (void*)sh_closesocket;
    g_shim[26] = (void*)sh_WsaSend;
    g_shim[27] = (void*)sh_WsaRecv;
    g_shim[28] = (void*)sh_connect;
    g_shim[29] = (void*)sh_FindWindowW;
    g_shim[30] = (void*)sh_RegCreateKeyExW;
    g_shim[31] = (void*)sh_NtCreateFile;
    g_shim[32] = (void*)sh_NtWriteVirtualMemory;
    g_shim[33] = (void*)sh_NtProtectVirtualMemory;
    g_shim[34] = (void*)sh_NtAllocateVirtualMemory;
    g_shim[35] = (void*)sh_NtCreateThreadEx;
    g_shim[36] = (void*)sh_GetAsyncKeyState;
    g_shim[37] = (void*)sh_GetKeyState;
    g_shim[38] = (void*)sh_SetWindowsHookExW;
    g_shim[39] = (void*)sh_GetClipboardData;
    g_shim[40] = (void*)sh_keybd_event;
    g_shim[41] = (void*)sh_SendMessageW;
    g_shim[42] = (void*)sh_CreateThread;
    g_shim[43] = (void*)sh_MoveFileW;
    g_shim[44] = (void*)sh_VirtualAllocEx;
    g_shim[45] = (void*)sh_InternetOpenW;
    g_shim[46] = (void*)sh_HttpSendRequestW;
    g_shim[47] = (void*)sh_UrlDownloadToFileW;
    g_shim[48] = (void*)sh_getaddrinfo;
}

// ============================================================
// Public API
// ============================================================
ULONG HE_API he_version(void) { return g_version; }

HE_API const wchar_t* he_module_path(void) {
    static wchar_t path[512];
    if (g_self) GetModuleFileNameW(g_self, path, 512);
    return path;
}

static int setup(void) {
    static int done = 0;
    if (done) return 1;
    init_shim_ptr();
    register_catalog();
    bind_trampolines();  // binds NULL initially; call bind again post-hook
    done = 1;
    return 1;
}

BOOL HE_API he_hook(ULONG apiId) {
    if (!setup()) return FALSE;
#ifdef HE_DEBUG
    fprintf(stderr, "[HE] he_hook(%lu) setup ok\n", apiId);
#endif
    BOOL ok = install_hook(apiId);
#ifdef HE_DEBUG
    fprintf(stderr, "[HE]   install_hook=%d origAddr=%p\n", ok, g_slots[apiId].origAddr);
#endif
    bind_trampolines();
    return g_slots[apiId].origAddr != NULL;
}

BOOL HE_API he_unhook(ULONG apiId) {
    if (!setup()) return FALSE;
    BOOL r = uninstall_hook(apiId);
    bind_trampolines();
    return r;
}

BOOL HE_API he_hook_all(void) {
    setup();
    BOOL all = TRUE;
    for (int i = 0; i < g_slotCount; i++) { if (!he_hook((ULONG)i)) all = FALSE; }
    return all;
}

void HE_API he_unhook_all(void) {
    setup();
    for (int i = g_slotCount - 1; i >= 0; i--) {
        if (g_slots[i].origAddr) he_unhook((ULONG)i);
    }
}

BOOL HE_API he_is_hooked(ULONG apiId) {
    setup();
    return apiId < (ULONG)g_slotCount && g_slots[apiId].origAddr != NULL;
}

ULONG HE_API he_catalog_count(void) {
    setup();
    return (ULONG)g_slotCount;
}

BOOL HE_API he_catalog_info(ULONG index, HEApiInfo* out) {
    setup();
    if (!out || index >= (ULONG)g_slotCount) return FALSE;
    *out = g_slots[index].info;
    return TRUE;
}

ULONG HE_API he_total_calls(ULONG apiId) {
    return apiId < 256 ? g_callCount[apiId] : 0;
}

// ---------------- injection ----------------
BOOL HE_API he_spawn_and_inject(const wchar_t* exePath, const wchar_t* hookDllPath,
                                DWORD* outPid, wchar_t* msg, size_t msgBytes) {
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };
    BOOL ok = CreateProcessW(NULL, (wchar_t*)exePath, NULL, NULL, FALSE,
                             CREATE_SUSPENDED, NULL, NULL, &si, &pi);
    if (!ok) {
        if (msg) swprintf_s(msg, msgBytes / 2, L"CreateProcess failed err=%lu", GetLastError());
        return FALSE;
    }
    // give it a moment
    BOOL inj = he_inject_process(pi.dwProcessId, hookDllPath, msg, msgBytes);
    ResumeThread(pi.hThread);
    if (outPid) *outPid = pi.dwProcessId;
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return inj;
}

// Remote-start entry: called on a fresh thread inside the target process so the
// ring is mapped (shared memory) and all hooks are installed there.
// Returns bitmask: 1=hook ring ok, 2=net ring ok, 4=all hooks installed.
HE_API BOOL he_remote_start(void) {
    ULONG rc = 0;
    if (he_open_ring(NULL)) rc |= 1;
    if (he_net_open()) rc |= 2;
    BOOL all = he_hook_all();
    if (all) rc |= 4;
    return (BOOL)rc;
}

static DWORD WINAPI remote_main_thread(LPVOID) {
    return he_remote_start();
}

// ============================================================
// Injection
// ============================================================
BOOL HE_API he_inject_process(DWORD pid, const wchar_t* hookDllPath, wchar_t* msg, size_t msgBytes) {
    HANDLE h = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION |
                           PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, pid);
    if (!h) {
        if (msg) swprintf_s(msg, msgBytes / 2, L"OpenProcess failed (pid %lu) err=%lu", pid, GetLastError());
        return FALSE;
    }
    size_t pathLen = (wcslen(hookDllPath) + 1) * sizeof(wchar_t);
    void* remoteBuf = VirtualAllocEx(h, NULL, pathLen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteBuf) {
        if (msg) swprintf_s(msg, msgBytes / 2, L"VirtualAllocEx failed err=%lu", GetLastError());
        CloseHandle(h); return FALSE;
    }
    if (!WriteProcessMemory(h, remoteBuf, hookDllPath, pathLen, NULL)) {
        if (msg) swprintf_s(msg, msgBytes / 2, L"WriteProcessMemory failed err=%lu", GetLastError());
        VirtualFreeEx(h, remoteBuf, 0, MEM_RELEASE); CloseHandle(h); return FALSE;
    }
    HMODULE k32 = GetModuleHandleA("kernel32.dll");
    FARPROC loadLib = GetProcAddress(k32, "LoadLibraryW");
    if (!loadLib) { VirtualFreeEx(h, remoteBuf, 0, MEM_RELEASE); CloseHandle(h); return FALSE; }
    HANDLE th = CreateRemoteThread(h, NULL, 0, (LPTHREAD_START_ROUTINE)loadLib, remoteBuf, 0, NULL);
    if (!th) {
        if (msg) swprintf_s(msg, msgBytes / 2, L"CreateRemoteThread failed err=%lu", GetLastError());
        VirtualFreeEx(h, remoteBuf, 0, MEM_RELEASE); CloseHandle(h); return FALSE;
    }
    WaitForSingleObject(th, 5000);
    DWORD st = 0;
    GetExitCodeThread(th, &st);
    CloseHandle(th);
    VirtualFreeEx(h, remoteBuf, 0, MEM_RELEASE);
    CloseHandle(h);
    if (st == 0) {
        if (msg) swprintf_s(msg, msgBytes / 2, L"LoadLibraryW in pid %lu failed (err=%lu)", pid, GetLastError());
        return FALSE;
    }
    // DLL is now inside the target. Start a remote thread that opens the ring and
    // installs the hooks. The export RVA is identical in both processes, so we can
    // derive the remote entry address from the local one.
    HMODULE localBase = g_self ? g_self : GetModuleHandleW(L"HookEngine.dll");
    FARPROC localEntry = localBase ? GetProcAddress(localBase, "he_remote_start") : NULL;
    DWORD remoteStatus = 0;
    if (localBase && localEntry) {
        ULONG_PTR remoteEntry = (ULONG_PTR)st + ((ULONG_PTR)localEntry - (ULONG_PTR)localBase);
        HANDLE th2 = CreateRemoteThread(h, NULL, 0, (LPTHREAD_START_ROUTINE)remoteEntry, NULL, 0, NULL);
        if (th2) {
            WaitForSingleObject(th2, 8000);
            GetExitCodeThread(th2, &remoteStatus);
            CloseHandle(th2);
        }
    }
    // status bits: 1 hook ring ok, 2 net ring ok, 4 all hooks installed
    if (remoteStatus == 0 || remoteStatus == STILL_ACTIVE) {
        if (msg) swprintf_s(msg, msgBytes / 2, L"Injected pid %lu but remote start failed (code=%lu)", pid, remoteStatus);
        return FALSE;
    }
    if (msg) {
        const wchar_t* ring = (remoteStatus & 1) ? L"hook-ring=OK" : L"hook-ring=NO";
        const wchar_t* net = (remoteStatus & 2) ? L"net-ring=OK" : L"net-ring=NO";
        const wchar_t* hooks = (remoteStatus & 4) ? L"hooks=ALL" : L"hooks=PARTIAL";
        swprintf_s(msg, msgBytes / 2, L"Injected pid %lu (load=0x%08lx %ls %ls %ls)", pid, st, ring, net, hooks);
    }
    return TRUE;
}
BOOL HE_API he_set_mod_rule(ULONG slot, const HEModRule* rule) {
    if (slot >= HE_MAX_MOD_RULES || !rule) return FALSE;
    if (!g_rulesInit) { ZeroMemory(g_modRules, sizeof(g_modRules)); g_rulesInit = TRUE; }
    g_modRules[slot] = *rule;
    return TRUE;
}
BOOL HE_API he_get_mod_rule(ULONG slot, HEModRule* out) {
    if (slot >= HE_MAX_MOD_RULES || !out) return FALSE;
    if (!g_rulesInit) { ZeroMemory(g_modRules, sizeof(g_modRules)); g_rulesInit = TRUE; }
    *out = g_modRules[slot];
    return TRUE;
}
void HE_API he_reset_mod_rules(void) {
    ZeroMemory(g_modRules, sizeof(g_modRules));
    g_rulesInit = TRUE;
}
void HE_API he_set_net_capture(ULONG mask) { g_netCaptureMask = mask; }
ULONG HE_API he_get_net_capture(void) { return g_netCaptureMask; }

// DLL entry
BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        g_self = h;
    }
    return TRUE;
}

#ifdef __cplusplus
}
#endif