#pragma once
#include <windows.h>
#include <stdint.h>

#ifdef HOOKENGINE_EXPORTS
#define HE_API __declspec(dllexport)
#else
#define HE_API __declspec(dllimport)
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define HE_RING_NAME    L"Local\\ValhallaHookRing"
#define HE_NET_RING_NAME L"Local\\ValhallaNetRing"
#define HE_RING_SIZE    (16 * 1024 * 1024)
#define HE_MAX_EVENTS   8192
#define HE_ARG_TEXT     256
#define HE_RET_TEXT     64
#define HE_MAX_ARGS     6
#define HE_MSG          192

#define HE_NET_CAPTURE_SEND   0x01
#define HE_NET_CAPTURE_RECV   0x02
#define HE_NET_CAPTURE_SENDTO  0x04
#define HE_NET_CAPTURE_RECVFROM 0x08
#define HE_PAYLOAD_MAX         512

typedef struct {
    ULONGLONG ts;              // QPC ticks since ring open
    ULONG pid;
    ULONG tid;
    ULONG apiId;               // catalog index
    ULONG argCount;
    ULONG_PTR args[HE_MAX_ARGS];
    ULONG_PTR ret;
    char text[HE_ARG_TEXT];    // formatted args (pre-call snapshot)
    char retText[HE_RET_TEXT]; // formatted return
    int direction;             // +1 send, -1 recv, 0 other (network events)
    ULONG payloadLen;          // bytes copied into payload[] (0 = none)
    BYTE  payload[HE_PAYLOAD_MAX]; // raw bytes for send/recv payload inspection
} HEHookEvent;

typedef struct {
    ULONG magic;               // 0x56484F4B 'VHOK'
    ULONG version;
    ULONG eventSize;           // sizeof(HEHookEvent)
    ULONG capacity;            // HE_MAX_EVENTS
    volatile LONG head;       // reader consumed counter
    volatile LONG tail;       // writer claim counter
    volatile LONG committed;  // writer published counter (readable up to here)
    ULONG overflowDrop;
    ULONGLONG openTicks;       // timestamp base
    ULONG pidWriter;           // process that owns the writer
    char moduleName[64];
} HERingHeader;

typedef struct {
    char module[24];
    char name[64];
    char retKind[8];           // "ptr","i32","u32","i64","u64","bool","hnd","void"
    char argKinds[HE_MAX_ARGS][8]; // per-arg kinds: wstr,astr,ptr,hnd,i32,u32,i64,u64,hex32,voidp,size,dmethod(flags),mask(in/out),sock
    ULONG argCount;
    ULONG risk;                // 0..3 (info/low/med/high)
    BOOL  netRelated;          // ws2_32 / network relevant
} HEApiInfo;

// ---- engine control (self-hook) ----
HE_API ULONG  he_version(void);
HE_API const wchar_t* he_module_path(void);

// ---- inline hook install/uninstall for THIS process ----
HE_API BOOL   he_open_ring(const wchar_t* moduleName);
HE_API void   he_close_ring(void);
HE_API ULONG  he_catalog_count(void);
HE_API BOOL   he_catalog_info(ULONG index, HEApiInfo* out);
HE_API BOOL   he_hook(ULONG apiId);
HE_API BOOL   he_unhook(ULONG apiId);
HE_API BOOL   he_hook_all(void);
HE_API void   he_unhook_all(void);
HE_API BOOL   he_is_hooked(ULONG apiId);

// ---- log drain (call from the same process that opened the ring) ----
HE_API ULONG  he_events_available(void);
HE_API ULONG  he_read_events(HEHookEvent* out, ULONG maxCount);
HE_API void   he_clear_events(void);

// ---- network event channel (independent ring for send/recv payloads) ----
HE_API BOOL   he_net_open(void);
HE_API void   he_net_close(void);
HE_API ULONG  he_net_events_available(void);
HE_API ULONG  he_net_read_events(HEHookEvent* out, ULONG maxCount);
HE_API void   he_net_clear_events(void);

// ---- remote injection: spawn suspended & inject, or inject running PID ----
HE_API BOOL   he_inject_process(DWORD pid, const wchar_t* hookDllPath, wchar_t* msg, size_t msgBytes);
HE_API BOOL   he_spawn_and_inject(const wchar_t* exePath, const wchar_t* hookDllPath,
                                  DWORD* outPid, wchar_t* msg, size_t msgBytes);
HE_API BOOL   he_remote_start(void);

// ---- network manipulation rules (applied on send/recv/WSASend/WSARecv) ----
#define HE_MAX_MOD_RULES 8
#define HE_MOD_MAX_LEN   64
typedef struct {
    BOOL   active;
    int    direction;          // +1 apply to outgoing, -1 incoming, 0 both
    ULONG  haystackLen;        // not used (auto)
    BYTE   find[HE_MOD_MAX_LEN];
    ULONG  findLen;
    BYTE   replace[HE_MOD_MAX_LEN];
    ULONG  replaceLen;
    char   label[48];
} HEModRule;

HE_API BOOL he_set_mod_rule(ULONG slot, const HEModRule* rule);
HE_API BOOL he_get_mod_rule(ULONG slot, HEModRule* out);
HE_API void he_reset_mod_rules(void);

// ---- capture toggles for network stack hooks (default all on) ----
HE_API void he_set_net_capture(ULONG mask);
HE_API ULONG he_get_net_capture(void);

// ---- stats ----
HE_API ULONG he_total_calls(ULONG apiId);

#ifdef __cplusplus
}
#endif