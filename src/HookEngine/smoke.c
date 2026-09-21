// Smoke testi: HookEngine.dll'yi yukler, ring acar, bir kac API hooklar,
// islem yapar ve olay kuyrugunu okur.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <stdio.h>
#include <wchar.h>
#include <string.h>

#define HE_ARG_TEXT 256
#define HE_RET_TEXT 64
#define HE_MAX_ARGS 6
#define HE_PAYLOAD_MAX 512

typedef struct {
    ULONGLONG ts;
    ULONG pid;
    ULONG tid;
    ULONG apiId;
    ULONG argCount;
    ULONG_PTR args[HE_MAX_ARGS];
    ULONG_PTR ret;
    char text[HE_ARG_TEXT];
    char retText[HE_RET_TEXT];
    int direction;
    ULONG payloadLen;
    BYTE payload[HE_PAYLOAD_MAX];
} HEHookEvent;

typedef struct {
    char module[24];
    char name[64];
    char retKind[8];
    char argKinds[HE_MAX_ARGS][8];
    ULONG argCount;
    ULONG risk;
    BOOL netRelated;
} HEApiInfo;

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    HMODULE dll = LoadLibraryW(L"Output\\HookEngine.dll");
    if (!dll) { printf("LoadLibrary FAILED err=%lu\n", GetLastError()); return 1; }

    ULONG (__cdecl *version)(void) = (void*)GetProcAddress(dll, "he_version");
    const wchar_t* (__cdecl *module_path)(void) = (void*)GetProcAddress(dll, "he_module_path");
    ULONG (__cdecl *catalog_count)(void) = (void*)GetProcAddress(dll, "he_catalog_count");
    BOOL (__cdecl *catalog_info)(ULONG, HEApiInfo*) = (void*)GetProcAddress(dll, "he_catalog_info");
    BOOL (__cdecl *open_ring)(const wchar_t*) = (void*)GetProcAddress(dll, "he_open_ring");
    void (__cdecl *close_ring)(void) = (void*)GetProcAddress(dll, "he_close_ring");
    BOOL (__cdecl *hook)(ULONG) = (void*)GetProcAddress(dll, "he_hook");
    BOOL (__cdecl *hook_all)(void) = (void*)GetProcAddress(dll, "he_hook_all");
    void (__cdecl *unhook_all)(void) = (void*)GetProcAddress(dll, "he_unhook_all");
    BOOL (__cdecl *is_hooked)(ULONG) = (void*)GetProcAddress(dll, "he_is_hooked");
    ULONG (__cdecl *available)(void) = (void*)GetProcAddress(dll, "he_events_available");
    ULONG (__cdecl *read_events)(HEHookEvent*, ULONG) = (void*)GetProcAddress(dll, "he_read_events");
    ULONG (__cdecl *total_calls)(ULONG) = (void*)GetProcAddress(dll, "he_total_calls");
    BOOL (__cdecl *net_open)(void) = (void*)GetProcAddress(dll, "he_net_open");
    void (__cdecl *net_close)(void) = (void*)GetProcAddress(dll, "he_net_close");
    ULONG (__cdecl *net_available)(void) = (void*)GetProcAddress(dll, "he_net_events_available");
    ULONG (__cdecl *net_read_events)(HEHookEvent*, ULONG) = (void*)GetProcAddress(dll, "he_net_read_events");
    void (__cdecl *net_clear_events)(void) = (void*)GetProcAddress(dll, "he_net_clear_events");
    ULONG (__cdecl *set_net_mask)(ULONG) = (void*)GetProcAddress(dll, "he_set_net_capture");
    ULONG (__cdecl *get_net_mask)(void) = (void*)GetProcAddress(dll, "he_get_net_capture");

    if (!version || !module_path || !catalog_count || !catalog_info || !open_ring ||
        !hook || !hook_all || !unhook_all || !is_hooked || !available || !read_events ||
        !net_open || !net_close || !net_available || !net_read_events || !set_net_mask || !get_net_mask) {
        printf("GetProcAddress FAILED (one or more) err=%lu\n", GetLastError());
        return 1;
    }

    printf("he_version           = 0x%08lx\n", version());
    printf("he_module_path       = %ls\n", module_path());

    ULONG ncat = catalog_count();
    printf("catalog_count        = %lu\n", ncat);
    for (ULONG i = 0; i < ncat && i < 6; i++) {
        HEApiInfo info; if (catalog_info(i, &info))
            printf("  [%02lu] %s!%s risk=%lu net=%d args=%lu\n",
                   i, info.module, info.name, info.risk, info.netRelated, info.argCount);
    }

    if (!open_ring(L"smoke")) { printf("open_ring FAILED\n"); return 1; }
    printf("ring open OK\n");

    BOOL h0 = hook(0);   printf("after hook(0)\n");
    BOOL h1 = hook(1);   printf("after hook(1)\n");
    BOOL h2 = hook(2);   printf("after hook(2)\n");
    BOOL h15 = hook(15); printf("after hook(15)\n");
    printf("hook CreateFileW=%d ReadFile=%d WriteFile=%d Sleep=%d (is_hooked={%d,%d,%d,%d})\n",
           h0, h1, h2, h15, is_hooked(0), is_hooked(1), is_hooked(2), is_hooked(15));

    // dosya islemleri -> olay uretir
    wchar_t path[MAX_PATH];
    swprintf_s(path, MAX_PATH, L"%ls\\valhalla_smoke.tmp", L"C:\\Users\\k7\\AppData\\Local\\Temp\\opencode");
    {
        HANDLE f = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (f != INVALID_HANDLE_VALUE) {
            DWORD w = 0; const char* data = "VALHALLASMOKE42";
            WriteFile(f, data, 16, &w, NULL);
            CloseHandle(f);
        }
        HANDLE g = CreateFileW(path, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (g != INVALID_HANDLE_VALUE) {
            char buf[64]; DWORD r = 0;
            ReadFile(g, buf, 64, &r, NULL);
            CloseHandle(g);
        }
        DeleteFileW(path);
    }
    Sleep(10);

    ULONG avail0 = available();
    printf("events_available     = %lu  (total_calls: CreateFileW=%lu ReadFile=%lu WriteFile=%lu Sleep=%lu)\n",
           avail0, total_calls(0), total_calls(1), total_calls(2), total_calls(15));

    HEHookEvent ev[256];
    ULONG n = read_events(ev, 256);
    printf("read_events          = %lu\n", n);
    for (ULONG i = 0; i < n && i < 12; i++) {
        HEHookEvent* e = &ev[i];
        printf("  ev[%02lu] api=%lu pid=%lu tid=%lu args=%lu ret=0x%Ix dir=%d text='%s' retText='%s'\n",
               i, e->apiId, e->pid, e->tid, e->argCount, e->ret, e->direction, e->text, e->retText);
    }
    printf("available_after_read = %lu\n", available());

    // ---- network ring test (ağ API'leri önce hooklanır) ----
    for (ULONG i = 21; i <= 24; i++) { BOOL ok = hook(i); printf("    NH[%02lu]=%d\n", i, ok); }
    net_open();
    printf("net ring open OK, mask=0x%lx\n", get_net_mask());
    set_net_mask(0x3F); // hoparlor capture on
    printf("net mask set -> 0x%lx\n", get_net_mask());

    // WSADATA + socket + send/recv over a local loopback UDP pair
    {
        WSADATA ws;
        if (WSAStartup(MAKEWORD(2, 2), &ws) == 0) {
            SOCKET a = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
            SOCKET b = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
            struct sockaddr_in addr; memset(&addr, 0, sizeof(addr));
            addr.sin_family = AF_INET; addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK); addr.sin_port = 0;
            if (a != INVALID_SOCKET && b != INVALID_SOCKET) {
                bind(a, (struct sockaddr*)&addr, sizeof(addr));
                bind(b, (struct sockaddr*)&addr, sizeof(addr));
                struct sockaddr_in ainfo; int alen = sizeof(ainfo);
                getsockname(a, (struct sockaddr*)&ainfo, &alen);
                const char* msg = "HELLO-VALHALLA-NET";
                sendto(b, msg, 18, 0, (struct sockaddr*)&ainfo, sizeof(ainfo));
                char rbuf[64];
                recvfrom(a, rbuf, sizeof(rbuf), 0, NULL, NULL);
                closesocket(a); closesocket(b);
                printf("udp loopback send/recv done\n");
            }
            WSACleanup();
        } else {
            printf("WSAStartup FAILED err=%d\n", WSAGetLastError());
        }
    }
    Sleep(10);

    ULONG navail = net_available();
    printf("net_events_available = %lu\n", navail);
    HEHookEvent nev[256];
    ULONG nn = net_read_events(nev, 256);
    printf("net_read_events      = %lu\n", nn);
    for (ULONG i = 0; i < nn && i < 8; i++) {
        HEHookEvent* e = &nev[i];
        printf("  net[%02lu] api=%lu dir=%d ret=0x%Ix text='%s' payloadLen=%lu\n",
               i, e->apiId, e->direction, e->ret, e->text, e->payloadLen);
        if (e->payloadLen > 0 && e->payloadLen <= 32) {
            printf("         payload='%.*s'\n", (int)e->payloadLen, e->payload);
        }
    }
    net_clear_events();
    net_close();
    printf("net ring close done, available=%lu\n", net_available());

    // her slotu tek tek dene, ilk hatada/beklenmedik noktada bilgi ver
    int fails = 0;
    for (ULONG i = 0; i < ncat; i++) {
        BOOL ok = hook(i);
        printf("    H[%02lu]=%d\n", i, ok);
        if (!ok) fails++;
    }
    printf("hook_all(loop) done fails=%d (catalog=%lu)\n", fails, ncat);
    Sleep(5);
    unhook_all();
    printf("unhook_all done\n");

    close_ring();
    FreeLibrary(dll);
    printf("SMOKE OK\n");
    return 0;
}