#include <windows.h>
#include <stdio.h>

int x64_len_dbg(const BYTE* p, int maxScan) {
    // kopya: sadece teşhis için basitleştirilmiş decoder (kendi sürümümüzü çağıracağız)
    return 0;
}

// gerçek test: kernel32 fonksiyonlarının prologue'unu dök
int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    const char* names[] = { "CreateFileW", "ReadFile", "WriteFile", "CreateProcessW",
        "VirtualAlloc", "VirtualProtect", "LoadLibraryW", "GetProcAddress", "Sleep",
        "RegOpenKeyExW", "FindWindowW", "connect" };
    HMODULE k32 = GetModuleHandleA("kernel32.dll");
    HMODULE adv = GetModuleHandleA("advapi32.dll");
    HMODULE usr = GetModuleHandleA("user32.dll");
    HMODULE ws2 = GetModuleHandleA("ws2_32.dll");
    HMODULE* mods[] = { k32, k32, k32, k32, k32, k32, k32, k32, k32, adv, usr, ws2 };
    for (int n = 0; n < 12; n++) {
        HMODULE m = mods[n];
        void* fn = (void*)GetProcAddress(m, names[n]);
        char mname[64] = {0}; GetModuleFileNameA(m, mname, 64);
        for (char* c = mname; *c; c++) if (*c == '\\') { mname[0] = 0; break; }
        printf("== %s (in %s) @ %p\n", names[n], mname, fn);
        if (!fn) { printf("   GetProcAddress FAILED\n"); continue; }
        BYTE* p = (BYTE*)fn;
        printf("   prologue: ");
        for (int i = 0; i < 28; i++) printf("%02X ", p[i]);
        printf("\n");
    }
    return 0;
}