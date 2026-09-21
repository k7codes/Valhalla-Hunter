// ---------------------------------------------------------------------------
//  dllmain.cpp - Dinamik kutuphane giris noktasi.
//
//  DllMain'de minimum is yapilir; asil lisans mantigi license.cpp'dedir.
//  Process detach'te oturum durumu temizlenir.
// ---------------------------------------------------------------------------
#include <windows.h>
#include "license.h"

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        // Boyut optimizasyonu: is parcalari (threads) ayri yukleme istemeyiz.
        DisableThreadLibraryCalls(hModule);
        break;

    case DLL_PROCESS_DETACH:
        // Guvenlik: belirteci ve dogrulama bayragini yok et.
        ma_cleanup();
        break;

    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break;
    }
    return TRUE;
}