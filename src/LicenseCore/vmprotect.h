// ---------------------------------------------------------------------------
//  vmprotect.h - VMProtect isaretci (marker) soyutlamasi.
//
//  AMAC:
//    * VMProtect SDK kurulu DEĞİLKEN proje sorunsuz derlenir (marker'lar
//      no-op makro olur).
//    * SDK eklendiginde yalnizca MA_USE_VMPROTECT tanimlanir ve
//      VMProtectSDK32.lib / VMProtectSDK64.lib baglanir; isaretciler devreye girer.
//
//  KULLANIM (ornek):
//    #include "vmprotect.h"
//    ...
//    MA_VMP_BEGIN(MA_VMP_ULTRA);   // kritik blok
//    ... dogrulama kodu ...
//    MA_VMP_END;
// ---------------------------------------------------------------------------
#pragma once

#ifdef MA_USE_VMPROTECT

    // --- Gercek VMProtect SDK entegrasyonu -------------------------------
    // NuGet/VCPkg yerine VMProtect SDK'sini dahil et:
    //   1) include klasorunu  -> AdditionalIncludeDirectories
    //   2) static lib 64-bit  -> VMProtectSDK64.lib (proje dizininde)
    #include <VMProtectSDK.h>

    #define MA_VMP_BEGIN(code)  code
    #define MA_VMP_END          VMProtectEnd()

#else

    // --- SDK'siz derleme (no-op marker'lar) ------------------------------
    // Derleme sirasinda fonksiyonlarin isaretli olmasini istemiyorsan
    // bu dallari acik birak. HICBIR SEKILDE kodu degistirmez.
    #define MA_VMP_BEGIN(code)  do { (void)0; } while (0)
    #define MA_VMP_END

    // Kullanim kolayligi icin hazir etiketler:
    #define MA_VMP_ULTRA          VMProtectBeginUltra("ma_block")
    #define MA_VMP_VM             VMProtectBeginVirtualization("ma_block")
    #define MA_VMP_MUT            VMProtectBeginMutation("ma_block")

#endif // MA_USE_VMPROTECT

#ifdef MA_USE_VMPROTECT
    // VMProtect tanimlarini gecerli yap: begin/end fonksiyon cagrisi bicimindedir.
    #undef  MA_VMP_BEGIN
    #define MA_VMP_BEGIN(code)  code
    #undef  MA_VMP_END
    #define MA_VMP_END          VMProtectEnd()
#endif