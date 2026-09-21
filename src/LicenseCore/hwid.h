// ---------------------------------------------------------------------------
//  hwid.h - Donanim Kimligi (HWID) uretim arayuzu.
//  Yalnizca native Win32 API kullanir; C# tarafina GUVENILMEZ.
// ---------------------------------------------------------------------------
#pragma once
#include <string>

namespace license
{
    // Bilgisayarin benzersiz donanim kimligini uretir.
    // Bilesenler: Anakart UUID (SMBIOS) + Ilk sabit diskin seri numarasi.
    // Sonuc: SHA-256 hex (64 karakter + NUL).
    //
    // cikti  : en az 65 byte'lik buffer'a hex HWID yazilir.
    // cap    : buffer kapasitesi.
    // Donus degeri: basariliysa true (cikti doldurulur).
    bool ComputeHardwareId(char* cikti, size_t cap);

    // Sadece anakart UUID'sini ham (hex, tireli) bicimde dondurur.
    // Basarisizsa bos string.
    std::string GetMotherboardUuid();

    // Sadece disk seri numarasini dondurur. Basarisizsa bos string.
    std::string GetDiskSerialNumber();
}