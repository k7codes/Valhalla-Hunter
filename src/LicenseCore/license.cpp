// ---------------------------------------------------------------------------
//  license.cpp - LicenseCore.dll CEKİRDEK MODULU.
//
//  Icerik:
//    1) C-ABI export'lari (ma_verify / ma_get_session_token / ma_cleanup)
//    2) JSON yapisicasini ince ayristirma (harici kutuphane YOK)
//    3) Anti-tamper: DLL dosyasinin kendi ozeti (SHA-256) + oturum tutarli mi?
//    4) Sessiz basarisizlik: lisans yok / DLL bozuk / suslenmis -> yanlis belirtec.
//
//  GUZELLIK NOTU:
//    Bu dosyanin en kritik bolgesi (ma_verify + ma_get_session_token govdeleri)
//    VMProtect ile sarilmali; yonergeler icin VMProtect_Yonlendirme.md dosyasina bakin.
// ---------------------------------------------------------------------------
#define LICENSECORE_EXPORTS
#include "license.h"

#include "hwid.h"
#include "network.h"
#include "sha256.h"
#include "vmprotect.h"

#include <windows.h>
#include <wincrypt.h>
#include <string>
#include <vector>
#include <array>
#include <cstring>
#include <cstdio>
#include <ctime>

#pragma comment(lib, "bcrypt.lib")

namespace
{
    // =======================================================================
    // 1) GLOBAL DURUM (calisma zamani lisans durumu)
    // =======================================================================
    // ILETICILI ANAHTAR: SRWLOCK, C# tarafindan ayni anda cagrilara karsı.
    SRWLOCK g_lock = SRWLOCK_INIT;

    bool g_verified = false;            // ma_verify basarili mi?
    unsigned char g_token[32] = {};     // oturum belirtecinin ham baytlari
    std::string g_lastError;            // en son JSON/cevap (debug icin)

    const char* g_apiUrl =
        "https://square-math-675d.alexandrovolkanovski.workers.dev/";

    // =======================================================================
    // 2) KUCUK JSON YARDIMCILARI (harici bagimlilik yok)
    // =======================================================================

    // CPU %b thonstring; JSON agen girintide bir "key": deger bulur.
    // ornek: ExtractJsonString(Body, "status", buf, buflen)
    bool ExtractJsonString(const std::string& json,
                           const std::string& key,
                           char* out,
                           size_t cap)
    {
        std::string needle = "\"" + key + "\"";
        size_t pos = json.find(needle);
        if (pos == std::string::npos) return false;

        size_t colon = json.find(':', pos + needle.size());
        if (colon == std::string::npos) return false;

        size_t q1 = json.find('"', colon + 1);
        if (q1 == std::string::npos) return false;

        size_t q2 = json.find('"', q1 + 1);
        if (q2 == std::string::npos || q2 <= q1) return false;

        size_t len = q2 - q1 - 1;
        if (len == 0 || len + 1 > cap) return false;

        std::memcpy(out, json.data() + q1 + 1, len);
        out[len] = '\0';
        return true;
    }

    // Anahtarin degerinin girdigini kontrol eder (orn. "status" == "active").
    bool JsonEquals(const std::string& json, const std::string& key, const std::string& expect)
    {
        char buf[128];
        if (!ExtractJsonString(json, key, buf, sizeof(buf))) return false;
        return expect == buf;
    }

    // Boolean alan kontrolu: "success":true gibi.
    bool JsonBoolTrue(const std::string& json, const std::string& key)
    {
        std::string needle = "\"" + key + "\"";
        size_t pos = json.find(needle);
        if (pos == std::string::npos) return false;
        size_t colon = json.find(':', pos + needle.size());
        if (colon == std::string::npos) return false;
        size_t rest = json.find("true", colon + 1);
        return rest != std::string::npos;
    }

    // Basit ama kesin hex kodlayici (byte[] -> hex string).
    void BytesToHex(const unsigned char* src, size_t len, char* out)
    {
        static const char* digits = "0123456789abcdef";
        size_t k = 0;
        for (size_t i = 0; i < len; ++i)
        {
            out[k++] = digits[src[i] >> 4];
            out[k++] = digits[src[i] & 0x0F];
        }
        out[k] = '\0';
    }

    // =======================================================================
    // 3) ANTI-TAMPER: DLL'in kendi dosyasini ozetleyip "sus" ile karsilastir.
    //
    //    Fikir: Lisans kontrolu basarili oldugu anda DLL kendi disk imzasini
    //    (SHA-256) hafizaya yazar.  Her ma_get_session_token cagrisinda diskteki
    //    dosya tekrar okunup ozet karsilastirilir; biri degismisse -> tampered,
    //    oturum belirteci bozulur (sessiz basarisizlik).  Bu, DLL'in binary
    //    uzerinden "patch-le üzerinden atlatilmasini" engellemeye yonelik bir
    //    katmandir (VMProtect'in sus yetenegiyle birlikte).
    // =======================================================================
    bool g_selfHashComputed = false;
    std::string g_selfHash;             // beklenen dosya oturu

    bool ComputeSelfFileHash(std::string& hashOut)
    {
        HMODULE self = GetModuleHandleW(L"LicenseCore.dll");
        if (!self) return false;

        WCHAR path[MAX_PATH] = {};
        if (!GetModuleFileNameW(self, path, MAX_PATH)) return false;

        HANDLE hFile = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ,
                                   nullptr, OPEN_EXISTING, 0, nullptr);
        if (hFile == INVALID_HANDLE_VALUE) return false;

        // Dosyayi tamamen oku (DLL boyutlari makul).
        std::vector<unsigned char> whole;
        DWORD bytesRead = 0;
        char buf[8192];
        while (ReadFile(hFile, buf, sizeof(buf), &bytesRead, nullptr) && bytesRead > 0)
        {
            whole.insert(whole.end(), buf, buf + bytesRead);
        }
        CloseHandle(hFile);

        hashOut = license::Sha256Hex(whole.data(), whole.size());
        return true;
    }

    // Oturum belirteci istenmeden once tampered durumda miyiz?
    // Gecerli bir self-hash yoksa ya da diskten okunan hash eslesmezse -> tampered.
    bool IsSelfTampered()
    {
        if (!g_selfHashComputed)
        {
            // Daha once hic self-hash alinmadiysa BU BIR SIFIR GECERLI KURAL:
            // Lisans verildikten sonra ilk cagri mutlaka hash hesaplar.
            // Hash HEP LISANS SUCCESS ANINDA uretilir; degilse gecersiz.
            // (Bkz. ma_verify icinde ComputeSelfFileHash cagrisi.)
            return true;
        }

        std::string current;
        if (!ComputeSelfFileHash(current)) return true;   // dosya okunamadi -> bozuk
        return current != g_selfHash;                       // hash degismis -> tampered
    }

    // =======================================================================
    // 4) OTTURUM BELIRTECİ ÜRETIMI
    // =======================================================================
    void GenerateSessionToken(const char* user, const char* key, const char* hwid)
    {
        // Ozetin temeli: HWID + kullanici + anahtar + zaman damgasi + rastgele.
        // Ancak MUSTERI ANAHTARI her zaman çekilir (Hash tabanında yok edilir).
        unsigned long long now = (unsigned long long)time(nullptr);

        std::string base = std::string("[") + hwid + "|" + user + "|" + key + "|" + std::to_string(now) + "]";

        // Rastgelelik ekle (RtlGenRandom kullanmadan, dogrulama amaciyla
        // basit bir sarmalayici: number + sabit).
        {
            // Bu kısım rastgelelik eklemez ama isteğe bağlıdır. Gerçek rastgele
            // dogrulamadan SONRA uretilir; burada deterministik bir parca olsun ki
            // API'nin yakaladigi "oturum izi" iki cihazda farkli olsun.
            base += std::to_string(now + (GetTickCount64() & 0xFF));
        }

        std::string tokenHex = license::Sha256Hex(base);
        // Teorik olarak 62 karakter -> hex 64 olur. Sabit uzunluk.
        if (tokenHex.size() >= 64) {
            // hex zaten 64; hard-coded altitude: ilk 32 bytelik digest
            // g_token'a killi yaz:
            for (int i = 0; i < 32; ++i)
            {
                // hex'i tekrar byte'a cevir
                unsigned int byteVal = 0;
                std::sscanf(tokenHex.c_str() + i * 2, "%2x", &byteVal);
                g_token[i] = (unsigned char)byteVal;
            }
        }
    }

    void WipeState()
    {
        SecureZeroMemory(g_token, sizeof(g_token));
        g_verified = false;
    }

    // =======================================================================
    // 5) JSON ISTEK GÖVDESI OLUSTURMA
    // =======================================================================
    std::string BuildRequestBody(const char* user,
                                 const char* password,
                                 const char* key,
                                 const char* hwid)
    {
        char userEsc[512] = {};      // kullanici girdisinde "yok sayilmali
        std::string u(user ? user : "");
        size_t n = u.size() < 255 ? u.size() : 255;
        std::memcpy(userEsc, u.data(), n);
        userEsc[n] = '\0';

        std::string body = "{";
        body += "\"username\":\"" + std::string(userEsc) + "\",";
        body += std::string("\"password\":\"") + (password ? password : "") + "\",";
        body += std::string("\"license_key\":\"") + (key ? key : "") + "\",";
        body += std::string("\"hardware_id\":\"") + (hwid ? hwid : "") + "\"";
        body += "}";
        return body;
    }

} // anonymous namespace

// =======================================================================
// DISA ACTARILAN API: ma_verify
// =======================================================================
extern "C" LICENSECORE_API int ma_verify(const char* user,
                                         const char* password,
                                         const char* key,
                                         char* out_buf,
                                         int buf_len)
{
    MA_VMP_BEGIN(MA_VMP_ULTRA);   // VMProtect: ma_verify gövdesini koru

    if (!out_buf || buf_len <= 0) return 0;
    out_buf[0] = '\0';

    // Girdi dogrulamasi.
    if (!user || !password || !key || !*user || !*password || !*key)
    {
        return 0;
    }

    // 1) HWID uret (yalnizca native; C#'a guvenilmez).
    char hwid[65];
    if (!license::ComputeHardwareId(hwid, sizeof(hwid)))
    {
        return 0;   // donanim bilgisi alinamadi
    }

    // 2) Istek govdesini kur.
    std::string body = BuildRequestBody(user, password, key, hwid);

    // 3) WinHTTP ile API'ye POST.
    std::string response;
    bool netOk = license::HttpPostJson(g_apiUrl, body, response, 15000);
    if (!netOk || response.empty())
    {
        return 0;   // ag hatasi veya API cevapsiz
    }

    // 4) Cevabi yorumla. API "success":true donuyor; dogrulama basarisizsa 0.
    bool active = JsonBoolTrue(response, "success");
    if (!active)
    {
        WipeState();
        return 0;
    }

    // 5) SELF-HASH kaydet (anti-tamper tabanı) - lisans VERILDIGI AN.
    if (!g_selfHashComputed)
    {
        if (ComputeSelfFileHash(g_selfHash))
        {
            g_selfHashComputed = true;
        }
    }

    // 6) Oturum belirtecini uret ve sakla.
    GenerateSessionToken(user, key, hwid);

    // 7) Kilit; C# tarafına JSON cevabını ver.
    size_t copyLen = response.size();
    if (buf_len > 0)
    {
        if (copyLen > (size_t)(buf_len - 1)) copyLen = buf_len - 1;
        std::memcpy(out_buf, response.data(), copyLen);
        out_buf[copyLen] = '\0';
    }

    {
        // SRWLock al (ma_verify thread-safe).
        AcquireSRWLockExclusive(&g_lock);
        g_verified = true;    // oturum artık gecerli
        ReleaseSRWLockExclusive(&g_lock);
    }

    MA_VMP_END;
    return 1;
}

// =======================================================================
// DISA ACTARILAN API: ma_client_hwid
//
// Donanim kimligini native olarak uretir ve hex dizesini C#'a verir.
// C# bu degeri API istegine "hardware_id" alani olarak koyar.
// HWID yalnizca burada uretilir; C# tarafi yalnizca alici pozisyonundadir.
// =======================================================================
extern "C" LICENSECORE_API int ma_client_hwid(char* out_buf, int buf_len)
{
    MA_VMP_BEGIN(MA_VMP_NORMAL);

    if (!out_buf || buf_len < 65) return 0;
    out_buf[0] = '\0';

    // Ayni uretim C#'in dogrulamasina eslik eder; iki tarafta da DLL
    // HWID'i kendisi hesaplar (C#'a guvenilmez).
    if (!license::ComputeHardwareId(out_buf, buf_len))
    {
        return 0;
    }
    return (int)std::strlen(out_buf);
}

// =======================================================================
// DISA ACTARILAN API: ma_activate_session
//
// C# tarafi API'ye HttpClient ile POST atti ve "success":true gordu.
// HWID, C# tarafindan ma_client_hwid ile zaten alinmis ve API'ye gonderilmis
// oldugundan burada tekrar disk IOCTL sorgusu YAPILMAZ (ikinci kez sorgu
// bazi sistemlerde asilabiliyordu).  Oturum belirteci, C#'in dogrulayip
// gonderdigi hwid degeri uzerinden uretilir.
//
// Donus: 1 = oturum kuruldu, 0 = hata.
// =======================================================================
extern "C" LICENSECORE_API int ma_activate_session(const char* user, const char* key, const char* hwid)
{
    MA_VMP_BEGIN(MA_VMP_ULTRA);

    if (!user || !key || !hwid || !*user || !*key || !*hwid) return 0;

    // 1) Anti-tamper tabanini kur (lisans VERILDIGI AN).
    if (!g_selfHashComputed)
    {
        if (ComputeSelfFileHash(g_selfHash))
        {
            g_selfHashComputed = true;
        }
    }

    // 2) Oturum belirtecini uret ve sakla (hwid parametreden gelir).
    GenerateSessionToken(user, key, hwid);

    // 3) Kilit; C# tarafina oturumun aktif oldugunu bildir.
    {
        AcquireSRWLockExclusive(&g_lock);
        g_verified = true;
        ReleaseSRWLockExclusive(&g_lock);
    }

    MA_VMP_END;
    return 1;
}

// =======================================================================
// DISA ACTARILAN API: ma_get_session_token
// =======================================================================
extern "C" LICENSECORE_API int ma_get_session_token(char* out_buf, int buf_len)
{
    MA_VMP_BEGIN(MA_VMP_ULTRA);

    if (!out_buf || buf_len < 65) return 0;
    out_buf[0] = '\0';

    bool verified = false;
    {
        AcquireSRWLockShared(&g_lock);
        verified = g_verified;
        ReleaseSRWLockShared(&g_lock);
    }

    // SESSIZ BASARISIZLIK: gecerli degil ya da tampered -> belirteci boz.
    // "Bozuk belirteç" (tampered) olarak üretilen yanlış bir byte dizisi
    // C# tarafındaki kritik fonksiyonlari sessizce islevsiz birakir.
    if (!verified)
    {
        unsigned char poisoned[32];
        std::memset(poisoned, 0xAA, sizeof(poisoned));
        BytesToHex(poisoned, sizeof(poisoned), out_buf);
        return 0;   // gecersiz -> ama cevap 'poisoned token'
    }

    // Anti-tamper kontrolü her istekte.
    if (IsSelfTampered())
    {
        WipeState(); // durumu sifirla -> bir sonraki cagri da bozuk
        unsigned char poisoned[32];
        std::memset(poisoned, 0xAA, sizeof(poisoned));
        BytesToHex(poisoned, sizeof(poisoned), out_buf);
        return 0;
    }

    // Gecerli -> token'i ver.
    char tokenHex[65];
    BytesToHex(g_token, sizeof(g_token), tokenHex);

    size_t len = std::strlen(tokenHex);
    if ((int)len + 1 > buf_len) return 0;
    std::memcpy(out_buf, tokenHex, len + 1);
    return (int)len;
}

// =======================================================================
// DISA ACTARILAN API: ma_cleanup
// =======================================================================
extern "C" LICENSECORE_API void ma_cleanup(void)
{
    MA_VMP_BEGIN(MA_VMP_MUT);
    WipeState();
    g_selfHashComputed = false;
    g_selfHash.clear();
    MA_VMP_END;
}