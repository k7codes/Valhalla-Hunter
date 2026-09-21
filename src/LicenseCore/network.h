// ---------------------------------------------------------------------------
//  network.h - WinHTTP tabanli, harici bagimlilik icermeyen HTTPS/POST istemcisi.
// ---------------------------------------------------------------------------
#pragma once
#include <string>

namespace license
{
    // Belirtilen HTTPS (veya HTTP) adresine JSON gonderir ve cevabi dondurur.
    //
    // url       : Ornek  https://square-math-675d.alexandrovolkanovski.workers.dev/
    // jsonBody  : Gonderilecek ham JSON metni
    // outResp   : API'nin dondugu ham metin (basarili ise)
    // timeoutMs : Toplam istek zamansi
    //
    // Donus: HTTP 200 ve gecerli istek alindiysa true.
    bool HttpPostJson(
        const std::string& url,
        const std::string& jsonBody,
        std::string& outResp,
        unsigned long timeoutMs = 15000);
}