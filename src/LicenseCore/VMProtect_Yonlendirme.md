# VMProtect Koruma Yönlendirmesi — LicenseCore.dll

Bu doküman, `LicenseCore.dll` içinde hangi fonksiyonların hangi VMProtect
tekniğiyle korunacağını netleştirir. Proje şu an SDK'sız derleniyor
(`vmprotect.h` içindeki `MA_USE_VMPROTECT` tanımı kapalı).

---

## 1) Çalışma prensibi

Kodda üç VMProtect marker'ı hazır durumdadır:

| Marker | Açıklama | Ne zaman kullanılır |
|---|---|---|
| `MA_VMP_ULTRA` | `VMProtectBeginUltra` | En kritik, manuel analiz & anti-debug |
| `MA_VMP_VM` | `VMProtectBeginVirtualization` | Yüksek koruma (karmaşık kod) |
| `MA_VMP_MUT` | `VMProtectBeginMutation` | Hafif koruma, hız hassas yerler |

Söz dizimi kodda şöyle:

```cpp
MA_VMP_BEGIN(MA_VMP_ULTRA);   // blok basi
    ... korunacak govde ...
MA_VMP_END;                   // blok sonu
```

---

## 2) Hangi fonksiyonlar hangi korumayla?

| Fonksiyon | Öneri | Gerekçe |
|---|---|---|
| `ma_verify` | **ULTRA** (`MA_VMP_ULTRA`) | API'ye giden istek, HWID, JSON parse, lisans kararı. Anti-debug en yoğun burada. |
| `ma_get_session_token` | **ULTRA** (`MA_VMP_ULTRA`) | Oturum belirteci üretimi + anti-tamper kontrolü. Crack'çünün en çok uğraşacağı dönüş noktası. |
| `IsSelfTampered` / self-hash | **VM** (`MA_VMP_VM`) | Diskteki DLL'i hash ile karşılaştırma; VM mutasyonu + virtualizasyon yavaşlatır ama güvenli. |
| `ExtractJsonString` / JSON helper | **MUT** (`MA_VMP_MUT`) | Hız ister, ama string sabitlerinin okunmasını zorlaştırır. |
| `ComputeSelfFileHash` | **MUT** | Dosya okuma; çok koruma gerektirmez ama marker koymak iyi. |
| `BuildRequestBody` | **MUT** | JSON yapılanması. |
| `ma_cleanup` / `dllmain.cpp` | **korumasız** | Temizlik ve giriş; VM eklemek stabilite riski verir, faydası az. |
| `network.cpp` WinHTTP | **korumasız** | Ağ katmanı zaten TLS; Wireshark ile görülür. VM eklemeksiz bırakın (stabilite). |

> ⚠️ **Kritik:** `ma_verify` ve `ma_get_session_token` gövdesini **ULTRA**
> ile sarmayı unutmayın. Bunlar rakip yazılım tarafının atlattığı ilk nokta.

---

## 3) SDK kurulumu (aktif etme)

1. VMProtect SDK'sını projenin bir klasörüne kopyalayın (örn. `third_party\vmprotect\`).
2. `vmprotect.h` içindeki `#ifdef MA_USE_VMPROTECT` dalının aktif olması için
   derleyiciye `-DMA_USE_VMPROTECT` ekleyin (veya vcxproj → Preprocessor Definitions).
3. `VMProtectSDK64.lib` dosyasını linker'a tanıtın (vcxproj → Additional Dependencies).
4. Son ürünü **VMProtect GUI** ile açıp **Project → Make** değil, direkt:
   - **VMProtect SDK** ile derleme sırasında koruma uygulanır.
   - Alternatif olarak build sonrası `.dll` dosyasını VMProtect GUI'e sürükleyip
     marker'ları otomatik tanıması için **Project → Add function** adımı yapılabilir.

#### vcxproj içinde örnek (`vmprotect.h` + SDK):

```xml
<PropertyGroup>
  <IncludePath>$(ProjectDir)third_party\vmprotect\;$(IncludePath)</IncludePath>
</PropertyGroup>
<!-- AdditionalDependencies'e ekle: -->
<AdditionalDependencies>VMProtectSDK64.lib;%(AdditionalDependencies)</AdditionalDependencies>
```

> Projede `vmprotect.h` zaten SDK'sız no-op marker'lar sağlar; yani SDK olmadan
> da proje derlenip çalışır. VMProtect SDK'sı eklendiğinde aynı kod gerçek
> korumaya döner.

---

## 4) Anti-tamper katmanı

DLL, kendi disk dosyasının SHA-256'sını **lisans başarıyla doğrulanınca**
hafızaya kaydeder ve her `ma_get_session_token` çağrısında tekrar okur.
Uyuşmazlık → oturum belirteci "poisoned" olur → C# tarafı `IsLicensed=false`
yapar ve kritik fonksiyonları sessizce devre dışı bırakır.

Bu, binary'nin disk üzerinde `ma_verify`'ı patlatmak için patchlenmesine karşı
ilk katmandır. VMProtect ile birlikte "patch-dirsiz DLL" olur.

---

## 5) Test ederken unutma

- `LicenseCore.dll`'yi `exe` yanına koy, WPF startup'ında `Login` penceresi
  `LicenseManager.LoginAsync(...)` çağırır.
- DLL'i değiştir (bir byte patchle) → uygulama 5 dk içinde sessizce kapanmalı.
- DLL'i sil → `ProbeDll` yakalar → `LicenseDeactivated` ateşlenir.
- 32-bit exe ile 64-bit DLL çakışmasına dikkat (`BadImageFormatException`).