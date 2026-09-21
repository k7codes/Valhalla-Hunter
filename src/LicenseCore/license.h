// ---------------------------------------------------------------------------
//  license.h - LicenseCore.dll'in genel arayuzu (C-ABI export bildirimleri).
//
//  DllExport / DllImport duzeni:
//    * C# tarafi bu imzayi birebir [DllImport] eder.
//    * Sadece temiz "extern C" tipler kullanilir (char*).
// ---------------------------------------------------------------------------
#pragma once

#ifdef LICENSECORE_EXPORTS
#  define LICENSECORE_API extern "C" __declspec(dllexport)
#else
#  define LICENSECORE_API extern "C" __declspec(dllimport)
#endif

// ---------------------------------------------------------------------------
// ma_verify - Sunucuya kimlik bilgilerini dogrular.
//
// Kullanici girisi:
//   user          : "ahmet_yazilim"   (UTF-8)
//   passHashHex   : "8c69..."         (SHA-256 hex, 64 karakter) - DLL bu degeri
//                                      oldugu gibi kullanir; hash'leme C# tarafinda yapilmistir.
//   key           : "MH26-EFZ2-DC8F-ZKJ3"
//   out_buf       : Cevabin yazilacagi buffer (JSON: status/expires/plan)
//   buf_len       : out_buf kapasitesi (en az 512 onerilir)
//
// Donus: 1 = lisans aktif, 0 = reddedildi / hata. Cevap JSON'u out_buf'ta.
// ---------------------------------------------------------------------------
LICENSECORE_API int ma_verify(const char* user,
                              const char* passHashHex,
                              const char* key,
                              char* out_buf,
                              int buf_len);

// ---------------------------------------------------------------------------
// ma_client_hwid - Donanim kimligini (HWID) hex olarak uretir ve dondurur.
//
// Bu, C# tarafinin API istegine "hardware_id" alani koyabilmesi icindir.
// HWID yalnizca native tarafta uretilir; C#'a yalnizca okunmis deger verilir.
//
// Donus: HWID uzunlugu (64) ya da 0 (hata).
// ---------------------------------------------------------------------------
LICENSECORE_API int ma_client_hwid(char* out_buf, int buf_len);

// ---------------------------------------------------------------------------
// ma_activate_session - Agsiz oturum kurulumu (C# HTTP dogrulamasindan sonra).
//
// C# tarafi API'ye HttpClient ile POST atar ve "success":true gordugunde bu
// fonksiyonu cagirir.  HWID zaten C# tarafindan ma_client_hwid ile alinmis
// olur; burada tekrar disk sorgusu YAPILMAZ (ikinci kez IOCTL bazli sistemlerde
// asilabiliyordu).  DLL anti-tamper self-hash'ini kaydeder ve oturum belirtecini
// uretir (token, C#'in dogrulayip gonderdigi hwid uzerinden uretilir).
//
// Donus: 1 = oturum kuruldu, 0 = hata.
// ---------------------------------------------------------------------------
LICENSECORE_API int ma_activate_session(const char* user, const char* key, const char* hwid);

// ---------------------------------------------------------------------------
// ma_get_session_token - Aktif oturum belirtecini alir.
//
// Basarili ma_verify sonrasi DLL icinde uretilen 32 byte rastgele belirtecin
// hex'ini (64 char + NUL) dondurur.  Bu belirtec C# tarafindan "kritik
// fonksiyonlari kilitleyen" anahtar olarak kullanilir:
//   * alinamazsa ya da igrasilirsa -> C# tarafi sessizce islevsiz hale gelir.
//   * DLL silinmis / degistirilmis / suslenmis CAĞRIYA SUSAR ve yanlis belirtec verir.
//
// Donus: belirtecin uzunlugu (64) ya da 0 (lisans yok / tampered).
// ---------------------------------------------------------------------------
LICENSECORE_API int ma_get_session_token(char* out_buf, int buf_len);

// ---------------------------------------------------------------------------
// ma_cleanup - Tum oturum durumunu ve belirteci temizler.
// ---------------------------------------------------------------------------
LICENSECORE_API void ma_cleanup(void);