#pragma once
// ---------------------------------------------------------------------------
//  sha256.h - Bagimsiz (self-contained) SHA-256 implementasyonu.
//  Herhangi bir harici kutuphaneye (OpenSSL, Libsodium vb.) ihtiyac yoktur;
//  yalnizca Windows'ta dogrudan derlenebilir. C ve C++ projelerinde kullanilabilir.
// ---------------------------------------------------------------------------
#include <cstdint>
#include <cstddef>
#include <string>

namespace license
{
    // Tek parca verinin SHA-256 ozetini hesaplar ve out[32] bufferina yazar.
    void Sha256(const void* data, std::size_t len, std::uint8_t out[32]);

    // Verinin SHA-256 ozetini kucuk harfli hex string olarak dondurur.
    std::string Sha256Hex(const void* data, std::size_t len);

    // std::string kolayligi icin overload.
    std::string Sha256Hex(const std::string& data);
}