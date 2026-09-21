// ---------------------------------------------------------------------------
//  sha256.cpp - SHA-256 (FIPS 180-4) implementasyonu.
//  Tamamen bagimsiz; govde FIPS standart tablo ve donusumlerini kullanir.
//  Byte-order duzenlemeleri acik/secik yapildigi icin platformdan bagimsizdir.
// ---------------------------------------------------------------------------
#include "sha256.h"
#include <cstring>

namespace license
{
    // -----------------------------------------------------------------------
    // Sabitler
    // -----------------------------------------------------------------------
    static constexpr std::uint32_t K[64] = {
        0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
        0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
        0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
        0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
        0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
        0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
        0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
        0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
        0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
        0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
        0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
        0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
        0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
        0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
        0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
        0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
    };

    // -----------------------------------------------------------------------
    // Yardimci makrolar
    // -----------------------------------------------------------------------
    static inline std::uint32_t rotr(std::uint32_t v, unsigned int n)
    {
        return (v >> n) | (v << (32u - n));
    }

    static inline std::uint32_t Ch(std::uint32_t x, std::uint32_t y, std::uint32_t z)
    {
        return (x & y) ^ (~x & z);
    }

    static inline std::uint32_t Maj(std::uint32_t x, std::uint32_t y, std::uint32_t z)
    {
        return (x & y) ^ (x & z) ^ (y & z);
    }

    static inline std::uint32_t Sigma0(std::uint32_t x)
    {
        return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
    }

    static inline std::uint32_t Sigma1(std::uint32_t x)
    {
        return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
    }

    static inline std::uint32_t sigma0(std::uint32_t x)
    {
        return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
    }

    static inline std::uint32_t sigma1(std::uint32_t x)
    {
        return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);
    }

    // -----------------------------------------------------------------------
    // Genisletme / zorlama (message schedule) hesaplamasi
    // -----------------------------------------------------------------------
    static inline void compress(std::uint32_t state[8], const std::uint8_t block[64])
    {
        std::uint32_t w[64];

        // 16x 4-byte buyuk-endian kelimeleri olustur.
        for (int i = 0; i < 16; ++i)
        {
            w[i] = ((std::uint32_t)block[i * 4] << 24)
                 | ((std::uint32_t)block[i * 4 + 1] << 16)
                 | ((std::uint32_t)block[i * 4 + 2] << 8)
                 | ((std::uint32_t)block[i * 4 + 3]);
        }

        // 16..63 arasi kelimeleri genislet.
        for (int i = 16; i < 64; ++i)
        {
            w[i] = sigma1(w[i - 2]) + w[i - 7] + sigma0(w[i - 15]) + w[i - 16];
        }

        // Calisma degiskenleri.
        std::uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
        std::uint32_t e = state[4], f = state[5], g = state[6], h = state[7];

        // 64 tur.
        for (int i = 0; i < 64; ++i)
        {
            const std::uint32_t t1 = h + Sigma1(e) + Ch(e, f, g) + K[i] + w[i];
            const std::uint32_t t2 = Sigma0(a) + Maj(a, b, c);
            h = g; g = f; f = e; e = d + t1;
            d = c; c = b; b = a; a = t1 + t2;
        }

        // Durumu guncelle.
        state[0] += a; state[1] += b; state[2] += c; state[3] += d;
        state[4] += e; state[5] += f; state[6] += g; state[7] += h;
    }

    // -----------------------------------------------------------------------
    // Kamu API'lari
    // -----------------------------------------------------------------------
    void Sha256(const void* data, std::size_t len, std::uint8_t out[32])
    {
        std::uint32_t state[8] = {
            0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
            0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u
        };

        std::uint64_t bitLen = (std::uint64_t)len * 8u;
        const std::uint8_t* src = (const std::uint8_t*)data;

        // Tam bloklari isle.
        std::size_t remain = len;
        while (remain >= 64)
        {
            compress(state, src);
            src += 64;
            remain -= 64;
        }

        // Son blok + padding olustur.
        std::uint8_t tail[128];
        std::size_t tailLen = 0;
        if (remain > 0)
        {
            std::memcpy(tail, src, remain);
            tailLen = remain;
        }

        tail[tailLen++] = 0x80u; // 0b10000000
        // 8 byte uzunluk alanina yer ac: 56 byte kurali.
        while (tailLen % 64 != 56)
        {
            tail[tailLen++] = 0x00;
        }
        // Uzunluk buyuk-endian olarak son 8 byte'a yazilir.
        for (int i = 0; i < 8; ++i)
        {
            tail[tailLen++] = (std::uint8_t)(bitLen >> (56 - i * 8));
        }

        // Padding'li son blok(lari) isle.
        compress(state, tail);                 // ilk blok
        if (tailLen > 64)
        {
            compress(state, tail + 64);        // ikinci blok (uzunluk alanina takildiysa)
        }

        // Ciktiyi buyuk-endian yazarak buffer'a kopyala.
        for (int i = 0; i < 8; ++i)
        {
            out[i * 4]     = (std::uint8_t)(state[i] >> 24);
            out[i * 4 + 1] = (std::uint8_t)(state[i] >> 16);
            out[i * 4 + 2] = (std::uint8_t)(state[i] >> 8);
            out[i * 4 + 3] = (std::uint8_t)(state[i]);
        }
    }

    std::string Sha256Hex(const void* data, std::size_t len)
    {
        std::uint8_t digest[32];
        Sha256(data, len, digest);

        static const char* hexDigits = "0123456789abcdef";
        std::string result;
        result.reserve(64);
        for (int i = 0; i < 32; ++i)
        {
            result.push_back(hexDigits[digest[i] >> 4]);
            result.push_back(hexDigits[digest[i] & 0x0F]);
        }
        return result;
    }

    std::string Sha256Hex(const std::string& data)
    {
        return Sha256Hex(data.data(), data.size());
    }
}