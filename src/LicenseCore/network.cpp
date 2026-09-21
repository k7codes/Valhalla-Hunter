// ---------------------------------------------------------------------------
//  network.cpp - WinHTTP ile minimal, harici bagimliliksiz HTTP(S) POST.
//
//  Yaklasim:
//    * winhttp.dll calisma zamaninda bulunur (Windows Vista+ daima mevcut).
//    * Kucuk bir URL ayristirici, host:port/path cikarir.
//    * Istege "Content-Type: application/json" ekler, govdeyi WinHttpSendRequest
//      ile gonderir, cevabi tamamen okuyup dondurur.
// ---------------------------------------------------------------------------
#include "network.h"
#include <windows.h>
#include <winhttp.h>
#include <cctype>

#pragma comment(lib, "winhttp.lib")

namespace license
{
    // -----------------------------------------------------------------------
    // URL'yi (https?://host[:port]/path) bileenlerine ayirir.
    // -----------------------------------------------------------------------
    struct UrlParts
    {
        bool   secure = false;
        std::string host;
        INTERNET_PORT port = 80;
        std::string path = "/";
    };

    static bool SplitUrl(const std::string& url, UrlParts& out)
    {
        std::string u = url;
        out.secure = false;

        // "https://" veya "http://"
        if (u.compare(0, 8, "https://") == 0)
        {
            out.secure = true;
            u = u.substr(8);
        }
        else if (u.compare(0, 7, "http://") == 0)
        {
            u = u.substr(7);
        }
        else
        {
            return false;
        }

        // Path kismini ayir.
        std::string authority;
        std::string::size_type slash = u.find('/');
        if (slash != std::string::npos)
        {
            authority = u.substr(0, slash);
            out.path = u.substr(slash);
        }
        else
        {
            authority = u;
            out.path = "/";
        }

        // Port kismini ayir.
        std::string::size_type colon = authority.find(':');
        if (colon != std::string::npos)
        {
            out.host = authority.substr(0, colon);
            std::string portStr = authority.substr(colon + 1);
            try
            {
                int port = std::stoi(portStr);
                if (port < 1 || port > 65535)
                {
                    return false;
                }
                out.port = (INTERNET_PORT)port;
            }
            catch (...)
            {
                return false;
            }
        }
        else
        {
            out.host = authority;
            out.port = out.secure ? 443 : 80;
        }

        return !out.host.empty();
    }

    // -----------------------------------------------------------------------
    // WinHTTP istegi; istemci sutunu baglamadan once ayarlar, sonunda temizler.
    // -----------------------------------------------------------------------
    bool HttpPostJson(const std::string& url,
                      const std::string& jsonBody,
                      std::string& outResp,
                      unsigned long timeoutMs)
    {
        if (url.empty() || jsonBody.empty())
        {
            return false;
        }

        UrlParts parts;
        if (!SplitUrl(url, parts))
        {
            return false;
        }

        std::wstring wHost(parts.host.begin(), parts.host.end());
        std::wstring wPath(parts.path.begin(), parts.path.end());

        bool ok = false;
        outResp.clear();

        HINTERNET hSession = ::WinHttpOpen(
            L"MalwareHunter/1.0 (LicenseClient)",
            WINHTTP_ACCESS_TYPE_NO_PROXY,
            WINHTTP_NO_PROXY_NAME,
            WINHTTP_NO_PROXY_BYPASS,
            0);

        if (!hSession)
        {
            return false;
        }

        // Govde boyutu icin ham iletisim gereken toplam byte sayisini bul.
        DWORD bodyLen = (DWORD)jsonBody.size();
        std::wstring wHeaders = L"Content-Type: application/json\r\nAccept: application/json";

        HINTERNET hConnect = ::WinHttpConnect(hSession, wHost.c_str(), parts.port, 0);
        if (hConnect)
        {
            HINTERNET hRequest = ::WinHttpOpenRequest(
                hConnect,
                L"POST",
                wPath.c_str(),
                nullptr,
                WINHTTP_NO_REFERER,
                WINHTTP_DEFAULT_ACCEPT_TYPES,
                parts.secure ? WINHTTP_FLAG_SECURE : 0);

            if (hRequest)
            {
                // Zamansinirini her etapa uygula.
                ::WinHttpSetTimeouts(hRequest, timeoutMs, timeoutMs, timeoutMs, timeoutMs);
                DWORD redirectAlways = WINHTTP_OPTION_REDIRECT_POLICY_ALWAYS;
                ::WinHttpSetOption(hRequest, WINHTTP_OPTION_REDIRECT_POLICY,
                                   &redirectAlways,
                                   sizeof(redirectAlways));

                BOOL sent = ::WinHttpSendRequest(
                    hRequest,
                    wHeaders.c_str(),
                    (DWORD)wHeaders.size(),
                    (LPVOID)jsonBody.data(),
                    bodyLen,
                    bodyLen,
                    0);

                if (sent && ::WinHttpReceiveResponse(hRequest, nullptr))
                {
                    // Durum kodunu kontrol et.
                    DWORD status = 0;
                    DWORD statusSize = sizeof(status);
                    ::WinHttpQueryHeaders(hRequest,
                                          WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                                          WINHTTP_HEADER_NAME_BY_INDEX,
                                          &status,
                                          &statusSize,
                                          WINHTTP_NO_HEADER_INDEX);

                    if (status == 200)
                    {
                        // Cevabi parca parca oku.
                        BYTE buffer[4096];
                        DWORD bytesRead = 0;
                        while (::WinHttpReadData(hRequest, buffer, sizeof(buffer), &bytesRead) && bytesRead > 0)
                        {
                            outResp.append(reinterpret_cast<char*>(buffer), bytesRead);
                            bytesRead = 0;
                        }
                        ok = true;
                    }
                }

                ::WinHttpCloseHandle(hRequest);
            }
            ::WinHttpCloseHandle(hConnect);
        }
        ::WinHttpCloseHandle(hSession);

        return ok;
    }
}