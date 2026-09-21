// ---------------------------------------------------------------------------
//  hwid.cpp - HWID (Donanim Kimligi) Motoru.
//
//  Kaynak veriler EVCIL Windows API ile toplanir (C# degil!):
//    1) Anakart UUID   -> GetSystemFirmwareTable(SMBIOS) ile SMBIOS Tip 1 tablosu.
//    2) Disk seri No   -> CreateFile("\\\\.\\PhysicalDrive0") +
//                         IOCTL_STORAGE_QUERY_PROPERTY + StorageDeviceProperty.
//
//  Bu iki deger birlestirilip SHA-256 ile hash'lenir; boylece yalnizca hizli
//  degis(tiril)mez donanim (anakart + fiziksel disk) kimlik belirler.
// ---------------------------------------------------------------------------
#include "hwid.h"
#include "sha256.h"

#include <windows.h>
#include <winioctl.h>
#include <ntddstor.h>
#include <vector>
#include <iomanip>
#include <sstream>
#include <cstring>

namespace license
{
    // -----------------------------------------------------------------------
    // SMBIOS Tip 1 (System Information) tablosundan UUID okur.
    // DDT/GetSystemFirmwareTable 'RSMB' ham SMBIOS tablolarini verir.
    // -----------------------------------------------------------------------
    std::string GetMotherboardUuid()
    {
        UINT byteLen = ::GetSystemFirmwareTable('RSMB', 0, nullptr, 0);
        if (byteLen == 0)
        {
            return std::string(); // SMBIOS yok veya erisim yok
        }

        std::vector<BYTE> buffer(byteLen);
        UINT realLen = ::GetSystemFirmwareTable('RSMB', 0, buffer.data(), byteLen);
        if (realLen == 0)
        {
            return std::string();
        }

        // Raw SMBIOS: baslangicta 8 byte header (Used20CallingMethod, SMBIOSMajor,
        // SMBIOSMinor, ... ve 4 byte table area). Tablolar ardindan baslar.
        const BYTE* raw = buffer.data();
        if (byteLen < 8)
        {
            return std::string();
        }

        const BYTE* p = raw + 8;
        const BYTE* end = raw + realLen;

        while (p + 4 <= end)
        {
            BYTE type = p[0];
            BYTE length = p[1];

            // Tip 1 = System Information; UUID, alanlarin 8. ofsetindedir.
            if (type == 1 && length >= 8 + 16)
            {
                const BYTE* uuid = p + 8;

                // UUID onbellegi: dword + 2 word + 8 byte.
                // Little-endian karistirilmasi YARA/BIOS formatinda genellikle
                // onemsizdir; amac benzersiz birsayidir, dogrulama carpasi degil.
                std::ostringstream oss;
                oss << std::hex << std::uppercase << std::setfill('0');
                for (int i = 0; i < 16; ++i)
                {
                    oss << std::setw(2) << (int)uuid[i];
                    if (i == 3 || i == 5 || i == 7 || i == 9)
                    {
                        oss << '-';
                    }
                }
                return oss.str();
            }

            // String listesini atla (cift NUL ile biter).
            p += length;
            while (p < end)
            {
                if (*p == 0 && (p + 1 < end) && *(p + 1) == 0)
                {
                    p += 2;
                    break;
                }
                if (*p == 0)
                {
                    ++p;
                    continue;
                }
                ++p;
            }
        }

        return std::string();
    }

    // -----------------------------------------------------------------------
    // Ilk fiziksel diskin seri numarasini okur.
    // IOCTL_STORAGE_QUERY_PROPERTY -> StorageDeviceProperty -> SerialNumberOffset.
    // -----------------------------------------------------------------------
    std::string GetDiskSerialNumber()
    {
        // Sadece kagit uzerindeki ilk fiziksel disk. (Bazi makinelerde
        // StorageDeviceProperty bu yolla calismaz; o zaman volume serial fallback yapilir.)
        HANDLE hDisk = ::CreateFileW(
            L"\\\\.\\PhysicalDrive0",
            0,                                   // okuma/yonetim girisine ihtiyac yok
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr,
            OPEN_EXISTING,
            0,
            nullptr);

        if (hDisk == INVALID_HANDLE_VALUE)
        {
            return std::string();
        }

        STORAGE_PROPERTY_QUERY query = {};
        query.PropertyId = StorageDeviceProperty;
        query.QueryType = PropertyStandardQuery;

        BYTE outBuf[512] = {};
        DWORD returned = 0;

        BOOL ok = ::DeviceIoControl(
            hDisk,
            IOCTL_STORAGE_QUERY_PROPERTY,
            &query,
            sizeof(query),
            outBuf,
            sizeof(outBuf),
            &returned,
            nullptr);

        ::CloseHandle(hDisk);

        if (!ok || returned < sizeof(STORAGE_DEVICE_DESCRIPTOR))
        {
            // Fallback: C:\ volume seri numarasi (kernel tarafindan dogrulanmis).
            DWORD volumeSerial = 0;
            DWORD maxCompLen = 0;
            DWORD fsFlags = 0;
            WCHAR fsName[64] = {};
            if (::GetVolumeInformationW(
                L"C:\\", nullptr, 0,
                &volumeSerial, &maxCompLen, &fsFlags,
                fsName, 64))
            {
                std::ostringstream oss;
                oss << std::uppercase << std::hex << volumeSerial;
                return oss.str();
            }
            return std::string();
        }

        STORAGE_DEVICE_DESCRIPTOR* desc = reinterpret_cast<STORAGE_DEVICE_DESCRIPTOR*>(outBuf);
        if (desc->SerialNumberOffset && desc->SerialNumberOffset < sizeof(outBuf))
        {
            char* serialPtr = reinterpret_cast<char*>(outBuf + desc->SerialNumberOffset);
            return std::string(serialPtr);
        }

        return std::string();
    }

    // -----------------------------------------------------------------------
    // Birlesik HWID uretimi.
    // Ust bilgi: "AnakartUUID|DiskSeri" -> SHA-256 hex.
    // -----------------------------------------------------------------------
    bool ComputeHardwareId(char* cikti, size_t cap)
    {
        std::string mbUuid = GetMotherboardUuid();
        std::string diskSerial = GetDiskSerialNumber();

        // Ikisi de bos olursa gercek bir donanim kimligi uretilemez.
        if (mbUuid.empty() && diskSerial.empty())
        {
            return false;
        }

        std::string raw = "[MB]" + mbUuid + "[DISK]" + diskSerial;
        std::string hwid = license::Sha256Hex(raw);

        if (cap < hwid.size() + 1)
        {
            return false;
        }

        std::memcpy(cikti, hwid.data(), hwid.size());
        cikti[hwid.size()] = '\0';
        return true;
    }
}