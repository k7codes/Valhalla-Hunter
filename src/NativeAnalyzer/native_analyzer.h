#pragma once
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

#ifdef NATIVEANALYZER_EXPORTS
#define NATIVE_API __declspec(dllexport)
#else
#define NATIVE_API __declspec(dllimport)
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_STRINGS 500
#define MAX_SECTIONS 16
#define MAX_STR_LEN 128
#define MAX_API_STR 256
#define MAX_IMPORTS 200
#define MAX_EXPORTS 256
#define MAX_DATA_DIRS 16

typedef struct {
    char name[9];
    unsigned long virtualSize;
    unsigned long virtualAddress;
    unsigned long sizeOfRawData;
    unsigned long pointerToRawData;
    unsigned long characteristics;
    double entropy;
    int suspicious;
} SectionInfo;

typedef struct {
    char name[MAX_API_STR];
} ImportEntry;

typedef struct {
    char string_data[MAX_STRINGS][MAX_STR_LEN];
    int count;
} StringTable;

typedef struct {
    unsigned short machine;
    unsigned long entryPoint;
    unsigned long baseOfCode;
    unsigned long baseOfData;
    unsigned long imageBase;
    unsigned long sectionCount;
    unsigned long sizeOfImage;
    unsigned long sizeOfHeaders;
    unsigned long characteristics;
    unsigned long subsystem;
    unsigned long numberOfSymbols;
    unsigned long timeDateStamp;
    unsigned long sizeOfOptionalHeader;
    int isDll;
    int is64Bit;
} Pemetadata;

typedef struct {
    Pemetadata pe;
    SectionInfo sections[MAX_SECTIONS];
    int sectionCount;
    StringTable strings;
    int importCount;
    ImportEntry imports[MAX_IMPORTS];
    int suspiciousFlags;
    double overallEntropy;
    char detectedPacker[64];
    char errorMessage[256];

    // Deep analysis (v2.0)
    unsigned long long imageBase64;
    unsigned long dllCharacteristics;
    unsigned long checksum;
    unsigned long subsystemVersion;   // (major << 16) | minor
    unsigned long overlaySize;
    double overlayEntropy;
    int hasRichHeader;
    char compilerFingerprint[64];
    int hasTlsCallbacks;
    int tlsCallbackCount;
    unsigned long exportCount;
    ImportEntry exports[MAX_EXPORTS];
    int hasCertificate;
    unsigned long certificateSize;
    int dangerousImportCount;
    int suspiciousStringCount;
    char entrySection[9];
    int dataDirectoryMask;
} AnalysisResult;

NATIVE_API AnalysisResult* AnalyzePE(const wchar_t* filePath);
NATIVE_API void FreeResult(AnalysisResult* result);
NATIVE_API const wchar_t* GetAnalyzerVersion();

#ifdef __cplusplus
}
#endif