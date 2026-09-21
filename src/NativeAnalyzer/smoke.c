#include <windows.h>
#include <stdio.h>
#include "native_analyzer.h"
int wmain(int argc, wchar_t** argv) {
    const wchar_t* path = argc > 1 ? argv[1] : L"C:\\Windows\\System32\\kernel32.dll";
    AnalysisResult* r = AnalyzePE(path);
    if (!r) { printf("NULL result\n"); return 1; }
    if (r->errorMessage[0]) { printf("Error: %s\n", r->errorMessage); free(r); return 1; }
    printf("Machine: 0x%X is64=%d sections=%d imageBase=0x%llX ent=%.3f packer=[%s]\n",
        r->pe.machine, r->pe.is64Bit, r->sectionCount, r->imageBase64, r->overallEntropy, r->detectedPacker);
    printf("entry=0x%lX strings=%d imports=%d dangerousImports=%d suspiciousStrings=%d\n",
        r->pe.entryPoint, r->strings.count, r->importCount, r->dangerousImportCount, r->suspiciousStringCount);
    printf("dllChars=0x%lX checksum=0x%lX subVer=%u.%u rich=%d comp=[%s]\n",
        r->dllCharacteristics, r->checksum, r->subsystemVersion >> 16, r->subsystemVersion & 0xFFFF,
        r->hasRichHeader, r->compilerFingerprint);
    printf("tls=%d tlsCallbacks=%d exports=%d cert=%d certSize=%lu overlay=%lu overlayEnt=%.3f\n",
        r->hasTlsCallbacks, r->tlsCallbackCount, r->exportCount, r->hasCertificate, r->certificateSize,
        r->overlaySize, r->overlayEntropy);
    printf("entrySection=[%s] dataDirMask=0x%X suspiciousFlags=0x%X\n",
        r->entrySection, r->dataDirectoryMask, r->suspiciousFlags);
    for (int i = 0; i < r->sectionCount; i++)
        printf("  sec[%d] %-8s VA=0x%lX VS=0x%lX raw=0x%lX ent=%.3f susp=%d\n",
            i, r->sections[i].name, r->sections[i].virtualAddress, r->sections[i].virtualSize,
            r->sections[i].sizeOfRawData, r->sections[i].entropy, r->sections[i].suspicious);
    for (int i = 0; i < r->importCount && i < 3; i++)
        printf(" imp: %s\n", r->imports[i].name);
    for (int i = 0; i < (int)r->exportCount && i < 3; i++)
        printf(" exp: %s\n", r->exports[i].name);
    free(r);
    return 0;
}