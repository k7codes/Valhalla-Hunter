@echo off
REM ===========================================================================
REM  build_vs.bat - LicenseCore.dll'yi VS2022 x64 Release olarak derler.
REM  Kullanim:  build_vs.bat   (veya komut satirinda direkt calistir)
REM  Cikti:     bin\x64\Release\LicenseCore.dll
REM ===========================================================================
setlocal

set VSWHERE="%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist %VSWHERE% (
    echo [HATA] vswhere bulunamadi. VS2022 kurulu olmali.
    exit /b 1
)

for /f "usebackq tokens=*" %%i in (`%VSWHERE% -latest -products * -requires Microsoft.Component.MSBuild -property installationPath`) do set VSPATH=%%i

if not defined VSPATH (
    echo [HATA] VS2022 bulunamadi.
    exit /b 1
)

call "%VSPATH%\MSBuild\Current\Bin\MSBuild.exe" LicenseCore.vcxproj /p:Configuration=Release /p:Platform=x64 /m

if exist "bin\x64\Release\LicenseCore.dll" (
    echo.
    echo [OK] LicenseCore.dll hazir: bin\x64\Release\LicenseCore.dll
) else (
    echo.
    echo [HATA] Derleme basarisiz.
    exit /b 1
)

endlocal