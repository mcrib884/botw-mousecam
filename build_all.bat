@echo off
setlocal ENABLEDELAYEDEXPANSION

REM Change to the directory of this script
pushd "%~dp0"

echo =====================================================
echo   BOTW MouseCam - Build All (DLL + Injector + Finder)
echo =====================================================

REM Check required tools
where cargo >nul 2>nul
if errorlevel 1 (
  echo [ERROR] Rust cargo not found. Install Rust MSVC toolchain from https://rustup.rs/
  goto :fail
)

where dotnet >nul 2>nul
if errorlevel 1 (
  echo [ERROR] .NET SDK not found. Install .NET 6+ SDK from https://dotnet.microsoft.com/download
  goto :fail
)

REM 1) Build Rust workspace (DLL + injector)
echo.
echo [1/3] Building Rust workspace (Release)...
cargo build --release
if errorlevel 1 (
  echo [ERROR] cargo build failed.
  goto :fail
)

REM 2) Publish position_finder as self-contained, single-file
echo.
echo [2/3] Publishing position_finder (self-contained single-file)...
dotnet publish "position_finder\position_finder.csproj" ^
  -c Release -r win-x64 --self-contained true ^
  -p:PublishSingleFile=true ^
  -p:PublishTrimmed=true ^
  -p:EnableCompressionInSingleFile=true ^
  -p:DebugType=none ^
  -p:IncludeNativeLibrariesForSelfExtract=true ^
  -p:IncludeAllContentForSelfExtract=true ^
  -o "position_finder\publish"
if errorlevel 1 (
  echo [ERROR] dotnet publish failed.
  goto :fail
)

REM 3) Copy artifacts to root release\ folder
echo.
echo [3/3] Copying artifacts to release\ ...
if not exist "release" mkdir "release"

copy /Y "target\release\botw_mousecam.dll" "release\botw_mousecam.dll" >nul
if errorlevel 1 (
  echo [ERROR] Missing target\release\botw_mousecam.dll
  goto :fail
)

copy /Y "target\release\injector.exe" "release\injector.exe" >nul
if errorlevel 1 (
  echo [ERROR] Missing target\release\injector.exe
  goto :fail
)

copy /Y "position_finder\publish\position_finder.exe" "release\position_finder.exe" >nul
if errorlevel 1 (
  echo [ERROR] Missing position_finder\publish\position_finder.exe
  goto :fail
)

echo.
echo [SUCCESS] Build complete. Artifacts available in release\
echo   - release\botw_mousecam.dll
echo   - release\injector.exe
echo   - release\position_finder.exe

popd
exit /b 0

:fail
echo.
echo Build failed. See messages above.
popd
exit /b 1

