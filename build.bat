@echo off
rem ============================================================
rem  Rebuild 7zBackup.exe with the C# compiler built into Windows
rem  (No SDK / Visual Studio needed)
rem ============================================================
setlocal
set "CSC=%SystemRoot%\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
if not exist "%CSC%" set "CSC=%SystemRoot%\Microsoft.NET\Framework\v4.0.30319\csc.exe"
if not exist "%CSC%" (
  echo BUILD FAILED: csc.exe not found on this system.
  pause
  exit /b 1
)

"%CSC%" /nologo /target:winexe /codepage:65001 /optimize+ ^
  /out:"%~dp07zBackup.exe" ^
  /r:System.dll /r:System.Core.dll /r:System.Drawing.dll /r:System.Windows.Forms.dll ^
  "%~dp07zBackup.cs"

if errorlevel 1 (
  echo.
  echo BUILD FAILED.
  pause
  exit /b 1
)
echo.
echo BUILD OK: %~dp07zBackup.exe
echo.
pause
