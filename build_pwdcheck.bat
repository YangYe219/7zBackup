@echo off
rem ============================================================
rem  Rebuild 7zPwdCheck.exe with the C# compiler built into Windows
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
  /out:"%~dp07zPwdCheck.exe" ^
  /r:System.dll /r:System.Core.dll /r:System.Drawing.dll /r:System.Windows.Forms.dll ^
  "%~dp07zPwdCheck.cs"

if errorlevel 1 (
  echo.
  echo BUILD FAILED.
  pause
  exit /b 1
)
echo.
echo BUILD OK: %~dp07zPwdCheck.exe
echo.
pause
