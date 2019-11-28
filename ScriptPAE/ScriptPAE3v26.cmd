@ECHO OFF

rem ver. 0.0.2.6
rem place with PatchPAE3.exe
rem simple automation script by (L) evgen_b for PatchPAE3.exe
rem this script is provided on an "as is" basis

REM set DEBUGLOG=1 to print executed commands:
SET DEBUGLOG=0

IF *%DEBUGLOG%==*1 ECHO ON
COLOR 0a

IF *%PROCESSOR_ARCHITEW6432%==*AMD64 GOTO wow64
IF *%PROCESSOR_ARCHITECTURE%==*AMD64 (GOTO x64) ELSE GOTO x86
GOTO :EOF

REM PROCESSOR_ARCHITEW6432 means 7z-sfx or rar-sfx, etc 32-bit sfx with 64-bit OS...

:wow64
"%systemroot%\Sysnative\cmd.exe" /C " "%~0" %* "
GOTO :EOF

:x86
SET "osarc=32"
GOTO :cont1

:x64
SET "osarc=64"
GOTO :cont1

:cont1
SET isadmin=0
FSUtil.exe dirty query %systemdrive%>NUL && SET isadmin=1
REM SKIP IF ALREADY ELEVATED:
IF *%isadmin%==*1 GOTO cont2
REM SKIP IF RUN FROM VBSCRIPT-FOR-ELEVATE:
IF "%1"=="NOUAC" GOTO cont2

SET "vbadmin=%temp%\getadmin%RANDOM%.vbs"
ECHO.'%*>"%vbadmin%"
ECHO.allargs=CreateObject^("Scripting.FileSystemObject"^).OpenTextFile^(WScript.ScriptFullName^).ReadLine>>"%vbadmin%"
ECHO.CreateObject^("Scripting.FileSystemObject"^).DeleteFile^(WScript.ScriptFullName^)>>"%vbadmin%"
ECHO.CreateObject^("Shell.Application"^).ShellExecute "%ComSpec%", "/C ""  ""%~f0"" NOUAC " ^& Mid^(allargs, 2^) ^& " """, "", "runas", 1 : WScript.Sleep 3000>>"%vbadmin%"
IF *%DEBUGLOG%==*1 (CScript.exe //nologo "%vbadmin%") ELSE START "1" WScript.exe "%vbadmin%"
SET el=%errorlevel%
IF *%el%==*0 GOTO :EOF
COLOR 0C
ECHO.
ECHO.exitcode: %el%
ECHO. ERROR: Can't run Windwows Script Host to elevate rights.
ECHO. Press any key for exit...
PAUSE>NUL
GOTO :EOF

:cont2
REM MODE CON: cols=80 lines=25

FOR /f "usebackq tokens=1,* delims=[" %%i IN (`ver`) DO (SET winv=%%j)
FOR /f "tokens=2" %%i IN ("%winv%") DO (SET winv=%%i)
SET winv=%winv:~0,-1%
FOR /f "tokens=1-3 delims=." %%i IN ("%winv%") DO (SET osmajor=%%i && SET osminor=%%j && SET osbuild=%%k)
SET osmajor=%osmajor:~0,-1%
SET osminor=%osminor:~0,-1%

SET "mypath=%~p0"
SET "mydisk=%~d0"
CD /d "%mydisk%%mypath%"

ECHO.
ECHO. PAE Patch Script v2.6
ECHO. by evgen_b, based on Escape75 original script
ECHO. Use EasyBCD or MSCONFIG to manage boot menu.
ECHO.
ECHO. Running on Windows %osmajor%.%osminor% build %osbuild% %osarc%-bit
ECHO.

REM CHECK, IF ELEVATED FROM VBSCRIPT SUCCESSFUL:
IF *%isadmin%==*1 GOTO cont3
REM IF RUN FROM RESTRICTED USER AND UAC IS DISABLED, YOU NEVER GET ADMINISTRATOR RIGHTS
COLOR 0C
ECHO. ERROR: this script requires Administrator rights.
ECHO. Press any key for exit...
PAUSE>NUL
GOTO :EOF

:cont3
ECHO. Checking for Administrator rights: OK

IF *%osarc%==*32 GOTO cont4
COLOR 0C
ECHO. ERROR: 64-bit edition detected!
ECHO. Press any key for exit...
PAUSE>NUL
GOTO :EOF

:cont4
ECHO. Checking for 32-bit system: OK

bcdedit.exe /enum >nul 2>&1 && GOTO cont5
COLOR 0C
ECHO. ERROR: command BCDEDIT is missing!
ECHO. Press any key for exit...
PAUSE>NUL
GOTO :EOF

:cont5
ECHO. Checking for BCDEDIT command: OK

PatchPAE3.exe >nul 2>&1
SET el=%errorlevel%
IF *%el%==*2 GOTO cont6
IF *%el%==*9009 GOTO patchermissing

REM errorlevel 5:
COLOR 0C
ECHO. ERROR: utility "%mydisk%%mypath%PatchPAE3.exe" cannot run,
ECHO. may be VS2010 Redistributable not installed!
ECHO. Press any key for exit...
PAUSE>NUL
GOTO :EOF

:patchermissing
COLOR 0C
ECHO. ERROR: utility "%mydisk%%mypath%PatchPAE3.exe" is missing!
ECHO. Press any key for exit...
PAUSE>NUL
GOTO :EOF

:cont6
ECHO. Checking for PatchPAE3 utility: OK

SET "winver=0"
SET "checkSB=0"
IF *%osmajor%.%osminor%==*6.0  (SET winver=Vista) & (set kernel=ntkrnlpa.exe)
IF *%osmajor%.%osminor%==*6.1  (SET winver=7)     & (set kernel=ntkrnlpa.exe)
IF *%osmajor%.%osminor%==*6.2  (SET winver=8)     & (set kernel=ntoskrnl.exe) & (set checkSB=1)
IF *%osmajor%.%osminor%==*6.3  (SET winver=8.1)   & (set kernel=ntoskrnl.exe) & (set checkSB=1)
IF *%osmajor%.%osminor%==*10.0 (SET winver=10)    & (set kernel=ntoskrnl.exe) & (set checkSB=1)

IF NOT *%winver%==*0 GOTO cont7
COLOR 0C
ECHO. ERROR: unsupport version [%osmajor%.%osminor%]!
ECHO. Press any key for exit...
PAUSE>NUL
GOTO :EOF

:cont7
ECHO. Checking Windows version: OK

SET "enablesecboot=0"
IF *%checkSB%==*0 GOTO cont7_1
SET "secbootout=%temp%\secbootout%RANDOM%.log"
FOR /F "tokens=2 delims=:" %%a IN ('CHCP') DO SET codepage=%%a
CHCP 437 > NUL & PowerShell.exe -NoLogo -Command Confirm-SecureBootUEFI > "%secbootout%" 2>&1
CHCP %codepage%>NUL
TYPE "%secbootout%" | find.exe /i "True" && SET "enablesecboot=1" > NUL 2>&1
DEL /f /q "%secbootout%" > NUL
IF *%enablesecboot%==*0 GOTO cont7_2
COLOR 0C
ECHO. ERROR: You must disable SecureBoot in UEFI to run patched kernel!
ECHO. Press any key for exit...
PAUSE>NUL
GOTO :EOF
:cont7_1
ECHO. Skip checking UEFI SecureBoot...
GOTO cont7_3

:cont7_2
ECHO. Checking UEFI SecureBoot disable option: OK
:cont7_3
IF EXIST "%systemroot%\system32\%kernel%" GOTO cont8
COLOR 0C
ECHO. ERROR: cannot find the kernel file [%systemroot%\system32\%kernel%]!
ECHO. Press any key for exit...
PAUSE>NUL
GOTO :EOF

:cont8
ECHO. Checking original kernel: OK

SET current=0
FOR /F %%a IN ('bcdedit.exe /enum ^| find.exe /i "{current}"') DO SET current=1
IF *%current%==*1 GOTO cont9
COLOR 0C
ECHO. ERROR: cannot find current boot config!
ECHO. Please reboot and try again.
ECHO. Press any key for exit...
PAUSE>NUL
GOTO :EOF

:cont9
ECHO. Checking current boot config: OK

SET winload=0
FOR /F %%a IN ('bcdedit.exe /enum {current} ^| findstr.exe /b /r /c:"path.*%SystemRoot:~3%\\system32\\.*\.exe"') DO (SET winload=winload.exe) & (SET newload=winloadx.exe) 
FOR /F %%a IN ('bcdedit.exe /enum {current} ^| findstr.exe /b /r /c:"path.*%SystemRoot:~3%\\system32\\.*\.efi"') DO (SET winload=winload.efi) & (SET newload=winloadx.efi) 
IF NOT *%winload%==*0 GOTO cont10
COLOR 0C
ECHO. ERROR: cannot detect loader!
ECHO. Press any key for exit...
PAUSE>NUL
GOTO :EOF

:cont10
ECHO. Checking loader config: OK

IF EXIST "%systemroot%\system32\%winload%" GOTO cont11
COLOR 0C
ECHO. ERROR: cannot find the loader file [%systemroot%\system32\%winload%]!
ECHO. Press any key for exit...
PAUSE>NUL
GOTO :EOF

:cont11
ECHO. Checking original loader: OK

PatchPAE3.exe -type kernel -o "%systemroot%\system32\ntkrnlpx.exe" "%systemroot%\system32\%kernel%" >nul 2>&1
SET el=%errorlevel%
IF *%el%==*0 GOTO cont12
COLOR 0C
ECHO. ERROR: cannot patch the kernel file [%systemroot%\system32\%kernel%]!
ECHO. exitcode=%el%
ECHO. Press any key for exit...
PAUSE>NUL
GOTO :EOF

:cont12
ECHO. Patching kernel: OK

PatchPAE3.exe -type loader -o "%systemroot%\system32\%newload%" "%systemroot%\system32\%winload%" >nul 2>&1
SET el=%errorlevel%
IF *%el%==*0 GOTO cont13
COLOR 0C
ECHO. ERROR: cannot patch the loader file [%systemroot%\system32\%winload%]!
ECHO. exitcode=%el%
ECHO. Press any key for exit...
PAUSE>NUL
GOTO :EOF

:cont13
ECHO. Patching loader: OK

SET bcdpaepresent=0
FOR /F %%a IN ('bcdedit.exe /enum ^| findstr.exe /b /r "kernel.*ntkrnlpx\.exe"') DO SET bcdpaepresent=1
IF *%bcdpaepresent%==*0 GOTO cont14
ECHO. boot entry already present, skip...
GOTO cont_end

:cont14
FOR /F "tokens=2 delims={}" %%a IN ('bcdedit.exe /copy {current} /d "Windows %winver% with PAE"') DO SET newguid=%%a
IF NOT *%newguid%==* GOTO cont15
COLOR 0C
ECHO. ERROR: cannot add new boot entry!
ECHO. Press any key for exit...
PAUSE>NUL
GOTO :EOF

:cont15
ECHO. Adding new boot entry: OK

bcdedit.exe /set {%newguid%} kernel "ntkrnlpx.exe" >nul 2>&1
SET el=%errorlevel%
IF *%el%==*0 GOTO cont16
COLOR 0C
ECHO. ERROR: cannot set new kernel!
ECHO. exitcode=%el%
ECHO. Press any key for exit...
PAUSE>NUL
GOTO :EOF

:cont16
ECHO. Set new kernel: OK

bcdedit.exe /set {%newguid%} path "%systemroot:~2%\system32\%newload%" >nul 2>&1
SET el=%errorlevel%
IF *%el%==*0 GOTO cont17
COLOR 0C
ECHO. ERROR: cannot set new loader!
ECHO. exitcode=%el%
ECHO. Press any key for exit...
PAUSE>NUL
GOTO :EOF

:cont17
ECHO. Set new loader: OK

bcdedit.exe /set {%newguid%} nointegritychecks yes >nul 2>&1
SET el=%errorlevel%
IF *%el%==*0 GOTO cont18
COLOR 0C
ECHO. ERROR: cannot turn off DRM!
ECHO. exitcode=%el%
ECHO. Press any key for exit...
PAUSE>NUL
GOTO :EOF

:cont18
ECHO. Set DRM option off: OK

bcdedit.exe /set {bootmgr} default {%newguid%} >nul 2>&1
SET el=%errorlevel%
IF *%el%==*0 GOTO cont19
COLOR 06
ECHO. Warning: cannot set as default entry!
ECHO. exitcode=%el%
GOTO cont19_1

:cont19
ECHO. Set as default entry option: OK
:cont19_1
IF *%winver%==*7 GOTO cont20_skip
IF *%winver%==*Vista GOTO cont20_skip
bcdedit.exe /set {default} bootmenupolicy legacy >nul 2>&1
SET el=%errorlevel%
IF *%el%==*0 GOTO cont20
COLOR 06
ECHO. Warning: cannot set legacy boot menu option!
ECHO. exitcode=%el%
GOTO cont20_1
:cont20_skip
ECHO. Skip option 'legacy boot menu'...
GOTO cont20_1

:cont20
ECHO. Set legacy boot menu option: OK
:cont20_1
bcdedit.exe /set {bootmgr} displaybootmenu 1 >nul 2>&1
SET el=%errorlevel%
IF *%el%==*0 GOTO cont21
COLOR 06
ECHO. Warning: cannot set display boot menu option!
ECHO. exitcode=%el%
GOTO cont21_1

:cont21
ECHO. Set display boot menu option: OK
:cont21_1
bcdedit.exe /set {bootmgr} timeout 3 >nul 2>&1
SET el=%errorlevel%
IF *%el%==*0 GOTO cont22
COLOR 06
ECHO. Warning: cannot set boot menu timeout!
ECHO. exitcode=%el%
GOTO cont22_1

:cont22
ECHO. Set boot menu timeout: OK
:cont22_1

:cont_end
ECHO.
ECHO. Success, all done.
ECHO. Press any key for exit...
PAUSE>NUL
GOTO :EOF
