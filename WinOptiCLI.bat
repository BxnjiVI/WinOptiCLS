echo off

:: Check if the script is running as admin
net session >nul 2>&1
if %errorLevel% == 0 (
    set "isAdmin=[92mYES[0m"
) else (
    set "isAdmin=[1;91mNO (THIS WILL CAUSE ISSUES)[0m"
)

cls

:: Main Menu
title WinOptiCLS v1.0.0
echo.
echo  [94m              ##      ## #### ##    ##    [0m #######  ########  ######## ####     [94m ######  ##       #### 
echo  [94m              ##  ##  ##  ##  ###   ##    [0m##     ## ##     ##    ##     ##      [94m##    ## ##        ##  
echo  [94m              ##  ##  ##  ##  ####  ##    [0m##     ## ##     ##    ##     ##      [94m##       ##        ##  
echo  [94m              ##  ##  ##  ##  ## ## ##    [0m##     ## ########     ##     ##      [94m##       ##        ##  
echo  [94m              ##  ##  ##  ##  ##  ####    [0m##     ## ##           ##     ##      [94m##       ##        ##  
echo  [94m              ##  ##  ##  ##  ##   ###    [0m##     ## ##           ##     ##      [94m##    ## ##        ##  
echo  [94m               ###  ###  #### ##    ##    [0m #######  ##           ##    ####      [94m######  ######## ####[0m v1.0.0
echo.
echo.
echo  [94m^> [0mRunning as admin [94m=[0m %isAdmin%
echo.
echo  [94m[[0m [1mMain Menu [94m][0m
echo.
echo  [1m[0m1[94m)[0m Windows Tweaks
echo  [1m[0m2[94m)[0m Specific Hardware Tweaks
echo  [1m[0m3[94m)[0m Specific Game Tweaks
echo.
echo  [94m[[0m [1mCredit [94m][0m
echo.
echo  -  Created by Bxnji
echo.
set /p mainmenuinput=" [1;94m $ [0m"

:: Main Menu if inputs
if mainmenuinput==1 goto windowstweaks
if mainmenuinput==2 goto specifichardwaretweaks
if mainmenuinput==3 goto specificgametweaks

:: Windows Tweaks Menu
:windowstweaks
cls
echo.
echo  [94m              ##      ## #### ##    ##    [0m #######  ########  ######## ####     [94m ######  ##       #### 
echo  [94m              ##  ##  ##  ##  ###   ##    [0m##     ## ##     ##    ##     ##      [94m##    ## ##        ##  
echo  [94m              ##  ##  ##  ##  ####  ##    [0m##     ## ##     ##    ##     ##      [94m##       ##        ##  
echo  [94m              ##  ##  ##  ##  ## ## ##    [0m##     ## ########     ##     ##      [94m##       ##        ##  
echo  [94m              ##  ##  ##  ##  ##  ####    [0m##     ## ##           ##     ##      [94m##       ##        ##  
echo  [94m              ##  ##  ##  ##  ##   ###    [0m##     ## ##           ##     ##      [94m##    ## ##        ##  
echo  [94m               ###  ###  #### ##    ##    [0m #######  ##           ##    ####      [94m######  ######## ####[0m v1.0.0
echo.
echo.
echo  [94m[[0m [1mWindows Tweaks Menu [94m][0m
echo.
echo  [1m[0m1[94m)[0m Clear Temp Files
echo  [1m[0m2[94m)[0m Clear Prefetch Files
echo  [1m[0m3[94m)[0m Disable Game DVR
echo  [1m[0m4[94m)[0m Disable Game Bar
echo  [1m[0m5[94m)[0m Disable Xbox Game Monitoring Service
echo  [1m[0m6[94m)[0m Enable Windows Game Mode
echo  [1m[0m7[94m)[0m Enable High Peformance Plan
echo  [1m[0m8[94m)[0m Enable Hardware-Accelerated GPU Scheduling
echo  [1m[0m9[94m)[0m Disable Cortana
echo  [1m[0m10[94m)[0m Disable Windows Ink
echo  [1m[0m11[94m)[0m Prefer IPv4 over IPv6
echo  [1m[0m12[94m)[0m Disable Location Tracking
echo  [1m[0m13[94m)[0m Enable End Task with Right Click
echo.
set /p windowstweaksmenuinput=" [1;94m $ [0m"

:: Windows Tweaks Menu if inputs
if "!windowstweaksmenuinput!"=="1" goto tempfiles
if "!windowstweaksmenuinput!"=="2" goto prefetchfiles
if "!windowstweaksmenuinput!"=="3" goto gamedvr
if "!windowstweaksmenuinput!"=="4" goto gamebar
if "!windowstweaksmenuinput!"=="5" goto xboxgameserv
if "!windowstweaksmenuinput!"=="6" goto gamemode
if "!windowstweaksmenuinput!"=="7" goto highpef
if "!windowstweaksmenuinput!"=="8" goto HAGPUshe
if "!windowstweaksmenuinput!"=="9" goto cortarna
if "!windowstweaksmenuinput!"=="10" goto ink
if "!windowstweaksmenuinput!"=="11" goto preferipv4
if "!windowstweaksmenuinput!"=="12" goto disablelocation
if "!windowstweaksmenuinput!"=="13" goto enableendtask


:: Windows Tweaks Actions
:tempfiles
echo.
echo Clearing Temporary files...
del /q /f %temp%\*
del /q /f C:\Windows\Temp\*
echo.
echo Temporary files have been cleared, returning to menu
echo.
timeout /t 4 >nul
echo.
goto :windowstweaks

:prefetchfiles
echo.
echo Clearing Prefetch files...
echo.
del /q /f C:\Windows\Prefetch\*
echo.
echo Prefetch files have been cleared, returning to menu
echo.
timeout /t 4 >nul
echo.
goto :windowstweaks

:gamedvr
echo.
echo Disabling Game DVR...
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v AppCaptureEnabled /t REG_DWORD /d 0 /f
echo Game DVR Disabled, returning to menu
echo.
timeout /t 4 >nul
echo.
goto :windowstweaks

:gamebar
echo.
echo Disabling Game Bar...
reg add "HKEY_CURRENT_USER\Software\Microsoft\GameBar" /v AllowAutoGameMode /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\GameBar" /v ShowStartupPanel /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\GameBar" /v GameDVR_Enabled /t REG_DWORD /d 0 /f
echo Game Bar Disabled, returning to menu
echo.
timeout /t 4 >nul
echo.
goto :windowstweaks

:xboxgameserv
echo.
echo Disabling Xbox Game Monitoring Service...
sc config XblGameSave start= disabled
sc stop XblGameSave
echo Xbox Game Monitoring Service disabled, returning to menu
echo.
timeout /t 4 >nul
echo.
goto :windowstweaks

:gamemode
echo.
echo Enabling Windows Game Mode...
REG ADD "HKCU\Software\Microsoft\GameBar" /v "AllowAutoGameMode" /t REG_DWORD /d 1 /f
REG ADD "HKCU\Software\Microsoft\GameBar" /v "GameModeEnabled" /t REG_DWORD /d 1 /f
echo Windows Game Mode enabled, returning to menu
echo.
timeout /t 4 >nul
echo.
goto :windowstweaks

:highpef
echo.
echo Enabling High Peformance Plan...
powercfg -setactive SCHEME_MIN
echo High Peformance Plan enabled, returning to menu
echo.
timeout /t 4 >nul
echo.
goto :windowstweaks

:HAGPUshe
echo Enabling Hardware-Accelerated GPU Scheduling...
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v HwSchMode /t REG_DWORD /d 2 /f
echo Hardware-Accelerated GPU Scheduling enabled, returning to menu
echo.
timeout /t 4 >nul
echo.
goto :windowstweaks

:cortarna
echo Disabling Cortana...
reg add "HKCU\Software\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d 0 /f
echo Cortana disabled, returning to menu
echo.
timeout /t 4 >nul
echo.
goto :windowstweaks

:ink
echo Disabling Windows Ink...
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Pen\Critical" /v "AllowWindowsInkWorkspace" /t REG_DWORD /d 0 /f
echo Windows Ink disabled, returning to menu
echo.
timeout /t 4 >nul
echo.
goto :windowstweaks

:preferipv4
echo Prefer IPv4 over IPv6...
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" /v "DisabledComponents" /t REG_DWORD /d 0x20 /f
echo IPv4 preference enabled, returning to menu
echo.
timeout /t 4 >nul
echo.
goto :windowstweaks

:disablelocation
echo Disabling Location Tracking...
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" /v "Value" /t REG_DWORD /d 0 /f
echo Location Tracking disabled, returning to menu
echo.
timeout /t 4 >nul
echo.
goto :windowstweaks

:enableendtask
echo Enabling "End Task" with Right Click...
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoClose" /t REG_DWORD /d 0 /f
echo "End Task" with right-click enabled, returning to menu
echo.
timeout /t 4 >nul
echo.
goto :windowstweaks