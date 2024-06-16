@fltmc > nul || (echo CreateObject^("Shell.Application"^).ShellExecute "cmd.exe", "%~s0", , "runas", 1 >> "%tmp%\GetAdmin.vbs" && "%tmp%\GetAdmin.vbs" && del "%tmp%\GetAdmin.vbs" & @exit)
@echo off
color a
echo Speeding up...
start cleanmgr /sagerun /verylowdisk /autoclean
defrag /C /B /M
defrag /C /K /M
defrag /C /L /M
defrag /C /O /M
del /s /q C:\Windows\Prefetch\*.* C:\Windows\Temp %temp%\*.*
rd /s /q C:\Windows\Temp %tmp%
md C:\Windows\Temp %tmp%
taskkill /f /im TiWorker.exe > nul
sc config trustedinstaller start=disabled
sc config spooler start=disabled
sc stop diagTrack && sc delete diagTrack
sc stop dmwappushservice && sc delete dmwappushservice
fsutil behavior query memoryusage | find "2" || fsutil behavior set memoryusage 2
reg add HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NetworkThrottlingIndex" /t REG_DWORD /d 268435455 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "SystemResponsiveness" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Affinity" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Background Only" /t REG_SZ /d False /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Clock Rate" /t REG_DWORD /d 10000 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Scheduling Category" /t REG_SZ /d High /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "SFIO Priority" /t REG_SZ /d High /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "GPU Priority" /t REG_DWORD /d 8 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Priority" /t REG_DWORD /d 6 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" /v "PowerThrottlingOff" /t REG_DWORD /d 1 /f
netsh interface ipv4 set dns "Wi-Fi" static 1.1.1.1
netsh interface ipv6 set dns "Wi-Fi" static 2606:4700:4700::1111
netsh interface ipv4 add dns "Wi-Fi" 1.0.0.1
netsh interface ipv6 add dns "Wi-Fi" 2606:4700:4700::1001
netsh interface ipv4 set dns "Ethernet" static 1.1.1.1
netsh interface ipv6 set dns "Ethernet" static 2606:4700:4700::1111
netsh interface ipv4 add dns "Ethernet" 1.0.0.1
netsh interface ipv6 add dns "Ethernet" 2606:4700:4700::1001
netsh winsock reset
ipconfig /flushdns
ipconfig /release
ipconfig /release6
ipconfig /renew
ipconfig /renew6
timeout -1