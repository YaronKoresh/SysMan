<# :
@echo off
setlocal enabledelayedexpansion

>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"
if '%errorlevel%' NEQ '0' (
    powershell -Command "Start-Process -Verb RunAs -FilePath '%0'"
    exit /b
)

pushd "%CD%"
CD /D "%~dp0"

:mainMenu
cls
echo ==================================================
echo  SysMan Administration Tool (Open-Source MIT Edition)
echo ==================================================
echo.
echo [1] VM ^& vGPU Manager
echo [2] Remote Software ^& Updates
echo [3] Network Management
echo [4] Disk ^& System Maintenance
echo [5] Host Health ^& Stats
echo [6] Advanced Troubleshooting
echo [7] Exit
echo.
set /p "main_choice=Select Module: "

if "%main_choice%"=="1" goto selectVM
if "%main_choice%"=="2" goto menu_software
if "%main_choice%"=="3" goto menu_network
if "%main_choice%"=="4" goto menu_maintenance
if "%main_choice%"=="5" ( set "OperationMode=HEALTH_CHECK" & goto method_gpupv )
if "%main_choice%"=="6" goto menu_troubleshoot
if "%main_choice%"=="7" exit /b
goto mainMenu

:selectVM
cls
echo ==================================================
echo  Hyper-V GPU Manager
echo ==================================================
echo.
set /a "vm_count=0"
for /f "delims=" %%i in ('powershell -NoProfile -Command "Get-VM | Sort-Object VMName | ForEach-Object { $_.VMName }"') do (
    set /a "vm_count+=1"
    set "vm[!vm_count!]=%%i"
    echo [!vm_count!] - %%i
)

if %vm_count% equ 0 (
    echo No VMs found.
    pause
    exit /b
)

echo.
set /p "choice=Select VM Number: "
if %choice% GTR 0 if %choice% LEQ %vm_count% (
    call set "selected_vm=%%vm[%choice%]%%"
) else (
    goto selectVM
)

cls
echo ==================================================
echo  Selected VM: %selected_vm%
echo ==================================================
echo.
if "%OperationMode%"=="UPDATE_VM" goto method_gpupv
if "%OperationMode%"=="MAINT_COMPACT" goto method_gpupv
echo [1] GPU-PV (Paravirtualization) - Recommended
echo [2] DDA (Discrete Device Assignment)
echo [3] Remove GPU
echo.
set /p "method=Enter choice: "

if "%method%"=="1" goto method_gpupv
if "%method%"=="2" goto method_dda
if "%method%"=="3" goto method_remove
goto selectVM

:method_gpupv
cls
set "TargetVM=%selected_vm%"
powershell -NoProfile -ExecutionPolicy Bypass -Command "Invoke-Expression ([System.IO.File]::ReadAllText('%~f0'))"
pause
exit /b

:method_dda
cls
set /p "ddaconfirm=Type 'YES' to continue (Screen may go black): "
if not "%ddaconfirm%"=="YES" goto selectVM

powershell -NoProfile -Command "Get-PnpDevice | Where-Object { $_.Class -eq 'Display' -and $_.Status -eq 'OK' } | Select-Object -Property FriendlyName, InstanceId | Format-Table -AutoSize"
echo.
set /p "gpu_id=Paste GPU InstanceId here: "

powershell -NoProfile -Command "Stop-VM -Name '%selected_vm%' -Force"
powershell -NoProfile -Command "Set-VMFirmware -VMName '%selected_vm%' -EnableSecureBoot Off"
powershell -NoProfile -Command "Set-VM -VMName '%selected_vm%' -CheckpointType Disabled"
powershell -NoProfile -Command "Set-VM -VMName '%selected_vm%' -GuestControlledCacheTypes $true -LowMemoryMappedIoSpace 1GB -HighMemoryMappedIoSpace 33GB"
powershell -NoProfile -Command "Disable-PnpDevice -InstanceId '%gpu_id%' -Confirm:$false"
powershell -NoProfile -Command "$dev = Get-PnpDevice -InstanceId '%gpu_id%'; Dismount-VMHostAssignableDevice -LocationPath ($dev.GetDeviceLocationPath()) -Force"
powershell -NoProfile -Command "$dev = Get-PnpDevice -InstanceId '%gpu_id%'; Add-VMAssignableDevice -VMName '%selected_vm%' -LocationPath ($dev.GetDeviceLocationPath())"

if %errorlevel% equ 0 ( echo SUCCESS ) else ( echo ERROR )
pause
exit /b

:method_remove
cls
echo [1] Remove GPU-PV
echo [2] Remove DDA
echo.
set /p "undo_choice=Enter choice: "

if "%undo_choice%"=="1" (
    powershell -NoProfile -Command "Remove-VMGpuPartitionAdapter -VMName '%selected_vm%'"
    echo Done.
    pause
    exit /b
)

if "%undo_choice%"=="2" (
    powershell -NoProfile -Command "Stop-VM -Name '%selected_vm%' -Force"
    powershell -NoProfile -Command "$devices = Get-VMAssignableDevice -VMName '%selected_vm%'; if ($devices) { foreach ($d in $devices) { Remove-VMAssignableDevice -VMName '%selected_vm%' -LocationPath $d.LocationPath; Mount-VMHostAssignableDevice -LocationPath $d.LocationPath; } }"
    powershell -NoProfile -Command "Get-PnpDevice | Where-Object { $_.Class -eq 'Display' -and $_.Status -eq 'Error' } | Enable-PnpDevice -Confirm:$false"
    echo Done.
    pause
    exit /b
)
goto selectVM

:menu_software
cls
echo [1] Run Windows Update (Host)
echo [2] Run Windows Update (VM)
echo [3] Install Admin Tools (7Zip, Notepad++, Putty)
echo [4] Enable Remote Desktop (RDP)
echo [5] Back
echo.
set /p "sw_sel=Select: "

if "%sw_sel%"=="1" ( set "OperationMode=UPDATE_HOST" & goto method_gpupv )
if "%sw_sel%"=="2" ( set "OperationMode=UPDATE_VM" & goto selectVM )
if "%sw_sel%"=="3" ( set "OperationMode=SOFT_TOOLS" & goto method_gpupv )
if "%sw_sel%"=="4" ( set "OperationMode=SET_RDP" & goto method_gpupv )
if "%sw_sel%"=="5" goto mainMenu
goto menu_software

:menu_network
cls
echo [1] Create NAT Switch (192.168.100.1)
echo [2] Test Port Connectivity
echo [3] Back
echo.
set /p "net_sel=Select: "

if "%net_sel%"=="1" ( set "OperationMode=NET_NAT" & goto method_gpupv )
if "%net_sel%"=="2" ( set "OperationMode=NET_PORT" & goto method_gpupv )
if "%net_sel%"=="3" goto mainMenu
goto menu_network

:menu_maintenance
cls
echo [1] Compact VM Disks (Optimize VHDX)
echo [2] Clean Host Component Store (DISM)
echo [3] Repair System Files (SFC)
echo [4] Back
echo.
set /p "maint_sel=Select: "

if "%maint_sel%"=="1" ( set "OperationMode=MAINT_COMPACT" & goto selectVM )
if "%maint_sel%"=="2" ( set "OperationMode=MAINT_CLEANUP" & goto method_gpupv )
if "%maint_sel%"=="3" ( set "OperationMode=MAINT_SFC" & goto method_gpupv )
if "%maint_sel%"=="4" goto mainMenu
goto menu_maintenance

:menu_troubleshoot
cls
echo [1] Capture Host Screenshot (Evidence)
echo [2] Dump VM Error Logs (Last 20 Events)
echo [3] Restart Hyper-V Management Service (VMMS)
echo [4] Open VM Console (VMConnect)
echo [5] Back
echo.
set /p "ts_sel=Select: "

if "%ts_sel%"=="1" ( set "OperationMode=TS_SCREENSHOT" & goto method_gpupv )
if "%ts_sel%"=="2" ( set "OperationMode=TS_LOGS" & goto selectVM )
if "%ts_sel%"=="3" ( set "OperationMode=TS_RESTART_SVC" & goto method_gpupv )
if "%ts_sel%"=="4" ( set "OperationMode=TS_CONSOLE" & goto selectVM )
if "%ts_sel%"=="5" goto mainMenu
goto menu_troubleshoot

: end batch / begin powershell #>

if ($env:OperationMode -like "UPDATE_*") {
    $target = if ($env:OperationMode -eq "UPDATE_VM") { $env:TargetVM } else { "LocalHost" }
    Write-Host "Starting Update Manager on: $target" -ForegroundColor Magenta

    $UpdateScript = {
        Write-Host "Scanning for updates..." -ForegroundColor Yellow
        $s = New-Object -ComObject Microsoft.Update.Session
        $r = $s.CreateUpdateSearcher().Search("IsInstalled=0")
        
        if ($r.Updates.Count -eq 0) { 
            Write-Host "System is up to date." -ForegroundColor Green 
        } else {
            Write-Host "Found $($r.Updates.Count) updates. Installing..." -ForegroundColor Cyan
            $i = $s.CreateUpdateInstaller()
            $i.Updates = $r.Updates
            $i.Install()
            Write-Host "Installation Complete. Reboot may be required." -ForegroundColor Green
        }
    }

    if ($target -eq "LocalHost") { 
        Invoke-Command -ScriptBlock $UpdateScript 
    } else {
        Write-Host "Enter credentials for VM administrative access:" -ForegroundColor White
        Invoke-Command -VMName $target -Credential (Get-Credential) -ScriptBlock $UpdateScript
    }
    exit
}

if ($env:OperationMode -eq "NET_NAT") {
    $SW = "NATSwitch"
    New-VMSwitch -Name $SW -SwitchType Internal -Force
    New-NetIPAddress -IPAddress "192.168.100.1" -PrefixLength 24 -InterfaceAlias "vEthernet ($SW)" -Force
    New-NetNat -Name "NATNetwork" -InternalIPInterfaceAddressPrefix "192.168.100.0/24" -Force
    Write-Host "NAT Switch Created. Gateway: 192.168.100.1" -ForegroundColor Green
    exit
}

if ($env:OperationMode -eq "NET_PORT") {
    $t = Read-Host "Target IP/Host"
    $p = Read-Host "Port"
    Test-NetConnection -ComputerName $t -Port $p
    exit
}

if ($env:OperationMode -eq "MAINT_CLEANUP") {
    Write-Host "Running DISM Component Cleanup..." -ForegroundColor Yellow
    Start-Process -FilePath "dism.exe" -ArgumentList "/Online /Cleanup-Image /StartComponentCleanup /ResetBase" -Wait -NoNewWindow
    Write-Host "Cleanup Complete." -ForegroundColor Green
    exit
}

if ($env:OperationMode -eq "MAINT_COMPACT") {
    $VMName = $env:TargetVM
    Write-Host "Stopping VM: $VMName to release file locks..." -ForegroundColor Yellow
    Stop-VM -Name $VMName -Force -ErrorAction SilentlyContinue
    
    $Disks = Get-VMHardDiskDrive -VMName $VMName
    foreach ($d in $Disks) {
        Write-Host "Compacting: $($d.Path)" -ForegroundColor Cyan
        Optimize-VHD -Path $d.Path -Mode Full
    }
    Write-Host "Optimization Complete." -ForegroundColor Green
    exit
}

if ($env:OperationMode -eq "MAINT_SFC") {
    Write-Host "Running System File Checker..." -ForegroundColor Yellow
    Start-Process -FilePath "sfc.exe" -ArgumentList "/scannow" -Wait -NoNewWindow
    exit
}

if ($env:OperationMode -eq "SET_RDP") {
    Write-Host "Enabling Remote Desktop..." -ForegroundColor Yellow
    Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections" -value 0
    Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
    Write-Host "RDP Enabled." -ForegroundColor Green
    exit
}

if ($env:OperationMode -eq "SOFT_TOOLS") {
    Write-Host "Installing Admin Tools via Winget..." -ForegroundColor Cyan
    $tools = @("7zip.7zip", "Notepad++.Notepad++", "PuTTY.PuTTY")
    foreach ($t in $tools) {
        Write-Host "Installing: $t"
        winget install -e --id $t --accept-source-agreements --accept-package-agreements
    }
    Write-Host "Installation Complete." -ForegroundColor Green
    exit
}

if ($env:OperationMode -eq "TS_SCREENSHOT") {
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    
    $screen = [System.Windows.Forms.SystemInformation]::VirtualScreen
    $bitmap = New-Object System.Drawing.Bitmap $screen.Width, $screen.Height
    $graphic = [System.Drawing.Graphics]::FromImage($bitmap)
    $graphic.CopyFromScreen($screen.Left, $screen.Top, 0, 0, $bitmap.Size)
    
    $path = "$env:USERPROFILE\Desktop\Host_Capture_$(Get-Date -Format 'yyyyMMdd-HHmmss').png"
    $bitmap.Save($path)
    
    Write-Host "Screenshot saved to: $path" -ForegroundColor Green
    exit
}

if ($env:OperationMode -eq "TS_LOGS") {
    $target = $env:TargetVM
    Write-Host "Fetching Error Logs from $target..." -ForegroundColor Yellow
    Invoke-Command -VMName $target -Credential (Get-Credential) -ScriptBlock {
        Get-EventLog -LogName System -EntryType Error -Newest 20 | Format-Table TimeGenerated, Source, Message -AutoSize
    }
    exit
}

if ($env:OperationMode -eq "TS_RESTART_SVC") {
    Write-Host "Restarting Hyper-V Management Service..." -ForegroundColor Red
    Restart-Service vmms -Force
    Write-Host "Service Restarted." -ForegroundColor Green
    exit
}

if ($env:OperationMode -eq "TS_CONSOLE") {
    $target = $env:TargetVM
    Write-Host "Launching Console for $target..." -ForegroundColor Cyan
    Start-Process "vmconnect.exe" -ArgumentList "localhost $target"
    exit
}

if ($env:OperationMode -eq "HEALTH_CHECK") {
    Clear-Host
    Write-Host "=== HOST SYSTEM HEALTH ===" -ForegroundColor Cyan
    
    # CPU & RAM
    $os = Get-CimInstance Win32_OperatingSystem
    $totalMem = [math]::Round($os.TotalVisibleMemorySize / 1MB, 2)
    $freeMem = [math]::Round($os.FreePhysicalMemory / 1MB, 2)
    $usedMem = $totalMem - $freeMem
    $cpu = (Get-WmiObject Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average
    
    Write-Host "CPU Load:     $cpu %" -ForegroundColor ($cpu -gt 85 ? 'Red' : 'Green')
    Write-Host "Memory Usage: $usedMem GB / $totalMem GB" -ForegroundColor ($freeMem -lt 2 ? 'Red' : 'Green')
    
    # Disks
    Write-Host "`n--- DISK STATUS ---" -ForegroundColor Yellow
    Get-Volume | Where-Object {$_.DriveType -eq 'Fixed'} | Format-Table DriveLetter, FileSystemLabel, @{L='Free(GB)';E={"{0:N1}" -f ($_.SizeRemaining/1GB)}}, @{L='Total(GB)';E={"{0:N1}" -f ($_.Size/1GB)}} -AutoSize | Out-String | Write-Host

    # VMs
    Write-Host "--- VM STATUS ---" -ForegroundColor Yellow
    Get-VM | Select-Object Name, State, @{L='Uptime';E={$_.Uptime.ToString().Substring(0,8)}}, @{L='RAM(MB)';E={$_.MemoryAssigned/1MB}} | Sort-Object State | Format-Table -AutoSize | Out-String | Write-Host
    
    Write-Host "[Press Enter to return]"
    Read-Host
    exit
}

$VMName = $env:TargetVM
Write-Host "Configuring GPU-PV for: $VMName" -ForegroundColor Cyan

Set-VMFirmware -VMName $VMName -EnableSecureBoot Off
Set-VM -VMName $VMName -CheckpointType Disabled

Function Add-VMGpuPartitionAdapterFiles {
    param([string]$hostname = $ENV:COMPUTERNAME, [string]$DriveLetter, [string]$GPUName = "AUTO")

    If (!($DriveLetter -like "*:*")) { $DriveLetter = $DriveLetter + ":" }

    # 1. GPU Detection
    If ($GPUName -eq "AUTO") {
        $PartitionableGPUList = Get-WmiObject -Class "Msvm_PartitionableGpu" -ComputerName $env:COMPUTERNAME -Namespace "ROOT\virtualization\v2"
        $DevicePathName = $PartitionableGPUList.Name | Select-Object -First 1
        $GPU = Get-PnpDevice | Where-Object {($_.DeviceID -like "*$($DevicePathName.Substring(8,16))*") -and ($_.Status -eq "OK")} | Select-Object -First 1
        $GPUName = $GPU.Friendlyname
        $GPUServiceName = $GPU.Service 
    } Else {
        $GPU = Get-PnpDevice | Where-Object {($_.Name -eq "$GPUName") -and ($_.Status -eq "OK")} | Select-Object -First 1
        $GPUServiceName = $GPU.Service
    }

    $EasyDriverPath = "$DriveLetter\GPU-Drivers"
    $HostDriverStorePath = "$DriveLetter\windows\system32\HostDriverStore"
    
    New-Item -ItemType Directory -Path $EasyDriverPath -Force | Out-Null
    New-Item -ItemType Directory -Path $HostDriverStorePath -Force | Out-Null

    Write-Host "Detected GPU: $GPUName" -ForegroundColor Cyan
    Write-Host "Calculating driver dependencies..." -ForegroundColor Yellow

    # 2. Optimized Driver Collection (Folder based instead of file based)
    $DriverFolders = @()
    
    # Get main System32 driver path
    $servicePath = (Get-WmiObject Win32_SystemDriver | Where-Object {$_.Name -eq "$GPUServiceName"}).Pathname
    # Assuming standard DriverStore layout
    if ($servicePath -like "*DriverStore*") {
        $MainDriverFolder = $servicePath.split('\')[0..5] -join('\')
        $DriverFolders += $MainDriverFolder
    }

    # Get dependent drivers via WMI
    $Drivers = Get-WmiObject Win32_PNPSignedDriver | where {$_.DeviceName -eq "$GPUName"}
    foreach ($d in $drivers) {
        $ModifiedDeviceID = $d.DeviceID -replace "\\", "\\"
        $Antecedent = "\\" + $hostname + "\ROOT\cimv2:Win32_PNPSignedDriver.DeviceID=""$ModifiedDeviceID"""
        
        # Get all files, but extract only the unique parent folders
        $DriverFiles = Get-WmiObject Win32_PNPSignedDriverCIMDataFile | where {$_.Antecedent -eq $Antecedent}
        foreach ($f in $DriverFiles) {
             $fullPath = $f.Dependent.Split("=")[1] -replace '\\\\', '\'
             $cleanPath = $fullPath.Substring(1, $fullPath.Length-2) # Remove quotes
             
             if ($cleanPath -like "*DriverStore*") {
                 $folderPath = $cleanPath.split('\')[0..5] -join('\')
                 $DriverFolders += $folderPath
             }
        }
    }

    # Remove duplicates to avoid copying the same 500MB folder 10 times
    $UniqueFolders = $DriverFolders | Select-Object -Unique

    # 3. Fast Copy Execution
    Write-Host "Copying $($UniqueFolders.Count) Driver Packages..." -ForegroundColor Yellow
    
    foreach ($SrcFolder in $UniqueFolders) {
        $FolderName = $SrcFolder | Split-Path -Leaf
        
        # Destination 1: System-like path for auto-detection attempt
        $Dest1 = "$HostDriverStorePath\FileRepository\$FolderName"
        
        # Destination 2: Easy access path for manual install
        $Dest2 = "$EasyDriverPath\$FolderName"

        Write-Host "Copying: $FolderName" -NoNewline
        
        # Copy to Dest1
        if (!(Test-Path $Dest1)) { New-Item -ItemType Directory -Path $Dest1 -Force | Out-Null }
        Copy-Item -Path "$SrcFolder\*" -Destination "$Dest1" -Recurse -Force -ErrorAction SilentlyContinue

        # Copy to Dest2 (Manual Install)
        if (!(Test-Path $Dest2)) { New-Item -ItemType Directory -Path $Dest2 -Force | Out-Null }
        Copy-Item -Path "$SrcFolder\*" -Destination "$Dest2" -Recurse -Force -ErrorAction SilentlyContinue
        
        Write-Host " [OK]" -ForegroundColor Green
    }

    # 4. NVAPI Fix (Critical for Win11->Win10)
    $NvApiSource = "$env:SystemRoot\System32\nvapi64.dll"
    if (Test-Path $NvApiSource) {
        Write-Host "Copying nvapi64.dll..." -ForegroundColor Yellow
        Copy-Item $NvApiSource -Destination "$DriveLetter\Windows\System32\nvapi64.dll" -Force -ErrorAction SilentlyContinue
        }

    Write-Host "Injecting drivers into VM image..." -ForegroundColor Yellow
    Start-Process -FilePath "dism.exe" -ArgumentList "/Image:$DriveLetter\ /Add-Driver /Driver:$EasyDriverPath /Recurse /ForceUnsigned" -PassThru -Wait -NoNewWindow
}

$VM = Get-VM -VMName $VMName
$VHD = Get-VHD -VMId $VM.VMId

If ($VM.state -ne "Off"){ Stop-VM -Name $VMName -Force; Start-Sleep -s 2 }

try {
    $DriveLetter = (Mount-VHD -Path $VHD.Path -PassThru | Get-Disk | Get-Partition | Get-Volume | Where-Object {$_.DriveLetter} | Select-Object -ExpandProperty DriveLetter)
    if (-not $DriveLetter) { throw "Could not get DriveLetter" }
    
    Add-VMGpuPartitionAdapterFiles -hostname $ENV:COMPUTERNAME -DriveLetter $DriveLetter -GPUName "AUTO"
    
    Dismount-VHD -Path $VHD.Path
    try { Remove-VMGpuPartitionAdapter -VMName $VMName -ErrorAction SilentlyContinue } catch {}
    Add-VMGpuPartitionAdapter -VMName $VMName
    
    Write-Host "`nSUCCESS!" -ForegroundColor Green
    Write-Host "Drivers installed. Start the VM."
} catch {
    Write-Error $_
    if ($DriveLetter) { Dismount-VHD -Path $VHD.Path }
}