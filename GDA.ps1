title GhostDriverAudit v1 for WIN11 25H2 | Build 260524_2 by RoC-42 (GPL v3)

# 1. Enforce Administrator Rights
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script requires Administrator privileges! Please restart PowerShell as Administrator."
    Exit
}

Clear-Host
Write-Output "========================================================="
Write-Output "    INTELLIGENT AUDIT, BACKUP & INTERACTIVE FIX SYSTEM (V4.3)"
Write-Output "========================================================="

# -----------------------------------------------------------------
# PREPARATION: AUTOMATIC BACKUP (System Restore Point)
# -----------------------------------------------------------------
Write-Output "`n[0/4] Creating automatic System Restore Point..."
Write-Output "---------------------------------------------------------"

$sysRestoreReg = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore"
if (Test-Path $sysRestoreReg) {
    Set-ItemProperty -Path $sysRestoreReg -Name "SystemRestorePointCreationFrequency" -Value 0 -PropertyType DWORD -Force | Out-Null
}

$date = Get-Date -Format "yyyy-MM-dd - HH:mm:ss"
$restoreName = "GhostDriverAudit Backup $date"

try {
    Enable-ComputerRestore -Drive "C:\" -ErrorAction SilentlyContinue
    Checkpoint-Computer -Description $restoreName -RestorePointType "APPLICATION_UNINSTALL" -ErrorAction Stop
    Write-Output "[+] System Restore Point successfully created:"
    Write-Output "    '$restoreName'"
} catch {
    Write-Warning "[!] System Restore Point could not be created."
    Write-Warning "    Reason: $($_.Exception.Message)"
    $confirm = Read-Host "`nDo you want to CONTINUE the script WITHOUT a backup? (y/n)"
    if ($confirm -ne "y") { Exit }
}

# -----------------------------------------------------------------
# SETUP VARIABLES & EXPANDED IGNORE LIST (OS + BACKUP SOFTWARE)
# -----------------------------------------------------------------
$detectedServices = @()
$detectedClassFilters = @()
$detectedEnumFilters = @()

# Comprehensive list of native Windows + trusted Backup filters to completely bypass
$msFilters = @(
    # Core OS Filters
    "kbdclass", "mouclass", "vdrvroot", "volmgr", "fltsrv", "partmgr", 
    "rawwan", "ndis", "umpass", "rdpinput", "cdrom", "disk", "fvevol", 
    "pci", "acpi", "volmgrx", "tdx", "netvsc", "luafv", "iorate", "rdyboost",
    "volsnap", "ksthunk", "ehstorclass", "scfilter", "wpdupfltr", "wdmcompanionfilter",
    "pciidex", "intelpep", "spaceport", "sercx2", "bthpan",
    # Acronis Backup
    "file_protector", "tib_mounter", "fltsrv", "vidsflt", "tdrpman", "snapman",
    # AOMEI Backup
    "ambakdrv", "ammntdrv", "amlnk", "amwrtdrv",
    # Macrium Reflect
    "mrcbt", "mrflt", "vssmft",
    # Veeam
    "veeamsnap"
)

$coreClasses = @{
    "{4D36E96B-E325-11CE-BFC1-08002BE10318}" = "kbdclass"
    "{4D36E96F-E325-11CE-BFC1-08002BE10318}" = "mouclass"
}

# Helper function to check if a driver file belongs to Microsoft or trusted backup suites
function Is-TrustedDriver ($driverName) {
    $sysPath = "C:\Windows\System32\drivers\$driverName.sys"
    if (-not (Test-Path $sysPath)) { return $false }
    
    # 1. Check digital certificate signatures
    $signature = Get-AuthenticodeSignature $sysPath -ErrorAction SilentlyContinue
    $subject = $signature.SignerCertificate.Subject
    if ($subject -match "Microsoft Windows" -or 
        $subject -match "Acronis" -or 
        $subject -match "AOMEI" -or 
        $subject -match "Paramount Software") { 
        return $true 
    }
    
    # 2. Fallback check via File Metadata Company Name
    $company = (Get-Item $sysPath).VersionInfo.CompanyName
    if ($company -match "Microsoft" -or 
        $company -match "Acronis" -or 
        $company -match "AOMEI" -or 
        $company -match "Macrium") { 
        return $true 
    }
    
    return $false
}

# =================================================================
# PART 1: DIAGNOSTIC PHASE
# =================================================================

# 1.1 Scan for orphaned services
Write-Output "`n[1/4] Starting deep scan for orphaned kernel services..."
Write-Output "---------------------------------------------------------"
Get-ChildItem -Path "HKLM:\SYSTEM\CurrentControlSet\Services" | ForEach-Object {
    $name = $_.PSChildName
    $imagePath = (Get-ItemProperty -Path $_.PSPath -Name "ImagePath" -ErrorAction SilentlyContinue).ImagePath
    
    if ($imagePath -and $imagePath -match "system32\\drivers\\") {
        $cleanPath = $imagePath -replace '^\\SystemRoot\\', 'C:\Windows\'
        $cleanPath = $cleanPath -replace '^system32\\', 'C:\Windows\System32\'
        $cleanPath = $cleanPath -replace '"', ''
        if ($cleanPath -notmatch "^[A-Z]:") { $cleanPath = "C:\Windows\System32\drivers\$cleanPath" }

        if (-not (Test-Path $cleanPath)) {
            if ($msFilters -notcontains $name.ToLower()) {
                Write-Output "[!] Found: Service '$name' references a missing file."
                $detectedServices += ,[PSCustomObject]@{ ServiceName = $name; FilePath = $cleanPath }
            }
        }
    }
}
if ($detectedServices.Count -eq 0) { Write-Output "[+] No orphaned services located." }

# 1.2 Scan for unlisted third-party class filters
Write-Output "`n[2/4] Starting deep scan for unlisted Device Class filters..."
Write-Output "---------------------------------------------------------"
Get-ChildItem -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class" | ForEach-Object {
    $classGuid = $_.PSChildName
    $className = (Get-ItemProperty -Path $_.PSPath -Name "Class" -ErrorAction SilentlyContinue).Class
    $classDesc = (Get-ItemProperty -Path $_.PSPath -Name "ClassDesc" -ErrorAction SilentlyContinue).ClassDesc
    if ($classDesc -match "@") { $classDesc = $className }

    foreach ($filterType in @("UpperFilters", "LowerFilters")) {
        $filters = (Get-ItemProperty -Path $_.PSPath -Name $filterType -ErrorAction SilentlyContinue).$filterType
        if ($filters) {
            foreach ($f in $filters) {
                if ($msFilters -notcontains $f.ToLower()) {
                    if (-not (Is-TrustedDriver $f)) {
                        Write-Output "[?] Found: Class '$className' uses filter '$f' ($filterType)"
                        $detectedClassFilters += ,[PSCustomObject]@{ ClassGuid = $classGuid; FilterType = $filterType; FilterName = $f; ClassName = $className }
                    }
                }
            }
        }
    }
}
if ($detectedClassFilters.Count -eq 0) { Write-Output "[+] No unlisted Device Class filters active." }

# 1.3 Extended scan for individual device instances (Enum)
Write-Output "`n[3/4] Extending deep scan to Device Instances (Enum)..."
Write-Output "---------------------------------------------------------"
foreach ($sub in @("USB", "HID", "PCI")) {
    $enumPath = "HKLM:\SYSTEM\CurrentControlSet\Enum\$sub"
    if (Test-Path $enumPath) {
        Get-ChildItem -Path $enumPath -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
            $path = $_.PSPath
            $regPath = $_.Name -replace "HKEY_LOCAL_MACHINE", "HKLM:"
            $deviceName = $_.PSChildName
            
            foreach ($filterType in @("UpperFilters", "LowerFilters")) {
                $filters = (Get-ItemProperty -Path $path -Name $filterType -ErrorAction SilentlyContinue).$filterType
                if ($filters) {
                    foreach ($f in $filters) {
                        if ($msFilters -notcontains $f.ToLower()) {
                            if (-not (Is-TrustedDriver $f)) {
                                Write-Output "[?] Found: Instance '$sub\$deviceName' uses filter '$f' ($filterType)"
                                $detectedEnumFilters += ,[PSCustomObject]@{ RegPath = $regPath; FilterType = $filterType; FilterName = $f; DeviceName = $deviceName }
                            }
                        }
                    }
                }
            }
        }
    }
}
if ($detectedEnumFilters.Count -eq 0) { Write-Output "[+] No unlisted Device Instance filters active." }

# =================================================================
# PART 2: INTERACTIVE REMEDIATION PHASE
# =================================================================
Write-Output "`n========================================================="
Write-Output "       [4/4] INTERACTIVE REMEDIATION DECISION"
Write-Output "========================================================="

# 2.1 Prompt for orphaned services
if ($detectedServices.Count -gt 0) {
    Write-Output "`n--- Cleaning Orphaned Services ---"
    foreach ($srv in $detectedServices) {
        $choice = Read-Host "Do you want to delete the service '$($srv.ServiceName)'? (y/n)"
        if ($choice -eq "y") {
            Remove-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$($srv.ServiceName)" -Recurse -Force -ErrorAction SilentlyContinue
            Write-Output "   [+] Service '$($srv.ServiceName)' removed from registry."
        }
    }
}

# 2.2 Prompt for Class filters
if ($detectedClassFilters.Count -gt 0) {
    Write-Output "`n--- Cleaning Unlisted Device Class Filters ---"
    foreach ($flt in $detectedClassFilters) {
        $choice = Read-Host "Do you want to remove filter '$($flt.FilterName)' from Class '$($flt.ClassName)'? (y/n)"
        if ($choice -eq "y") {
            $classPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\$($flt.ClassGuid)"
            if (Test-Path $classPath) {
                $currentFilters = (Get-ItemProperty -Path $classPath -Name $flt.FilterType).$($flt.FilterType)
                [string[]]$cleanedFilters = $currentFilters | Where-Object { $_ -ne $flt.FilterName }
                
                if ($cleanedFilters.Count -gt 0) {
                    Set-ItemProperty -Path $classPath -Name $flt.FilterType -Value $cleanedFilters -PropertyType MultiString -Force
                    Write-Output "   [+] Filter '$($flt.FilterName)' successfully extracted."
                } else {
                    if ($coreClasses.ContainsKey($flt.ClassGuid)) {
                        $fallback = $coreClasses[$flt.ClassGuid]
                        Set-ItemProperty -Path $classPath -Name $flt.FilterType -Value @($fallback) -PropertyType MultiString -Force
                        Write-Output "   [!] Safety anchor triggered: Enforced default driver '$fallback'!"
                    } else {
                        Remove-ItemProperty -Path $classPath -Name $flt.FilterType -Force -ErrorAction SilentlyContinue
                        Write-Output "   [+] Filter entry cleared and reset."
                    }
                }

                $possibleFile = "C:\Windows\System32\drivers\$($flt.FilterName).sys"
                if (Test-Path $possibleFile) {
                    & takeown.exe /f $possibleFile /a | Out-Null
                    & icacls.exe $possibleFile /grant *S-1-5-32-544:F | Out-Null
                    Remove-Item -Path $possibleFile -Force -ErrorAction SilentlyContinue
                    Write-Output "   [+] Associated file '$($flt.FilterName).sys' deleted from disk."
                }
            }
        }
    }
}

# 2.3 Prompt for Device Instance filters (Enum layer)
if ($detectedEnumFilters.Count -gt 0) {
    Write-Output "`n--- Cleaning Device Instance Filters (Enum) ---"
    foreach ($efl in $detectedEnumFilters) {
        $choice = Read-Host "Do you want to remove filter '$($efl.FilterName)' from Instance '$($efl.DeviceName)'? (y/n)"
        if ($choice -eq "y") {
            if (Test-Path $efl.RegPath) {
                $currentFilters = (Get-ItemProperty -Path $efl.RegPath -Name $efl.FilterType).$($efl.FilterType)
                [string[]]$cleanedFilters = $currentFilters | Where-Object { $_ -ne $efl.FilterName }

                if ($cleanedFilters.Count -gt 0) {
                    Set-ItemProperty -Path $efl.RegPath -Name $efl.FilterType -Value $cleanedFilters -PropertyType MultiString -Force
                    Write-Output "   [+] Instance filter '$($efl.FilterName)' successfully extracted."
                } else {
                    Remove-ItemProperty -Path $efl.RegPath -Name $efl.FilterType -Force -ErrorAction SilentlyContinue
                    Write-Output "   [+] Instance filter entry cleared."
                }
            }
        }
    }
}

# 2.4 Optional Core Isolation Activation
Write-Output "`n--- Core Isolation Configuration ---"
$enableHvci = Read-Host "Do you want to enforce Core Isolation (Memory Integrity) enablement now? (y/n)"
if ($enableHvci -eq "y") {
    Write-Output "[+] Enforcing final update trigger for Core Isolation (Memory Integrity)..."
    $hvciPath = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity"
    if (-not (Test-Path $hvciPath)) { New-Item -Path $hvciPath -Force | Out-Null }
    Set-ItemProperty -Path $hvciPath -Name "Enabled" -Value 1 -PropertyType DWORD -Force
    Write-Output "   [+] Core Isolation forced via Registry."
} else {
    Write-Output "[-] Core Isolation configuration left untouched."
}

Write-Output "`n========================================================="
Write-Output " PROCESS COMPLETED. Please restart your PC now."
Write-Output "========================================================="
