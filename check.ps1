# check.ps1
# Script to check PC Security Features, including ASR rules and firewall settings.
# Requires PowerShell 7+; exits if version is older.
# Requires Administrator privileges for full report.
# Reports status without modifying settings.

# Check PowerShell version
$currentPSVersion = $PSVersionTable.PSVersion.Major
$requiredPSVersion = 7
$latestPSVersion = "7.5.2" # As of July 30, 2025

if ($currentPSVersion -lt $requiredPSVersion) {
    Write-Host "⚠ ERROR: Running PowerShell version $currentPSVersion." -ForegroundColor Red
    Write-Host "This script requires PowerShell $requiredPSVersion or later." -ForegroundColor Red
    Write-Host "Please install PowerShell $latestPSVersion from https://github.com/PowerShell/PowerShell/releases or Microsoft Store." -ForegroundColor Yellow
    Write-Host "Exiting script." -ForegroundColor Red
    exit
}

Write-Host "PowerShell version $currentPSVersion detected. Proceeding with security checks..." -ForegroundColor Green

#region Helper Functions
function Write-FeatureStatus {
    Param(
        [string]$FeatureName,
        [string]$Status,
        [string]$Color = "White",
        [int]$Indent = 0
    )
    $indentString = "  " * $Indent
    $paddedName = $FeatureName.PadRight(30)
    Write-Host "$($indentString)$($paddedName): " -NoNewline
    Write-Host "$Status" -ForegroundColor $Color
}

function Get-FriendlyBooleanStatus {
    Param(
        [bool]$Value
    )
    return ($Value ? "Enabled" : "Disabled")
}

function Write-Suggestion {
    Param(
        [string]$SuggestionText,
        [int]$Indent = 0
    )
    $indentString = "  " * $Indent
    Write-Host "$($indentString)↳ SUGGESTION: $SuggestionText" -ForegroundColor Cyan
}

function Test-PendingReboot {
    $rebootPending = $false
    $regPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired"
    )
    foreach ($path in $regPaths) {
        if (Test-Path $path) {
            $rebootPending = $true
            break
        }
    }
    $pendingFileRename = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name PendingFileRenameOperations -ErrorAction SilentlyContinue
    if ($pendingFileRename) {
        $rebootPending = $true
    }
    return $rebootPending
}
#endregion

# Define ASR Rule IDs and Descriptions
$asrRuleIds = @{
    "56A863A9-875E-4185-98A7-B882C64B5CE5" = "Block vulnerable signed drivers"
    "9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2" = "Block credential stealing from lsass.exe"
    "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC" = "Block obfuscated scripts"
    "E6DB77E5-3DF2-4CF1-B95A-636979351E5B" = "Block WMI event subscription"
    "C1DB55AB-C21A-4637-BB3F-A12568109D35" = "Use advanced ransomware protection"
    "33DDEDF1-C6E0-47CB-833E-DE6133960387" = "Block Safe Mode reboot (preview)"
    "C0033C00-D16D-4114-A5A0-DC9B3A7D2CEB" = "Block impersonated system tools (preview)"
}

# Initialize arrays to store enabled and disabled features
$enabledFeatures = @()
$disabledFeatures = @()

# Get Windows Edition
try {
    $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
    $windowsEdition = $osInfo.Caption -replace "Microsoft ", ""
} catch {
    $windowsEdition = "Unknown Windows Edition"
}

# Header
Write-Host "┌──────────────────────────────────────────────────┐" -ForegroundColor Cyan
Write-Host "│      $windowsEdition Security Features Report     │" -ForegroundColor Cyan
Write-Host "└──────────────────────────────────────────────────┘" -ForegroundColor Cyan
Write-Host "Generated on: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray
Write-Host ""

# Check for Administrator Privileges
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "⚠ WARNING: Not running as Administrator. Some checks may be incomplete." -ForegroundColor Yellow
    Write-Suggestion "Run PowerShell as Administrator for a full report." 1
    Write-Host ""
}

# Check for Pending Reboot
if (Test-PendingReboot) {
    Write-Host "⚠ WARNING: A system reboot is pending. Some security features may not be fully active." -ForegroundColor Yellow
    Write-Suggestion "Restart your PC to ensure all security settings are applied." 1
    Write-Host ""
}

# 1. Hardware Security Features
Write-Host "┌──── 1. Hardware Security Features ────────────────┐" -ForegroundColor Cyan

# Secure Boot
Write-Host "├─ Secure Boot ────────────────────────────────────┤" -ForegroundColor DarkCyan
try {
    if (Get-Command -Name Confirm-SecureBootUEFI -ErrorAction SilentlyContinue) {
        $SecureBootEnabled = Confirm-SecureBootUEFI
        $status = if ($SecureBootEnabled) { "Enabled (Protects boot process)" } else { "Disabled" }
        $color = if ($SecureBootEnabled) { "Green" } else { "Red" }
        Write-FeatureStatus "Secure Boot" $status $color 1
        if ($SecureBootEnabled) { $enabledFeatures += "Secure Boot" } else { $disabledFeatures += "Secure Boot" }
        if (-not $SecureBootEnabled) {
            Write-Suggestion "Enable Secure Boot in UEFI/BIOS to protect against boot-time attacks." 2
        }
    } else {
        Write-FeatureStatus "Secure Boot" "Not Supported (Requires UEFI)" "Yellow" 1
        $disabledFeatures += "Secure Boot (Not Supported)"
        Write-Suggestion "Check if your system supports UEFI/Secure Boot in its documentation." 2
    }
}
catch {
    Write-FeatureStatus "Secure Boot" "Error: $($_.Exception.Message)" "Red" 1
    $disabledFeatures += "Secure Boot (Error)"
    Write-Suggestion "Ensure necessary modules are loaded and run as administrator." 2
}

# TPM
Write-Host "├─ Trusted Platform Module (TPM) ──────────────────┤" -ForegroundColor DarkCyan
try {
    $tpm = Get-Tpm -ErrorAction SilentlyContinue
    if ($tpm -and $tpm.TpmPresent) {
        Write-FeatureStatus "TPM Present" "Yes (Hardware security enabled)" "Green" 1
        $enabledFeatures += "TPM Present"
        $tpmEnabledStatus = (Get-FriendlyBooleanStatus $tpm.TpmEnabled)
        $tpmEnabledColor = ($tpm.TpmEnabled ? "Green" : "Red")
        Write-FeatureStatus "TPM Enabled" $tpmEnabledStatus $tpmEnabledColor 2
        if ($tpm.TpmEnabled) { $enabledFeatures += "TPM Enabled" } else { $disabledFeatures += "TPM Enabled" }
        if (-not $tpm.TpmEnabled) {
            Write-Suggestion "Enable TPM in UEFI/BIOS for secure key storage." 3
        }
        $tpmReadyStatus = (Get-FriendlyBooleanStatus $tpm.TpmReady)
        $tpmReadyColor = ($tpm.TpmReady ? "Green" : "Red")
        Write-FeatureStatus "TPM Ready" $tpmReadyStatus $tpmReadyColor 2
        if ($tpm.TpmReady) { $enabledFeatures += "TPM Ready" } else { $disabledFeatures += "TPM Ready" }
        if (-not $tpm.TpmReady -and $tpm.TpmEnabled) {
            Write-Suggestion "Provision TPM via tpm.msc for full functionality." 3
        }
        Write-FeatureStatus "TPM Version" $tpm.TPMVersion "White" 2
        Write-FeatureStatus "TPM Manufacturer" $tpm.ManufacturerIdTxt "White" 2
    } else {
        Write-FeatureStatus "TPM Present" "No" "Red" 1
        Write-FeatureStatus "TPM Status" "Not found or disabled in BIOS" "Red" 2
        $disabledFeatures += "TPM Present"
        Write-Suggestion "Verify TPM availability and enable it in UEFI/BIOS." 2
    }
}
catch {
    Write-FeatureStatus "TPM" "Error: $($_.Exception.Message)" "Red" 1
    $disabledFeatures += "TPM (Error)"
    Write-Suggestion "Ensure necessary modules are loaded and run as administrator." 2
}
Write-Host "└──────────────────────────────────────────────────┘" -ForegroundColor Cyan
Write-Host ""

# 2. System Security Features
Write-Host "┌──── 2. System Security Features ──────────────────┐" -ForegroundColor Cyan

# Device Guard / VBS
Write-Host "├─ Virtualization-based Security (VBS) ────────────┤" -ForegroundColor DarkCyan
try {
    $DeviceGuard = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction SilentlyContinue
    if ($DeviceGuard) {
        $VBSStatus = switch ($DeviceGuard.VirtualizationBasedSecurityStatus) {
            0 { "Not Configured" }
            1 { "Enabled (Not fully active)" }
            2 { "Running (Fully active)" }
            default { "Unknown" }
        }
        Write-FeatureStatus "VBS Status" $VBSStatus ($VBSStatus -eq "Running (Fully active)" ? "Green" : "Yellow") 1
        if ($VBSStatus -eq "Running (Fully active)") { $enabledFeatures += "VBS" } else { $disabledFeatures += "VBS ($VBSStatus)" }
        if ($VBSStatus -eq "Enabled (Not fully active)") {
            Write-Suggestion "Reboot to fully activate VBS and its components." 2
        } elseif ($VBSStatus -eq "Not Configured") {
            Write-Suggestion "Enable VBS for enhanced kernel isolation (requires Hyper-V, UEFI, Secure Boot, TPM)." 2
        }
        $SecurityServicesConfigured = $DeviceGuard.SecurityServicesConfigured
        $SecurityServicesRunning = $DeviceGuard.SecurityServicesRunning
        $CGConfigured = $SecurityServicesConfigured -contains 1
        $CGRunning = $SecurityServicesRunning -contains 1
        Write-FeatureStatus "Credential Guard Configured" (Get-FriendlyBooleanStatus $CGConfigured) ($CGConfigured ? "Green" : "Red") 2
        Write-FeatureStatus "Credential Guard Running" (Get-FriendlyBooleanStatus $CGRunning) ($CGRunning ? "Green" : "Red") 2
        if ($CGRunning) { $enabledFeatures += "Credential Guard" } else { $disabledFeatures += "Credential Guard" }
        if (-not $CGConfigured) {
            Write-Suggestion "Enable Credential Guard via Group Policy/Registry for credential protection." 3
        } elseif ($CGConfigured -and -not $CGRunning) {
            Write-Suggestion "Reboot to activate Credential Guard." 3
        }
        $MIConfigured = $SecurityServicesConfigured -contains 2
        $MIRunning = $SecurityServicesRunning -contains 2
        Write-FeatureStatus "Memory Integrity Configured" (Get-FriendlyBooleanStatus $MIConfigured) ($MIConfigured ? "Green" : "Red") 2
        Write-FeatureStatus "Memory Integrity Running" (Get-FriendlyBooleanStatus $MIRunning) ($MIRunning ? "Green" : "Red") 2
        if ($MIRunning) { $enabledFeatures += "Memory Integrity" } else { $disabledFeatures += "Memory Integrity" }
        if (-not $MIConfigured) {
            Write-Suggestion "Enable Memory Integrity in Windows Security > Device security > Core isolation." 3
        } elseif ($MIConfigured -and -not $MIRunning) {
            Write-Suggestion "Reboot to activate Memory Integrity." 3
        }
        $CIStatus = switch ($DeviceGuard.CodeIntegrityPolicyEnforcementStatus) {
            0 { "Off" }
            1 { "Audit Mode" }
            2 { "Enforced (Active)" }
            default { "Unknown" }
        }
        Write-FeatureStatus "Code Integrity Policy" $CIStatus ($CIStatus -eq "Enforced (Active)" ? "Green" : "Yellow") 2
        if ($CIStatus -eq "Enforced (Active)") { $enabledFeatures += "Code Integrity Policy" } else { $disabledFeatures += "Code Integrity Policy ($CIStatus)" }
        if ($CIStatus -eq "Off") {
            Write-Suggestion "Enable Code Integrity policy for stricter application control." 3
        } elseif ($CIStatus -eq "Audit Mode") {
            Write-Suggestion "Set Code Integrity policy to Enforced mode to block unsigned code." 3
        }
    } else {
        Write-FeatureStatus "VBS" "Not Supported or Hyper-V not enabled" "Yellow" 1
        $disabledFeatures += "VBS (Not Supported)"
        Write-Suggestion "Ensure Hyper-V is enabled and system supports VBS (UEFI, Secure Boot, TPM)." 2
    }
}
catch {
    Write-FeatureStatus "VBS" "Error: $($_.Exception.Message)" "Red" 1
    $disabledFeatures += "VBS (Error)"
    Write-Suggestion "Ensure necessary modules are loaded and run as administrator." 2
}

# User Account Control (UAC)
Write-Host "├─ User Account Control (UAC) ─────────────────────┤" -ForegroundColor DarkCyan
try {
    $uacReg = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -ErrorAction SilentlyContinue
    $uacStatus = switch ($uacReg.EnableLUA) {
        1 {
            switch ($uacReg.ConsentPromptBehaviorAdmin) {
                0 { "Disabled (No prompts)" }
                2 { "Enabled (Prompt for consent on secure desktop)" }
                5 { "Enabled (Prompt for credentials on secure desktop)" }
                default { "Enabled (Unknown configuration)" }
            }
        }
        0 { "Disabled (Not recommended)" }
        default { "Unknown" }
    }
    $uacColor = if ($uacStatus -like "Enabled*") { "Green" } else { "Red" }
    Write-FeatureStatus "UAC Status" $uacStatus $uacColor 1
    if ($uacStatus -like "Enabled*") { $enabledFeatures += "UAC" } else { $disabledFeatures += "UAC" }
    if ($uacStatus -like "Disabled*") {
        Write-Suggestion "Enable UAC in Control Panel > User Accounts > Change User Account Control settings." 2
    }
}
catch {
    Write-FeatureStatus "UAC" "Error: $($_.Exception.Message)" "Red" 1
    $disabledFeatures += "UAC (Error)"
    Write-Suggestion "Ensure registry access and run as administrator." 2
}

# Windows Hello
Write-Host "├─ Windows Hello ──────────────────────────────────┤" -ForegroundColor DarkCyan
try {
    $helloReg = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -ErrorAction SilentlyContinue
    $helloEnabled = (Get-CimInstance -ClassName Win32_BiometricDevice -ErrorAction SilentlyContinue) -or ($helloReg.Userinit -like "*NgcPin*")
    $helloStatus = if ($helloEnabled) { "Configured (Biometric/PIN active)" } else { "Not Configured" }
    $helloColor = if ($helloEnabled) { "Green" } else { "Yellow" }
    Write-FeatureStatus "Windows Hello" $helloStatus $helloColor 1
    if ($helloEnabled) { $enabledFeatures += "Windows Hello" } else { $disabledFeatures += "Windows Hello" }
    if (-not $helloEnabled) {
        Write-Suggestion "Set up Windows Hello PIN or biometric in Settings > Accounts > Sign-in options." 2
    }
}
catch {
    Write-FeatureStatus "Windows Hello" "Error: $($_.Exception.Message)" "Red" 1
    $disabledFeatures += "Windows Hello (Error)"
    Write-Suggestion "Ensure biometric devices or PIN settings are accessible." 2
}
Write-Host "└──────────────────────────────────────────────────┘" -ForegroundColor Cyan
Write-Host ""

# 3. Antivirus Protection
Write-Host "┌──── 3. Antivirus Protection ──────────────────────┐" -ForegroundColor Cyan

# Microsoft Defender Antivirus
Write-Host "├─ Microsoft Defender Antivirus ───────────────────┤" -ForegroundColor DarkCyan
try {
    $defenderStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
    if ($defenderStatus) {
        $avStatus = (Get-FriendlyBooleanStatus $defenderStatus.AntivirusEnabled)
        Write-FeatureStatus "Antivirus Enabled" $avStatus ($defenderStatus.AntivirusEnabled ? "Green" : "Red") 1
        if ($defenderStatus.AntivirusEnabled) { $enabledFeatures += "Defender Antivirus" } else { $disabledFeatures += "Defender Antivirus" }
        if (-not $defenderStatus.AntivirusEnabled) {
            Write-Suggestion "Enable Microsoft Defender or ensure a third-party antivirus is active." 2
        }
        $rtpStatus = (Get-FriendlyBooleanStatus $defenderStatus.RealTimeProtectionEnabled)
        Write-FeatureStatus "Real-time Protection" $rtpStatus ($defenderStatus.RealTimeProtectionEnabled ? "Green" : "Red") 2
        if ($defenderStatus.RealTimeProtectionEnabled) { $enabledFeatures += "Real-time Protection" } else { $disabledFeatures += "Real-time Protection" }
        if (-not $defenderStatus.RealTimeProtectionEnabled -and $defenderStatus.AntivirusEnabled) {
            Write-Suggestion "Enable Real-time Protection in Windows Security." 3
        }
        $defStatus = ($defenderStatus.AntivirusSignatureLastUpdated -as [datetime]).ToString("yyyy-MM-dd HH:mm:ss")
        $defColor = if ($defenderStatus.AntivirusSignatureLastUpdated -lt (Get-Date).AddDays(-7)) { "Yellow" } else { "White" }
        Write-FeatureStatus "Definition Last Updated" $defStatus $defColor 2
        if ($defenderStatus.AntivirusSignatureLastUpdated -lt (Get-Date).AddDays(-7)) {
            Write-Suggestion "Update antivirus definitions via Windows Security or Windows Update." 3
        }
    } else {
        Write-FeatureStatus "Antivirus" "Status unavailable (Third-party AV may be active)" "Yellow" 1
        $disabledFeatures += "Defender Antivirus (Status Unavailable)"
        Write-Suggestion "Ensure Microsoft Defender or a third-party antivirus is active." 2
    }
}
catch {
    Write-FeatureStatus "Antivirus" "Error: $($_.Exception.Message)" "Red" 1
    $disabledFeatures += "Defender Antivirus (Error)"
    Write-Suggestion "Ensure necessary modules are loaded and run as administrator." 2
}

# Attack Surface Reduction (ASR) Rules
Write-Host "├─ Attack Surface Reduction (ASR) Rules ───────────┤" -ForegroundColor DarkCyan
try {
    $asrSettings = Get-MpPreference -ErrorAction SilentlyContinue
    if ($asrSettings) {
        $asrRules = $asrSettings.AttackSurfaceReductionRules_Ids
        $asrActions = $asrSettings.AttackSurfaceReductionRules_Actions
        foreach ($ruleId in $asrRuleIds.Keys) {
            $ruleName = $asrRuleIds[$ruleId]
            $ruleIndex = [array]::IndexOf($asrRules, $ruleId)
            if ($ruleIndex -ge 0 -and $asrActions[$ruleIndex]) {
                $action = switch ($asrActions[$ruleIndex]) {
                    1 { "Block" }
                    2 { "Audit" }
                    6 { "Warn" }
                    default { "Unknown" }
                }
                Write-FeatureStatus $ruleName "Enabled ($action)" "Green" 1
                $enabledFeatures += "ASR: $ruleName ($action)"
            } else {
                Write-FeatureStatus $ruleName "Disabled" "Red" 1
                $disabledFeatures += "ASR: $ruleName"
            }
        }
    } else {
        Write-FeatureStatus "ASR Rules" "Status unavailable" "Yellow" 1
        $disabledFeatures += "ASR Rules (Status Unavailable)"
    }
}
catch {
    Write-FeatureStatus "ASR Rules" "Error: $($_.Exception.Message)" "Red" 1
    $disabledFeatures += "ASR Rules (Error)"
}
Write-Host "└──────────────────────────────────────────────────┘" -ForegroundColor Cyan
Write-Host ""

# 4. Network Security
Write-Host "┌──── 4. Network Security ──────────────────────────┐" -ForegroundColor Cyan

# Windows Defender Firewall
Write-Host "├─ Windows Defender Firewall ──────────────────────┤" -ForegroundColor DarkCyan
try {
    $firewallProfiles = Get-NetFirewallProfile -All -ErrorAction SilentlyContinue
    if ($firewallProfiles) {
        foreach ($profile in $firewallProfiles) {
            $profileName = $profile.Name
            $enabledStatus = (Get-FriendlyBooleanStatus $profile.Enabled)
            $enabledColor = ($profile.Enabled ? "Green" : "Red")
            Write-FeatureStatus "$profileName Profile" $enabledStatus $enabledColor 1
            if ($profile.Enabled) { $enabledFeatures += "Firewall ($profileName Profile)" } else { $disabledFeatures += "Firewall ($profileName Profile)" }
            $inboundStatus = if ($profile.DefaultInboundAction -eq "Block") { "Block" } else { "Allow" }
            $inboundColor = if ($profile.DefaultInboundAction -eq "Block") { "Green" } else { "Red" }
            Write-FeatureStatus "$profileName Inbound" $inboundStatus $inboundColor 2
            if ($profile.Enabled -and $profile.DefaultInboundAction -eq "Block") {
                $enabledFeatures += "Firewall ($profileName Profile - Inbound Block)"
            } elseif ($profile.Enabled) {
                $disabledFeatures += "Firewall ($profileName Profile - Inbound Block)"
            }
            if (-not $profile.Enabled) {
                Write-Suggestion "Enable the $profileName Firewall in Windows Security." 2
            } elseif ($profile.DefaultInboundAction -ne "Block" -and $profileName -ne "Private") {
                Write-Suggestion "Set $profileName Profile to block incoming connections in Windows Security > Firewall & network protection." 2
            }
        }
    } else {
        Write-FeatureStatus "Firewall" "Status unavailable" "Yellow" 1
        $disabledFeatures += "Firewall (Status Unavailable)"
        Write-Suggestion "Ensure the Firewall service is running." 2
    }
}
catch {
    Write-FeatureStatus "Firewall" "Error: $($_.Exception.Message)" "Red" 1
    $disabledFeatures += "Firewall (Error)"
    Write-Suggestion "Ensure necessary modules are loaded and run as administrator." 2
}
Write-Host "└──────────────────────────────────────────────────┘" -ForegroundColor Cyan
Write-Host ""

# 5. Data Protection
Write-Host "┌──── 5. Data Protection ───────────────────────────┐" -ForegroundColor Cyan

# BitLocker
Write-Host "├─ BitLocker Drive Encryption ─────────────────────┤" -ForegroundColor DarkCyan
try {
    $bitlockerVolumes = Get-BitLockerVolume -ErrorAction SilentlyContinue
    if ($bitlockerVolumes) {
        foreach ($volume in $bitlockerVolumes | Where-Object { $_.VolumeType -eq "OperatingSystem" -or $_.VolumeType -eq "FixedData" }) {
            $status = if ($volume.ProtectionStatus -eq "On") { "Encrypted" } else { "Not Encrypted" }
            $color = if ($volume.ProtectionStatus -eq "On") { "Green" } else { "Red" }
            Write-FeatureStatus "Drive $($volume.MountPoint)" $status $color 1
            if ($volume.ProtectionStatus -eq "On") { $enabledFeatures += "BitLocker (Drive $($volume.MountPoint))" } else { $disabledFeatures += "BitLocker (Drive $($volume.MountPoint))" }
            if ($volume.ProtectionStatus -ne "On") {
                Write-Suggestion "Enable BitLocker for drive $($volume.MountPoint) in Windows Security > Device security." 2
            }
        }
    } else {
        Write-FeatureStatus "BitLocker" "Not available or no fixed drives found" "Yellow" 1
        $disabledFeatures += "BitLocker (Not Available)"
        Write-Suggestion "Ensure BitLocker is supported and fixed drives are present." 2
    }
}
catch {
    Write-FeatureStatus "BitLocker" "Error: $($_.Exception.Message)" "Red" 1
    $disabledFeatures += "BitLocker (Error)"
    Write-Suggestion "Ensure necessary modules are loaded and run as administrator." 2
}
Write-Host "└──────────────────────────────────────────────────┘" -ForegroundColor Cyan
Write-Host ""

# 6. Update Management
Write-Host "┌──── 6. Update Management ─────────────────────────┐" -ForegroundColor Cyan

# Windows Update
Write-Host "├─ Windows Update ─────────────────────────────────┤" -ForegroundColor DarkCyan
try {
    $wuService = Get-Service -Name wuauserv -ErrorAction SilentlyContinue
    $wuStatus = if ($wuService.Status -eq "Running") { "Enabled (Automatic updates active)" } else { "Disabled or Stopped" }
    $wuColor = if ($wuService.Status -eq "Running") { "Green" } else { "Red" }
    Write-FeatureStatus "Update Service" $wuStatus $wuColor 1
    if ($wuService.Status -eq "Running") { $enabledFeatures += "Windows Update Service" } else { $disabledFeatures += "Windows Update Service" }
    if ($wuService.Status -ne "Running") {
        Write-Suggestion "Start the Windows Update service (wuauserv) in Services." 2
    }
    $lastCheck = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "LastUpdateCheckTime" -ErrorAction SilentlyContinue
    $lastCheckStatus = if ($lastCheck) { ([datetime]$lastCheck.LastUpdateCheckTime).ToString("yyyy-MM-dd HH:mm:ss") } else { "Unknown" }
    $lastCheckColor = if ($lastCheck -and ([datetime]$lastCheck.LastUpdateCheckTime -gt (Get-Date).AddDays(-7))) { "White" } else { "Yellow" }
    Write-FeatureStatus "Last Update Check" $lastCheckStatus $lastCheckColor 1
    if ($lastCheckStatus -eq "Unknown" -or ([datetime]$lastCheck.LastUpdateCheckTime -lt (Get-Date).AddDays(-7))) {
        Write-Suggestion "Check for updates in Settings > Windows Update." 2
    }
}
catch {
    Write-FeatureStatus "Windows Update" "Error: $($_.Exception.Message)" "Red" 1
    $disabledFeatures += "Windows Update (Error)"
    Write-Suggestion "Ensure necessary modules are loaded and run as administrator." 2
}
Write-Host "└──────────────────────────────────────────────────┘" -ForegroundColor Cyan
Write-Host ""

# 7. Summary of Security Features
Write-Host "┌──── 7. Security Features Summary ─────────────────┐" -ForegroundColor Cyan
Write-Host "├─ Enabled Features ───────────────────────────────┤" -ForegroundColor DarkCyan
if ($enabledFeatures.Count -eq 0) {
    Write-Host "  None" -ForegroundColor Yellow
} else {
    foreach ($feature in $enabledFeatures) {
        Write-Host "  $feature" -ForegroundColor Green
    }
}
Write-Host "├─ Disabled/Not Configured Features ──────────────┤" -ForegroundColor DarkCyan
if ($disabledFeatures.Count -eq 0) {
    Write-Host "  None" -ForegroundColor Green
} else {
    foreach ($feature in $disabledFeatures) {
        Write-Host "  $feature" -ForegroundColor Red
    }
}
Write-Host "└──────────────────────────────────────────────────┘" -ForegroundColor Cyan
Write-Host ""

# Footer
Write-Host "┌──────────────────────────────────────────────────┐" -ForegroundColor Cyan
Write-Host "│          Security Features Report Complete        │" -ForegroundColor Cyan
Write-Host "└──────────────────────────────────────────────────┘" -ForegroundColor Cyan