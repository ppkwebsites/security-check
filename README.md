Descriptioncheck.ps1 is a PowerShell script designed to assess and report the status of key security features on a Windows system, ensuring a robust security posture for general use cases such as browsing, gaming, and LAN file transfers. It verifies that PowerShell 7 or later is running (exiting with an installation prompt if an older version is detected) and generates a detailed report covering hardware, system, antivirus, network, data protection, and update management security settings.FeaturesPowerShell Version Check: Ensures the script runs on PowerShell 7 or later (tested with 7.5.2). If an older version (e.g., Windows PowerShell 5.1) is detected, it exits with instructions to install PowerShell 7.5.2 from GitHub or the Microsoft Store.
Comprehensive Security Report: Evaluates and displays the status of:Hardware Security:Secure Boot (protects boot process).
Trusted Platform Module (TPM) presence, enablement, readiness, version, and manufacturer.

System Security:Virtualization-based Security (VBS) status, including Credential Guard, Memory Integrity, and Code Integrity Policy.
User Account Control (UAC) configuration.
Windows Hello (biometric/PIN authentication).

Antivirus Protection:Microsoft Defender Antivirus (enabled status, real-time protection, definition updates).
Attack Surface Reduction (ASR) rules, including seven key rules:Block abuse of exploited vulnerable signed drivers.
Block credential stealing from lsass.exe.
Block execution of potentially obfuscated scripts.
Block persistence through WMI event subscription.
Use advanced ransomware protection.
Block rebooting machine in Safe Mode (preview).
Block use of copied or impersonated system tools (preview).

Network Security:Windows Defender Firewall status for Domain, Public, and Private profiles, including inbound connection settings (noting Private profile’s “Allow” for SMB file sharing).

Data Protection:BitLocker Drive Encryption status for operating system and fixed data drives.

Update Management:Windows Update service status and last update check timestamp.

Administrator Check: Warns if not run with administrative privileges, as some checks (e.g., ASR, BitLocker) require elevated access.
Pending Reboot Detection: Alerts if a system reboot is pending, which may affect security feature activation.
User-Friendly Output: Formats the report with clear sections, color-coded status indicators (Green for enabled, Red for disabled, Yellow for warnings), and actionable suggestions for disabled features.
No Modifications: Reports status without altering system settings, ensuring safe diagnostics.

UsagePrerequisites:PowerShell 7.5.2 or later (download from GitHub or Microsoft Store).
Windows 11 (tested on IoT Enterprise LTSC; compatible with other editions).
Administrative privileges recommended for complete reporting.

Running the Script:powershell

cd C:\Path\To\Script
.\check.ps1

If script execution is restricted, set the execution policy:powershell

Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned

Output:Displays a formatted report of security features, e.g.:

PowerShell version 7 detected. Proceeding with security checks...
┌──────────────────────────────────────────────────┐
│      Windows 11 IoT Enterprise Security Features Report     │
└──────────────────────────────────────────────────┘
...
├─ Attack Surface Reduction (ASR) Rules ───────────┤
  Block vulnerable signed drivers: Disabled
  Block credential stealing from lsass.exe: Disabled
  Block obfuscated scripts: Disabled
  Block WMI event subscription: Enabled (Block)
  Use advanced ransomware protection: Disabled
  Block Safe Mode reboot (preview): Disabled
  Block impersonated system tools (preview): Disabled
...
┌──── 7. Security Features Summary ─────────────────┐
...

Includes suggestions for enabling disabled features.

Optional: Use the companion Enable-ASRRules.ps1 script to enable the seven ASR rules in Block mode (requires administrative privileges).

CompatibilityPowerShell: 7.0 or later (tested with 7.5.2).
Operating System: Windows 11 IoT Enterprise LTSC (compatible with other Windows 11/10 editions).
Use Case: Optimized for systems used for browsing, gaming, and LAN file transfers (e.g., SMB sharing with Private profile inbound “Allow”).

NotesRun as Administrator for accurate reporting of features like ASR and BitLocker.
If PowerShell version is below 7, the script exits with a prompt to install PowerShell 7.5.2.
Check Enable-ASRRules.ps1 for enabling ASR rules if the report shows them as disabled.
Logs for ASR configuration (if using Enable-ASRRules.ps1) are saved to ASR-Log.txt.

