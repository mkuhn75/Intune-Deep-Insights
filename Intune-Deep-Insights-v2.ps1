#Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.DeviceManagement

<#
.SYNOPSIS
    HP Intune Device Report v2 – OS Drilldown, BIOS comparison per model via HP CMSL
.DESCRIPTION
    - OS pie chart: click on segment → drilldown with exact build numbers
    - BIOS section: per device model, with latest available version (HP CMSL)
    - BIOS status badge: Current / Outdated / Unknown
    - Compliance, table, CSV export – same as v1
.PARAMETER OutputPath
    Path to the HTML output file. Default: .\HP-Intune-Report-v2.html
.PARAMETER MaxDevices
    Maximum number of devices (0 = all). Useful for testing.
.PARAMETER SkipBiosLookup
    Skip BIOS lookup via HP CMSL (faster, no internet required).
.EXAMPLE
    .\Get-IntuneHPReport-v2.ps1
    .\Get-IntuneHPReport-v2.ps1 -SkipBiosLookup         # without internet / CMSL
    .\Get-IntuneHPReport-v2.ps1 -SkipComplianceDetails  # without compliance causes (faster)
    .\Get-IntuneHPReport-v2.ps1 -MaxDevices 50           # test run
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$CustomerShortname,
    [string]$OutputPath          = "",
    [int]   $MaxDevices          = 0,
    [switch]$SkipBiosLookup,
    [switch]$SkipComplianceDetails,
    [switch]$SetupSecureBootScript,  # Creates Proactive Remediation for Secure Boot Cert status
    [switch]$SetupBiosScript         # Creates Proactive Remediation for BIOS version (WMI)
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $OutputPath = ".\$CustomerShortname-Intune-Deep-Insights-$(Get-Date -Format 'yyyy-MM-dd').html"
}

#region ── Helper functions ────────────────────────────────────────────────────

function Write-Status {
    param([string]$Msg, [string]$Color = "Cyan")
    Write-Host "  [$(Get-Date -Format 'HH:mm:ss')] $Msg" -ForegroundColor $Color
}

function Get-WindowsBuildFriendlyName {
    param([string]$V)
    $map = [ordered]@{
        "10.0.26200" = @{ Name="Windows 11 25H2"; Build="26200"; ReleaseDate="Oct 2025" }
        "10.0.26100" = @{ Name="Windows 11 24H2"; Build="26100"; ReleaseDate="Oct 2024" }
        "10.0.22631" = @{ Name="Windows 11 23H2"; Build="22631"; ReleaseDate="Oct 2023" }
        "10.0.22621" = @{ Name="Windows 11 22H2"; Build="22621"; ReleaseDate="Sep 2022" }
        "10.0.22000" = @{ Name="Windows 11 21H2"; Build="22000"; ReleaseDate="Oct 2021" }
        "10.0.19045" = @{ Name="Windows 10 22H2"; Build="19045"; ReleaseDate="Oct 2022" }
        "10.0.19044" = @{ Name="Windows 10 21H2"; Build="19044"; ReleaseDate="Nov 2021" }
        "10.0.19043" = @{ Name="Windows 10 21H1"; Build="19043"; ReleaseDate="May 2021" }
        "10.0.19042" = @{ Name="Windows 10 20H2"; Build="19042"; ReleaseDate="Oct 2020" }
        "10.0.19041" = @{ Name="Windows 10 2004"; Build="19041"; ReleaseDate="May 2020" }
        "10.0.18363" = @{ Name="Windows 10 1909"; Build="18363"; ReleaseDate="Nov 2019" }
    }
    if ([string]::IsNullOrWhiteSpace($V)) { return @{ Name="Unknown"; Build="?"; ReleaseDate="" } }
    foreach ($key in $map.Keys) {
        if ($V.StartsWith($key)) { return $map[$key] }
    }
    if ($V -match '10\.0\.(\d+)\.(\d+)') { return @{ Name="Windows Build $($Matches[1])"; Build=$Matches[1]; ReleaseDate="" } }
    if ($V -match '10\.0\.(\d+)')         { return @{ Name="Windows Build $($Matches[1])"; Build=$Matches[1]; ReleaseDate="" } }
    return @{ Name=$V; Build=$V; ReleaseDate="" }
}

function Get-NormalizedBiosVersion {
    param([string]$Raw)
    if ([string]::IsNullOrWhiteSpace($Raw)) { return "Unknown" }
    if ($Raw -match 'Ver\.\s*([\d.]+)')   { return $Matches[1] }
    if ($Raw -match '([\d]{1,2}\.\d{2}\.\d{2})') { return $Matches[1] }
    return $Raw.Trim()
}

function Compare-Versions {
    param([string]$Installed, [string]$Latest)
    if ($Installed -eq "Unknown" -or $Latest -eq "Unknown" -or [string]::IsNullOrWhiteSpace($Latest)) {
        return "unknown"
    }
    try {
        $i = [version]$Installed
        $l = [version]$Latest
        if ($i -ge $l) { return "current" } else { return "outdated" }
    } catch { return "unknown" }
}

function Invoke-IntuneReport {
    param([string]$Action, [string[]]$Select = @(), [string]$Filter = "", [int]$Top = 50000)
    $tmpFile = [System.IO.Path]::GetTempFileName()
    try {
        # Build JSON manually — ConvertTo-Json turns @() into null, API rejects that
        $selJson  = if ($Select.Count -gt 0) { '["' + ($Select -join '","') + '"]' } else { '[]' }
        $filEsc   = $Filter -replace '\\', '\\' -replace '"', '\"'
        $bodyJson = "{`"filter`":`"$filEsc`",`"select`":$selJson,`"skip`":0,`"top`":$Top}"
        Write-Status "    POST reports/$Action  body=$bodyJson" "DarkGray"
        Invoke-MgGraphRequest `
            -Uri "https://graph.microsoft.com/beta/deviceManagement/reports/$Action" `
            -Method POST -Body $bodyJson -ContentType "application/json" `
            -OutputFilePath $tmpFile -ErrorAction Stop
        $raw = [System.IO.File]::ReadAllText($tmpFile)
        return $raw | ConvertFrom-Json
    } catch {
        throw
    } finally {
        Remove-Item $tmpFile -Force -ErrorAction SilentlyContinue
    }
}

#endregion

#region ── Graph authentication ───────────────────────────────────────────────

$graphScopes = @(
    "DeviceManagementManagedDevices.Read.All",
    "DeviceManagementApps.Read.All",
    "DeviceManagementConfiguration.Read.All",
    "DeviceManagementScripts.Read.All"
)
if ($SetupSecureBootScript -or $SetupBiosScript) {
    $graphScopes += "DeviceManagementScripts.ReadWrite.All"
}

Write-Status "Connecting to Microsoft Graph..." "Yellow"
try {
    Connect-MgGraph -Scopes $graphScopes -ErrorAction Stop
    Write-Status "Connected." "Green"
    $tenantName  = try {
        (Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/v1.0/organization?`$select=displayName" -Method GET -ErrorAction Stop).value[0].displayName
    } catch { $CustomerShortname }
    $runningUser = try { (Get-MgContext -ErrorAction Stop).Account } catch { [System.Security.Principal.WindowsIdentity]::GetCurrent().Name }
} catch {
    Write-Host "`n  ERROR: $_" -ForegroundColor Red
    Write-Host "  Installation command: Install-Module Microsoft.Graph -Scope CurrentUser -Force" -ForegroundColor Yellow
    exit 1
}

#endregion

#region ── SetupSecureBootScript ─────────────────────────────────────────────

if ($SetupSecureBootScript) {
    Write-Status "Creating Proactive Remediation for Secure Boot Certificate status..." "Yellow"

    # Detection script — reads HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing
    # Outputs: "Up to date" / "Not up to date" / "Not applicable"
    $detectionScript = @'
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing"

# Check if Secure Boot is supported at all
$secureBootStatus = $null
try {
    $secureBootStatus = Confirm-SecureBootUEFI -ErrorAction SilentlyContinue
} catch {}

if ($null -eq $secureBootStatus) {
    Write-Output "Not applicable"
    exit 0
}

# Check registry key for servicing status
if (-not (Test-Path $regPath)) {
    # Key absent = certificate is current (no servicing required)
    Write-Output "Up to date"
    exit 0
}

$props = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue

# If ServicingRequired value is present and non-zero → needs update
if ($null -ne $props -and $null -ne $props.ServicingRequired -and $props.ServicingRequired -ne 0) {
    Write-Output "Not up to date"
    exit 1
} else {
    Write-Output "Up to date"
    exit 0
}
'@

    # Remediation script — just a no-op exit 0 (detection-only)
    $remediationScript = @'
# No automated remediation for Secure Boot certificate — manual Windows Update required
exit 0
'@

    $detectionB64    = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($detectionScript))
    $remediationB64  = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($remediationScript))

    $scriptName = "HP Report - Secure Boot Certificate Status"
    $description = "Detects whether the Secure Boot Servicing Certificate is current. Output: Up to date / Not up to date / Not applicable"

    # Check if script already exists
    Write-Status "  Checking if script already exists..." "DarkCyan"
    $existingScripts = @()
    try {
        $existingScripts = @((Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceHealthScripts?`$select=id,displayName" -Method GET -ErrorAction Stop).value)
    } catch {
        Write-Host "  ERROR retrieving existing scripts: $_" -ForegroundColor Red
        exit 1
    }

    $existing = $existingScripts | Where-Object { $_.displayName -eq $scriptName }

    if ($existing) {
        Write-Status "  Script '$scriptName' already exists (ID: $($existing.id))." "Green"
        $scriptId = $existing.id
    } else {
        Write-Status "  Creating new Health Script..." "DarkCyan"

        $bodyObj = @{
            displayName                    = $scriptName
            description                    = $description
            publisher                      = "IT Department"
            runAs32Bit                     = $false
            runAsAccount                   = "system"
            enforceSignatureCheck          = $false
            detectionScriptContent         = $detectionB64
            remediationScriptContent       = $remediationB64
            roleScopeTagIds                = @()
        }
        $bodyJson = $bodyObj | ConvertTo-Json -Depth 5 -Compress

        try {
            $created = Invoke-MgGraphRequest `
                -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceHealthScripts" `
                -Method POST -Body $bodyJson -ContentType "application/json" -ErrorAction Stop
            $scriptId = $created.id
            Write-Status "  Script created. ID: $scriptId" "Green"
        } catch {
            Write-Host "  ERROR creating script: $_" -ForegroundColor Red
            exit 1
        }
    }

    # Assign to All Devices
    Write-Status "  Assigning script to all devices..." "DarkCyan"
    $assignBody = @{
        deviceHealthScriptAssignments = @(
            @{
                target = @{
                    "@odata.type" = "#microsoft.graph.allDevicesAssignmentTarget"
                }
                runRemediationScript = $false
                runSchedule = @{
                    "@odata.type"  = "#microsoft.graph.deviceHealthScriptDailySchedule"
                    interval       = 1
                    useUtc         = $false
                    time           = "02:00:00"
                }
            }
        )
    }
    $assignJson = $assignBody | ConvertTo-Json -Depth 10 -Compress

    try {
        Invoke-MgGraphRequest `
            -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceHealthScripts/$scriptId/assign" `
            -Method POST -Body $assignJson -ContentType "application/json" -ErrorAction Stop
        Write-Status "  Assignment successful." "Green"
    } catch {
        Write-Host "  WARNING: Assignment failed: $_" -ForegroundColor Yellow
        Write-Host "  Please assign the script manually to devices in Intune." -ForegroundColor Yellow
    }

    Write-Host ""
    Write-Host "  ╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "  ║  Secure Boot Health Script was set up successfully!         ║" -ForegroundColor Cyan
    Write-Host "  ╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
    Write-Host "  ║  Script name: $scriptName" -ForegroundColor Cyan
    Write-Host "  ║  Script ID:   $scriptId" -ForegroundColor Cyan
    Write-Host "  ╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
    Write-Host "  ║  Next steps:                                                ║" -ForegroundColor Yellow
    Write-Host "  ║  1. Wait 24-48h for devices to run the script.             ║" -ForegroundColor Yellow
    Write-Host "  ║  2. Then run the report without -SetupSecureBootScript:     ║" -ForegroundColor Yellow
    Write-Host "  ║     .\Get-IntuneHPReport-v2.ps1                            ║" -ForegroundColor Yellow
    Write-Host "  ║  3. The SB certificate donut chart will then be populated.  ║" -ForegroundColor Yellow
    Write-Host "  ╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""

    Disconnect-MgGraph
    exit 0
}

#endregion

#region ── SetupBiosScript ───────────────────────────────────────────────────

if ($SetupBiosScript) {
    Write-Status "Creating Proactive Remediation for BIOS version..." "Yellow"

    # Detection script — reads BIOS version + HP SysID via WMI and outputs them
    # Output format:  BIOS:<SMBIOSBIOSVersion>
    #                 SYSID:<Win32_BaseBoard.Product>   (optional, HP-specific)
    $detectionScript = @'
# Only run on HP devices
$manufacturer = $null
try { $manufacturer = (Get-WmiObject -Class Win32_ComputerSystem -ErrorAction Stop).Manufacturer.Trim() } catch {}
if ($manufacturer -notmatch 'HP|Hewlett') {
    Write-Output "NOT_HP:$manufacturer"
    exit 0
}

$bios  = $null
$sysId = $null
$model = $null
try { $bios  = (Get-WmiObject -Class Win32_BIOS -ErrorAction Stop).SMBIOSBIOSVersion.Trim()          } catch {}
try { $sysId = (Get-WmiObject -Class Win32_BaseBoard -ErrorAction Stop).Product.Trim()               } catch {}
try { $model = (Get-WmiObject -Class Win32_ComputerSystem -ErrorAction Stop).Model.Trim()            } catch {}
if ([string]::IsNullOrWhiteSpace($bios)) { $bios = "Unknown" }
# BIOS must be the last line — some API fields (scriptOutput) return only the last output line
$lines = @()
if (-not [string]::IsNullOrWhiteSpace($sysId)) { $lines += "SYSID:$sysId" }
if (-not [string]::IsNullOrWhiteSpace($model)) { $lines += "MODEL:$model" }
$lines += "BIOS:$bios"
Write-Output ($lines -join "`n")
exit 0
'@

    $remediationScript = @'
exit 0
'@

    $detectionB64   = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($detectionScript))
    $remediationB64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($remediationScript))

    $scriptName  = "HP Report - BIOS Version"
    $description = "Reads BIOS version and HP SysID via WMI. Output: BIOS:<Version> / SYSID:<ProductId>"
    $publisher   = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name -replace '^.*\\',''

    # Resolve group ID for G_SEC_DEV_Windows
    $targetGroupName = "G_SEC_DEV_Windows"
    $targetGroupId   = $null
    Write-Status "  Searching for group '$targetGroupName'..." "DarkCyan"
    try {
        $grpResp = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/v1.0/groups?`$filter=displayName eq '$targetGroupName'&`$select=id,displayName" -Method GET -ErrorAction Stop
        $targetGroupId = @($grpResp.value)[0].id
        if ($targetGroupId) {
            Write-Status "  Group found: $targetGroupId" "DarkGreen"
        } else {
            Write-Host "  WARNING: Group '$targetGroupName' not found — assigning to 'All Devices'." -ForegroundColor Yellow
        }
    } catch {
        Write-Host "  WARNING: Group search failed: $_ — assigning to 'All Devices'." -ForegroundColor Yellow
    }

    Write-Status "  Checking if script already exists..." "DarkCyan"
    $existingScripts = @()
    try {
        $existingScripts = @((Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceHealthScripts?`$select=id,displayName" -Method GET -ErrorAction Stop).value)
    } catch {
        Write-Host "  ERROR retrieving existing scripts: $_" -ForegroundColor Red
        exit 1
    }

    $existing = $existingScripts | Where-Object { $_.displayName -eq $scriptName }

    if ($existing) {
        Write-Status "  Script '$scriptName' already exists — updating content..." "DarkCyan"
        $scriptId  = $existing.id
        $patchBody = @{
            publisher                = $publisher
            detectionScriptContent   = $detectionB64
            remediationScriptContent = $remediationB64
        } | ConvertTo-Json -Depth 5 -Compress
        try {
            Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceHealthScripts/$scriptId" -Method PATCH -Body $patchBody -ContentType "application/json" -ErrorAction Stop
            Write-Status "  Script content updated." "Green"
        } catch {
            Write-Host "  WARNING: Script update failed: $_" -ForegroundColor Yellow
        }
    } else {
        Write-Status "  Creating new Health Script..." "DarkCyan"
        $bodyObj = @{
            displayName              = $scriptName
            description              = $description
            publisher                = $publisher
            runAs32Bit               = $false
            runAsAccount             = "system"
            enforceSignatureCheck    = $false
            detectionScriptContent   = $detectionB64
            remediationScriptContent = $remediationB64
            roleScopeTagIds          = @()
        }
        $bodyJson = $bodyObj | ConvertTo-Json -Depth 5 -Compress
        try {
            $created  = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceHealthScripts" -Method POST -Body $bodyJson -ContentType "application/json" -ErrorAction Stop
            $scriptId = $created.id
            Write-Status "  Script created. ID: $scriptId" "Green"
        } catch {
            Write-Host "  ERROR creating script: $_" -ForegroundColor Red
            exit 1
        }
    }

    # Build assignment target — group if found, fallback to all devices
    $assignTarget = if ($targetGroupId) {
        @{ "@odata.type" = "#microsoft.graph.groupAssignmentTarget"; groupId = $targetGroupId }
    } else {
        @{ "@odata.type" = "#microsoft.graph.allDevicesAssignmentTarget" }
    }

    Write-Status "  Assigning script to '$($targetGroupId ? $targetGroupName : 'All Devices')' (hourly)..." "DarkCyan"
    $assignBody = @{
        deviceHealthScriptAssignments = @(
            @{
                target               = $assignTarget
                runRemediationScript = $false
                runSchedule          = @{
                    "@odata.type" = "#microsoft.graph.deviceHealthScriptHourlySchedule"
                    interval      = 1
                }
            }
        )
    }
    try {
        Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceHealthScripts/$scriptId/assign" -Method POST -Body ($assignBody | ConvertTo-Json -Depth 10 -Compress) -ContentType "application/json" -ErrorAction Stop
        Write-Status "  Assignment successful." "Green"
    } catch {
        Write-Host "  WARNING: Assignment failed: $_" -ForegroundColor Yellow
        Write-Host "  Please assign the script manually to devices in Intune." -ForegroundColor Yellow
    }

    Write-Host ""
    Write-Host "  ╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "  ║  BIOS Health Script was set up successfully!                ║" -ForegroundColor Cyan
    Write-Host "  ╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
    Write-Host "  ║  Script name: $scriptName" -ForegroundColor Cyan
    Write-Host "  ║  Script ID:   $scriptId" -ForegroundColor Cyan
    Write-Host "  ╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
    Write-Host "  ║  Next steps:                                                ║" -ForegroundColor Yellow
    Write-Host "  ║  1. Wait 24-48h for devices to run the script.             ║" -ForegroundColor Yellow
    Write-Host "  ║  2. Then run the report normally:                           ║" -ForegroundColor Yellow
    Write-Host "  ║     .\Get-IntuneHPReport-v2.ps1                            ║" -ForegroundColor Yellow
    Write-Host "  ║  3. BiosInstalled will then be read from the script output. ║" -ForegroundColor Yellow
    Write-Host "  ╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""

    Disconnect-MgGraph
    exit 0
}

#endregion

#region ── Fetch device data ───────────────────────────────────────────────────

Write-Status "Querying HP devices from Intune..."

$select = "id,deviceName,manufacturer,model,osVersion," +
          "complianceState,lastSyncDateTime,userDisplayName,userPrincipalName,serialNumber," +
          "hardwareInformation,deviceHealthAttestationState"

$allRaw = [System.Collections.Generic.List[PSCustomObject]]::new()
$url    = "https://graph.microsoft.com/beta/deviceManagement/managedDevices?`$filter=manufacturer eq 'HP' and operatingSystem eq 'Windows'&`$select=$select&`$top=999"
$page   = 0
do {
    $page++
    Write-Status "  Page $page..." "DarkCyan"
    $resp = Invoke-MgGraphRequest -Uri $url -Method GET
    foreach ($d in $resp.value) { $allRaw.Add([PSCustomObject]$d) }
    $url = $resp['@odata.nextLink']
    if ($MaxDevices -gt 0 -and $allRaw.Count -ge $MaxDevices) { break }
} while ($url)

if ($MaxDevices -gt 0) { $allRaw = $allRaw | Select-Object -First $MaxDevices }
Write-Status "Found: $($allRaw.Count) HP devices" "Green"

if ($allRaw.Count -eq 0) {
    Write-Host "  WARNING: No HP devices found." -ForegroundColor Yellow
    Disconnect-MgGraph; exit 0
}

# ── BIOS diagnostics: show hardwareInformation fields of the first device ──────
$diagDev = $allRaw[0]
if ($diagDev.hardwareInformation) {
    $hwInfo = $diagDev.hardwareInformation
    $hwType = $hwInfo.GetType().Name
    Write-Status "BIOS diagnostics ($($diagDev.deviceName ?? 'Device 1'), hardwareInformation type: $hwType)" "Magenta"
    $biosRelated = @('systemManagementBIOSVersion','biosVersion','firmwareVersion','tpmSpecificationVersion','tpmVersion','systemProductId','productName','osBuildNumber')
    foreach ($field in $biosRelated) {
        $val = try { $hwInfo[$field] } catch { $null }
        if ($null -eq $val) { $val = try { $hwInfo.$field } catch { $null } }
        Write-Status "  $field = $(if ($null -ne $val) { $val } else { '(null)' })" "DarkMagenta"
    }
} else {
    Write-Status "BIOS diagnostics: hardwareInformation is NULL for '$($diagDev.deviceName ?? 'Device 1')' — no BIOS field available." "Red"
    Write-Status "  Possible cause: missing permission or device not yet fully synchronized." "DarkRed"
}

#endregion

#region ── Process data ─────────────────────────────────────────────────────────

Write-Status "Processing device data..."

$processed = $allRaw | ForEach-Object {
    $osRaw    = $_.osVersion ?? ""
    $osInfo   = Get-WindowsBuildFriendlyName -V $osRaw
    $biosRaw  = ""
    if ($_.hardwareInformation) {
        $hw = $_.hardwareInformation
        # Graph API beta field names tried in order of likelihood
        foreach ($f in @('systemManagementBIOSVersion','biosVersion','firmwareVersion')) {
            $v = try { $hw[$f] } catch { $null }
            if ($null -eq $v) { $v = try { $hw.$f } catch { $null } }
            if (-not [string]::IsNullOrWhiteSpace($v)) { $biosRaw = "$v"; break }
        }
    }
    $biosNorm = Get-NormalizedBiosVersion -Raw $biosRaw
    $lastSync = if ($_.lastSyncDateTime) { [datetime]$_.lastSyncDateTime } else { $null }
    $daysSince = if ($lastSync) { [int]([datetime]::UtcNow - $lastSync.ToUniversalTime()).TotalDays } else { 999 }

    # SysID from hardwareInformation.systemProductId (preferred) or mapping table
    $sysIdFromHw = if ($_.hardwareInformation) { $_.hardwareInformation['systemProductId'] ?? "" } else { "" }

    # Intune sometimes returns "HP EliteBook 840 G9 Notebook PC" — shorten for knownSysIds lookup
    $modelNorm = ($_.model ?? "Unknown").Trim() -replace '\s+(Notebook|Desktop|Mobile Workstation)\s+PC$','' -replace '\s+PC$',''

    [PSCustomObject]@{
        DeviceName    = $_.deviceName     ?? "Unknown"
        Model         = $modelNorm
        SysId         = $sysIdFromHw
        OSFriendly    = $osInfo.Name
        OSBuild       = $osInfo.Build
        OSReleaseDate = $osInfo.ReleaseDate
        OSRaw         = $osRaw
        BiosInstalled = $biosNorm
        BiosLatest    = ""          # populated during BIOS lookup
        BiosStatus    = "unknown"   # current / outdated / unknown
        Compliance    = switch ($_.complianceState) {
            "compliant"     { "Compliant" }
            "noncompliant"  { "Non-compliant" }
            "conflict"      { "Conflict" }
            "error"         { "Error" }
            "inGracePeriod" { "Grace Period" }
            default         { "Unknown" }
        }
        User          = $_.userDisplayName ?? $_.userPrincipalName ?? "No user"
        LastSync      = if ($lastSync) { $lastSync.ToString("dd.MM.yyyy HH:mm") } else { "Never" }
        DaysSince     = $daysSince
        Serial           = $_.serialNumber ?? ""
        Id               = $_.id ?? ""
        ComplianceIssues = [object[]]@()  # populated during compliance lookup
        CertStatus       = "Unknown"    # populated during Secure Boot Cert lookup
        SecureBoot       = if ($_.hardwareInformation -and $null -ne $_.hardwareInformation['secureBootEnabled']) {
                               if ($_.hardwareInformation['secureBootEnabled']) { "Enabled" } else { "Disabled" }
                           } elseif ($_.deviceHealthAttestationState -and $null -ne $_.deviceHealthAttestationState['secureBoot']) {
                               if ($_.deviceHealthAttestationState['secureBoot'] -eq 'enabled') { "Enabled" } else { "Disabled" }
                           } elseif ($osRaw -match '^10\.0\.(22|26)') {
                               "Enabled"   # Windows 11 requires Secure Boot
                           } else { "Unknown" }
        Encrypted        = if ($_.hardwareInformation -and $null -ne $_.hardwareInformation['isEncrypted']) {
                               if ($_.hardwareInformation['isEncrypted']) { "Encrypted" } else { "Not encrypted" }
                           } else { "Unknown" }
    }
}

#endregion

#region ── BIOS version from Health Script (Proactive Remediation) ────────────

$knownSysIds = @{}  # populated further below with known mappings

Write-Status "Querying BIOS version (Health Script)..." "Yellow"

$biosInstalledMap   = @{}   # deviceId → normalized BIOS version string
$biosScriptSysIdMap = @{}   # deviceId → SysID from WMI (for CMSL fallback)

try {
    $hsUrl       = "https://graph.microsoft.com/beta/deviceManagement/deviceHealthScripts?`$select=id,displayName,description"
    $biosHScripts = @()
    do {
        $hsResp       = Invoke-MgGraphRequest -Uri $hsUrl -Method GET -ErrorAction Stop
        $biosHScripts += @($hsResp.value | Where-Object {
            $_.displayName -match 'HP Report.*BIOS|BIOS.*Version|BIOS.*Inventory' -or
            $_.description -match 'SMBIOSBIOSVersion|BIOS.*WMI|Win32_BIOS'
        })
        $hsUrl = $hsResp['@odata.nextLink']
    } while ($hsUrl)

    Write-Status "  BIOS Health Scripts found: $($biosHScripts.Count)" "DarkCyan"

    if ($biosHScripts.Count -eq 0) {
        Write-Status "  NOTE: No matching Health Script found. All scripts:" "DarkYellow"
        $hsUrl2 = "https://graph.microsoft.com/beta/deviceManagement/deviceHealthScripts?`$select=id,displayName"
        $allHs  = @((Invoke-MgGraphRequest -Uri $hsUrl2 -Method GET -ErrorAction SilentlyContinue).value)
        foreach ($s in $allHs) { Write-Status "    - $($s.displayName)" "DarkGray" }
    }

    foreach ($hs in $biosHScripts) {
        Write-Status "    Script: $($hs.displayName) (ID: $($hs.id))" "DarkCyan"
        # No $select here — combining $select + $expand causes preRemediationDetectionScriptOutput to return empty
        $runUrl = "https://graph.microsoft.com/beta/deviceManagement/deviceHealthScripts/$($hs.id)/deviceRunStates?`$expand=managedDevice(`$select=id,deviceName)&`$top=999"
        $runCount = 0
        $diagCount = 0
        do {
            $runResp = Invoke-MgGraphRequest -Uri $runUrl -Method GET -ErrorAction Stop
            # RAW DIAGNOSTICS: show all fields of the first entry
            if ($runCount -eq 0 -and @($runResp.value).Count -gt 0) {
                $firstRaw = @($runResp.value)[0]
                Write-Status "  RAW fields in first RunState:" "Magenta"
                foreach ($k in $firstRaw.Keys) {
                    $val = "$($firstRaw[$k])"
                    Write-Status "    $k = $($val.Substring(0,[Math]::Min(120,$val.Length)))" "Magenta"
                }
            }
            $runCount += @($runResp.value).Count
            foreach ($r in @($runResp.value)) {
                $devId = if ($r.managedDevice -and $r.managedDevice.id) { $r.managedDevice.id } else { $null }
                if (-not $devId) { continue }
                # Graph API returns preRemediationDetectionScriptOutput or scriptOutput depending on version
                $rawOut = $r.preRemediationDetectionScriptOutput
                if ([string]::IsNullOrWhiteSpace($rawOut)) { $rawOut = $r.scriptOutput }
                if ([string]::IsNullOrWhiteSpace($rawOut)) { $rawOut = $r.preRemediationDetectionScriptError }
                $out = "$rawOut" -replace '\r\n',"`n" -replace '\r',"`n"
                # Diagnose first 10 devices
                $diagCount++
                if ($diagCount -le 10) {
                    $lastRun = if ($r.lastStateUpdateDateTime) { $r.lastStateUpdateDateTime } else { "unknown" }
                    $usedField = if (-not [string]::IsNullOrWhiteSpace($r.preRemediationDetectionScriptOutput)) { "preRemediationDetectionScriptOutput" } elseif (-not [string]::IsNullOrWhiteSpace($r.scriptOutput)) { "scriptOutput" } else { "(empty)" }
                    Write-Status "    [$($r.managedDevice.deviceName)] state=$($r.detectionState) len=$($out.Length) field=$usedField lastRun=$lastRun" "DarkGray"
                    if ($out.Length -gt 0) { Write-Status "      Output: $($out.Substring(0,[Math]::Min(120,$out.Length)) -replace "`n",' | ')" "DarkGray" }
                    else { Write-Status "      Output: <empty>" "DarkYellow" }
                }
                if ($out -match '(?m)^BIOS:(.+)$') {
                    $ver = Get-NormalizedBiosVersion -Raw $Matches[1].Trim()
                    if ($ver -ne "Unknown" -and -not $biosInstalledMap.ContainsKey($devId)) {
                        $biosInstalledMap[$devId] = $ver
                    }
                }
                if ($out -match '(?m)^SYSID:(.+)$') {
                    $sid = $Matches[1].Trim()
                    if ($sid -and -not $biosScriptSysIdMap.ContainsKey($devId)) {
                        $biosScriptSysIdMap[$devId] = $sid
                    }
                    # Also auto-register model→SysID in knownSysIds so CMSL lookup works
                    if ($sid -and ($out -match '(?m)^MODEL:(.+)$')) {
                        # Normalize same way as $processed: strip "Notebook PC", "Desktop PC" etc.
                        $detectedModel = $Matches[1].Trim() -replace '\s+(Notebook|Desktop|Mobile Workstation)\s+PC$','' -replace '\s+PC$',''
                        if ($detectedModel -and -not $knownSysIds.ContainsKey($detectedModel)) {
                            $knownSysIds[$detectedModel] = $sid
                            Write-Status "  Auto-registered: '$detectedModel' = $sid" "DarkGreen"
                        }
                    }
                }
            }
            $runUrl = $runResp['@odata.nextLink']
        } while ($runUrl)
        Write-Status "    Run States total: $runCount" "DarkGray"
    }
} catch {
    Write-Status "  Health Script BIOS query error: $($_.Exception.Message -split '\r?\n' | Select-Object -First 1)" "DarkYellow"
}

Write-Status "BIOS Health Script: $($biosInstalledMap.Count) devices with BIOS version" "Cyan"

foreach ($d in $processed) {
    if ($d.Id -and $biosInstalledMap.ContainsKey($d.Id))   { $d.BiosInstalled = $biosInstalledMap[$d.Id] }
    if ($d.Id -and $biosScriptSysIdMap.ContainsKey($d.Id) -and -not $d.SysId) { $d.SysId = $biosScriptSysIdMap[$d.Id] }
}

#endregion

#region ── HP CMSL: Latest BIOS versions per model ──────────────────────────

# Model → SysID mapping (extended; CMSL is used for missing entries)
# Source: HP Developer Portal & Intune hardwareInformation.systemProductId
$knownSysIds = @{
    # ── EliteBook 840 ────────────────────────────────────────────────────────
    "HP EliteBook 840 14 inch G11"              = "8C16"
    "HP EliteBook 840 G11"                      = "8C16"
    "HP EliteBook 840 14 inch G10"              = "8BA0"
    "HP EliteBook 840 G10"                      = "8BA0"
    "HP EliteBook 840 14 inch G9"               = "8AAF"
    "HP EliteBook 840 G9"                       = "8AAF"
    "HP EliteBook 840 G8"                       = "8826"
    "HP EliteBook 840 G7"                       = "8723"
    "HP EliteBook 840 G6"                       = "8549"
    "HP EliteBook 840 G5"                       = "83B2"
    # ── EliteBook 850 ────────────────────────────────────────────────────────
    "HP EliteBook 850 G8"                       = "8827"
    "HP EliteBook 850 G7"                       = "8724"
    # ── EliteBook 860 ────────────────────────────────────────────────────────
    "HP EliteBook 860 16 inch G11"              = "8C19"
    "HP EliteBook 860 G11"                      = "8C19"
    "HP EliteBook 860 16 inch G10"              = "8BA3"
    "HP EliteBook 860 G10"                      = "8BA3"
    "HP EliteBook 860 16 inch G9"               = "8AB1"
    "HP EliteBook 860 G9"                       = "8AB1"
    # ── EliteBook 1040 ───────────────────────────────────────────────────────
    "HP EliteBook 1040 14 inch G11"             = "8C1C"
    "HP EliteBook 1040 G11"                     = "8C1C"
    "HP EliteBook 1040 14 inch G10"             = "8BA6"
    "HP EliteBook 1040 G10"                     = "8BA6"
    "HP EliteBook 1040 14 inch G9"              = "8AB4"
    "HP EliteBook 1040 G9"                      = "8AB4"
    # ── EliteBook Ultra / G1i AI ─────────────────────────────────────────────
    "HP EliteBook 8 G1i 14 inch Notebook AI PC"  = "8D89"
    "HP EliteBook 8 G1i 14 inch Notebook AI"    = "8D89"
    "HP EliteBook 8 G1i 16 inch Notebook AI PC"  = "8D8A"
    "HP EliteBook 8 G1i 16 inch Notebook AI"    = "8D8A"
    # ── ProBook 4xx ──────────────────────────────────────────────────────────
    "HP ProBook 450 14 inch G11"                = "8C62"
    "HP ProBook 450 G11"                        = "8C62"
    "HP ProBook 450 G10"                        = "8BA8"
    "HP ProBook 450 G9"                         = "8A79"
    "HP ProBook 450 G8"                         = "8897"
    "HP ProBook 455 14 inch G11"                = "8C63"
    "HP ProBook 455 G11"                        = "8C63"
    "HP ProBook 455 G10"                        = "8BA9"
    "HP ProBook 640 G8"                         = "8893"
    "HP ProBook 650 G8"                         = "8894"
    # ── ZBook ────────────────────────────────────────────────────────────────
    "HP ZBook Studio G9"                        = "8AB2"
    "HP ZBook Fury 16 G9"                       = "8AB5"
    "HP ZBook Firefly 14 G9"                    = "8AB0"
    # ── ProDesk / EliteDesk / Mini ───────────────────────────────────────────
    "HP Pro Mini 400 G9"                        = "8B30"
    "HP ProDesk 4 Mini G1i Desktop AI"          = "8CE0"
    "HP ProDesk 400 G7"                         = "8770"
    "HP ProDesk 400 G9"                         = "8B0E"
    "HP EliteDesk 800 G8"                       = "8826"
    "HP EliteDesk 800 G6"                       = "8717"
    "HP Elite Mini 800 G9"                      = "8B10"
    "HP EliteOne 800 G9 AiO"                    = "8B11"
}

# BIOS lookup result cache: Model → latestVersion
$biosCache = @{}

if (-not $SkipBiosLookup) {
    # Check if HP CMSL is available
    $cmslOk = $false
    try {
        Import-Module HPCMSL -ErrorAction Stop
        $cmslOk = $true
        Write-Status "HP CMSL loaded. Checking for updates..." "Green"
        try {
            $installed = (Get-Module HPCMSL -ListAvailable | Sort-Object Version -Descending | Select-Object -First 1).Version
            $online    = (Find-Module HPCMSL -ErrorAction Stop).Version
            if ($online -gt $installed) {
                Write-Status "  Updating HPCMSL $installed → $online..." "DarkCyan"
                Install-Module HPCMSL -Scope CurrentUser -Force -AcceptLicense -ErrorAction Stop
                Import-Module HPCMSL -Force -ErrorAction Stop
                Write-Status "  HP CMSL updated to $online." "DarkGreen"
            } else {
                Write-Status "  HP CMSL is up to date ($installed)." "DarkGreen"
            }
        } catch {
            Write-Status "  CMSL update skipped: $_" "DarkYellow"
        }
    } catch {
        Write-Status "HP CMSL not found. Attempting automatic installation..." "Yellow"
        try {
            # Ensure NuGet provider
            if (-not (Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue)) {
                Write-Status "  Installing NuGet provider..." "DarkCyan"
                Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Scope CurrentUser -Force -ErrorAction Stop | Out-Null
            }
            # Set PSGallery as trusted
            if ((Get-PSRepository -Name PSGallery).InstallationPolicy -ne 'Trusted') {
                Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
            }
            Install-Module HPCMSL -Scope CurrentUser -Force -AcceptLicense -ErrorAction Stop
            Import-Module HPCMSL -ErrorAction Stop
            $cmslOk = $true
            Write-Status "HP CMSL installed and loaded." "Green"
        } catch {
            Write-Status "CMSL could not be installed. BIOS lookup will be skipped." "Red"
            Write-Status "  Error: $_" "DarkRed"
            Write-Status "  Install manually: Install-Module HPCMSL -Scope CurrentUser -Force" "Yellow"
        }
    }

    if ($cmslOk) {
        # Determine unique models
        $uniqueModels = $processed | Select-Object -ExpandProperty Model -Unique | Where-Object { $_ -ne "Unknown" }
        Write-Status "Querying BIOS versions for $($uniqueModels.Count) models via HP CMSL..."

        foreach ($model in $uniqueModels) {
            if ($biosCache.ContainsKey($model)) { continue }

            $sysId = $knownSysIds[$model] ?? ""

            # SysID from detection script (Win32_BaseBoard.Product) — authoritative source
            $sample = $processed | Where-Object { $_.Model -eq $model } | Select-Object -First 1
            $scriptSysId = if ($sample -and $sample.SysId) { $sample.SysId } else { "" }

            # If table has no entry: use detection script SysID
            if (-not $sysId) { $sysId = $scriptSysId }

            # Fallback: strip " 14 inch" / " 16 inch" and look up again in table
            if (-not $sysId) {
                $modelShort = $model -replace '\s+\d{2}\s+inch',''
                if ($modelShort -ne $model) { $sysId = $knownSysIds[$modelShort] ?? "" }
            }

            # Fallback: CMSL name search
            if (-not $sysId) {
                foreach ($nameVariant in @($model, ($model -replace '\s+\d{2}\s+inch',''))) {
                    try {
                        $found = Get-HPDeviceDetails -Name $nameVariant -ErrorAction SilentlyContinue | Select-Object -First 1
                        if ($found -and $found.SystemID) { $sysId = $found.SystemID; break }
                    } catch {}
                }
            }

            if (-not $sysId) {
                Write-Status "  $model → SysID unknown, skipped" "DarkYellow"
                $biosCache[$model] = "Unknown"
                continue
            }

            # Inner helper: try Get-HPBIOSUpdates for a given SysID, return version string or ""
            $tryBiosLookup = {
                param([string]$id)
                foreach ($osParam in @(@{}, @{Os="win11"}, @{Os="win10"})) {
                    try {
                        $gpArgs = @{ Platform=$id; Latest=$true; ErrorAction="Stop" } + $osParam
                        $r = Get-HPBIOSUpdates @gpArgs
                        $v = ""
                        foreach ($prop in @('Version','Ver','BIOSVersion','BiosVersion','SoftpaqVersion')) {
                            $pv = try { $r.$prop } catch { $null }
                            if (-not [string]::IsNullOrWhiteSpace($pv)) { $v = "$pv"; break }
                        }
                        if (-not $v -and $r) {
                            $r.PSObject.Properties | Where-Object { "$($_.Value)" -match '^\d+\.\d+' } |
                                Select-Object -First 1 | ForEach-Object { $v = "$($_.Value)" }
                        }
                        if ($v) { return $v }
                    } catch {}
                }
                # Last attempt: without -Latest, pick newest from list
                try {
                    $all = Get-HPBIOSUpdates -Platform $id -ErrorAction Stop
                    if ($all) {
                        $newest = @($all) | Sort-Object { try { [version]($_.Version ?? $_.Ver ?? '0') } catch { [version]'0' } } -Descending | Select-Object -First 1
                        foreach ($prop in @('Version','Ver','BIOSVersion','BiosVersion','SoftpaqVersion')) {
                            $pv = try { $newest.$prop } catch { $null }
                            if (-not [string]::IsNullOrWhiteSpace($pv)) { return "$pv" }
                        }
                    }
                } catch {}
                return ""
            }

            $latestVer = & $tryBiosLookup $sysId

            # Table SysID failed → try detection script SysID (if different)
            if (-not $latestVer -and $scriptSysId -and $scriptSysId -ne $sysId) {
                Write-Status "  $model → SysID $sysId returns no data, trying detection script SysID $scriptSysId" "DarkYellow"
                $latestVer = & $tryBiosLookup $scriptSysId
                if ($latestVer) { $sysId = $scriptSysId }
            }

            # Last fallback: CMSL name search for alternative SysID
            if (-not $latestVer) {
                foreach ($nameVariant in @($model, ($model -replace '\s+\d{2}\s+inch',''))) {
                    try {
                        $found = Get-HPDeviceDetails -Name $nameVariant -ErrorAction SilentlyContinue | Select-Object -First 1
                        if ($found -and $found.SystemID -and $found.SystemID -ne $sysId) {
                            Write-Status "  $model → trying CMSL name search SysID $($found.SystemID)" "DarkYellow"
                            $latestVer = & $tryBiosLookup $found.SystemID
                            if ($latestVer) { $sysId = $found.SystemID; break }
                        }
                    } catch {}
                }
            }

            if ($latestVer) {
                $latestVer = Get-NormalizedBiosVersion -Raw $latestVer
                Write-Status "  $model ($sysId) → Latest: $latestVer" "DarkGreen"
            } else {
                Write-Status "  $model ($sysId) → No BIOS data found (model possibly not in CMSL catalog)" "DarkYellow"
            }
            $biosCache[$model] = if ($latestVer) { $latestVer } else { "Unknown" }
        }

        # Write BiosLatest & BiosStatus to processed devices
        foreach ($d in $processed) {
            $latest = $biosCache[$d.Model] ?? "Unknown"
            $d.BiosLatest = $latest
            $d.BiosStatus = Compare-Versions -Installed $d.BiosInstalled -Latest $latest
        }
    }
} else {
    Write-Status "BIOS lookup skipped (-SkipBiosLookup)." "Yellow"
}

#endregion

#region ── Compliance details for non-compliant devices ──────────────────────

if (-not $SkipComplianceDetails) {
    $noncompliantList = @($processed | Where-Object { $_.Compliance -eq "Non-compliant" })
    if ($noncompliantList.Count -gt 0) {
        Write-Status "Querying compliance details for $($noncompliantList.Count) non-compliant devices..."
        $ci = 0
        foreach ($dev in $noncompliantList) {
            $ci++
            if (-not $dev.Id) { continue }
            Write-Status "  [$ci/$($noncompliantList.Count)] $($dev.DeviceName)..." "DarkCyan"
            try {
                # Step 1: retrieve policy states (no $expand – settingStates is not a navigation property)
                $ciUrl  = "https://graph.microsoft.com/beta/deviceManagement/managedDevices/$($dev.Id)/deviceCompliancePolicyStates"
                $ciResp = Invoke-MgGraphRequest -Uri $ciUrl -Method GET
                $issues = [System.Collections.Generic.List[PSCustomObject]]::new()
                foreach ($policy in $ciResp.value) {
                    if ($policy.state -eq 'noncompliant') {
                        # Step 2: retrieve individual settings for this policy
                        try {
                            $sUrl  = "https://graph.microsoft.com/beta/deviceManagement/managedDevices/$($dev.Id)/deviceCompliancePolicyStates/$($policy.id)/settingStates"
                            $sResp = Invoke-MgGraphRequest -Uri $sUrl -Method GET
                            foreach ($s in $sResp.value) {
                                if ($s.state -eq 'noncompliant') {
                                    $issues.Add([PSCustomObject]@{
                                        Policy     = $policy.displayName ?? ""
                                        Setting    = if ($s.settingName) { $s.settingName } elseif ($s.setting) { $s.setting } else { "" }
                                        ErrorDesc  = $s.errorDescription ?? ""
                                    })
                                }
                            }
                        } catch {
                            # Fallback: policy name only without individual settings
                            $issues.Add([PSCustomObject]@{
                                Policy    = $policy.displayName ?? ""
                                Setting   = ""
                                ErrorDesc = ""
                            })
                        }
                    }
                }
                $dev.ComplianceIssues = $issues.ToArray()
            } catch {
                Write-Status "  Error for $($dev.DeviceName): $_" "DarkRed"
            }
        }
        Write-Status "Compliance details retrieved." "Green"
    }
} else {
    Write-Status "Compliance details skipped (-SkipComplianceDetails)." "Yellow"
}

#endregion

#region ── Secure Boot Status ────────────────────────────────────────────────
# hardwareInformation.secureBootEnabled + deviceHealthAttestationState.secureBoot
# are evaluated during device processing above (→ $d.SecureBoot).
$sbDist = $processed | Group-Object SecureBoot | ForEach-Object { "$($_.Name)=$($_.Count)" }
Write-Status "Secure Boot distribution: $($sbDist -join ', ')" "Cyan"
#endregion


#region ── Secure Boot Certificate Status (Device Health Scripts) ─────────────
# Registry: HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing
# Surfaced via Intune Device Health Scripts (Proactive Remediations).

Write-Status "Querying Secure Boot Certificate status (Health Scripts)..." "Yellow"

$sbCertMap = @{}   # deviceId → "Current" / "Not current" / "Not applicable"

try {
    # Find all device health scripts — filter client-side for Secure Boot relevance
    $hsUrl = "https://graph.microsoft.com/beta/deviceManagement/deviceHealthScripts?`$select=id,displayName,description"
    $allScripts = @()
    do {
        $hsResp = Invoke-MgGraphRequest -Uri $hsUrl -Method GET -ErrorAction Stop
        $allScripts += @($hsResp.value)
        $hsUrl = $hsResp['@odata.nextLink']
    } while ($hsUrl)

    $sbScripts = @($allScripts | Where-Object {
        ($_.displayName -match 'SecureBoot|Secure.Boot|SB.Cert|Boot.Cert|DBX|UEFI|Readiness|2026') -or
        ($_.description -match 'SecureBoot|Secure.Boot|DBX|certificate|UEFI|servicing|readiness')
    })
    Write-Status "  Health Scripts total: $($allScripts.Count) | Secure Boot relevant: $($sbScripts.Count)" "DarkCyan"

    foreach ($hs in $sbScripts) {
        Write-Status "    Script: $($hs.displayName)" "DarkCyan"
        $runUrl = "https://graph.microsoft.com/beta/deviceManagement/deviceHealthScripts/$($hs.id)/deviceRunStates?`$select=id,detectionState,lastStateUpdateDateTime,preRemediationDetectionScriptOutput,preRemediationDetectionScriptError&`$expand=managedDevice(`$select=id,deviceName)"
        do {
            $runResp = Invoke-MgGraphRequest -Uri $runUrl -Method GET -ErrorAction Stop
            foreach ($r in @($runResp.value)) {
                $devId = if ($r.managedDevice -and $r.managedDevice.id) { $r.managedDevice.id } else { $null }
                if (-not $devId) { continue }
                # Parse detection output for cert status keywords
                $out = "$($r.preRemediationDetectionScriptOutput) $($r.preRemediationDetectionScriptError)"
                $cs  = if     ($out -match 'up.?to.?date|aktuell|current|compliant|\bready\b|bereit|success|true')        { "Current" }
                       elseif ($out -match 'not.?up.?to.?date|veraltet|outdated|not.?current|not.?ready|nicht.?bereit|false|fail') { "Not current" }
                       elseif ($out -match 'not.?applic|n\.?a\b|nicht.?anwendbar')                        { "Not applicable" }
                       elseif ($r.detectionState -eq 'success')    { "Current" }
                       elseif ($r.detectionState -in 'fail','scriptError','notApplicable') {
                           if ($r.detectionState -eq 'notApplicable') { "Not applicable" } else { "Not current" }
                       }
                       else { $null }
                if ($cs -and -not $sbCertMap.ContainsKey($devId)) { $sbCertMap[$devId] = $cs }
            }
            $runUrl = $runResp['@odata.nextLink']
        } while ($runUrl)
    }
} catch {
    Write-Status "  Health Scripts error: $($_.Exception.Message -split '\r?\n' | Select-Object -First 1)" "DarkYellow"
}

Write-Status "SB Certificate: $($sbCertMap.Count) devices mapped" "Cyan"

foreach ($d in $processed) {
    if ($d.Id -and $sbCertMap.ContainsKey($d.Id)) { $d.CertStatus = $sbCertMap[$d.Id] }
}

#endregion

#region ── iOS/iPadOS versions ──────────────────────────────────────────────────

Write-Status "Querying iOS/iPadOS devices..." "Yellow"
$iosProcessed = [System.Collections.Generic.List[PSCustomObject]]::new()
try {
    $iosUrl = "https://graph.microsoft.com/beta/deviceManagement/managedDevices?" +
              "`$filter=(operatingSystem eq 'iOS' or operatingSystem eq 'iPadOS')" +
              "&`$select=id,deviceName,model,osVersion,operatingSystem,managedDeviceOwnerType,complianceState,userDisplayName,userPrincipalName&`$top=999"
    do {
        $iosResp = Invoke-MgGraphRequest -Uri $iosUrl -Method GET -ErrorAction Stop
        foreach ($d in @($iosResp.value)) {
            $ver   = $d.osVersion ?? ""
            $osTyp = $d.operatingSystem ?? "iOS"
            $lbl   = if ($ver -match '^(\d+\.\d+)') { "$osTyp $($Matches[1])" } else { "$osTyp Unknown" }
            $iosProcessed.Add([PSCustomObject]@{
                DeviceName = $d.deviceName ?? "Unknown"
                Model      = ($d.model ?? "Unknown").Trim()
                OSVersion  = $ver
                OSLabel    = $lbl
                OwnerType  = $d.managedDeviceOwnerType ?? "unknown"
                Compliance = switch ($d.complianceState) {
                    "compliant"    { "Compliant" }
                    "noncompliant" { "Non-compliant" }
                    default        { $d.complianceState ?? "Unknown" }
                }
                User = $d.userDisplayName ?? $d.userPrincipalName ?? "No user"
            })
        }
        $iosUrl = $iosResp['@odata.nextLink']
    } while ($iosUrl)
    Write-Status "  iOS/iPadOS: $($iosProcessed.Count) devices" "Green"
} catch {
    Write-Status "  iOS/iPadOS query error: $($_.Exception.Message -split '\r?\n' | Select-Object -First 1)" "DarkYellow"
}

#endregion

#region ── Android versions ─────────────────────────────────────────────────────

Write-Status "Querying Android devices..." "Yellow"
$androidProcessed = [System.Collections.Generic.List[PSCustomObject]]::new()
try {
    $andUrl = "https://graph.microsoft.com/beta/deviceManagement/managedDevices?" +
              "`$filter=operatingSystem eq 'Android'" +
              "&`$select=id,deviceName,model,osVersion,managedDeviceOwnerType,complianceState,userDisplayName,userPrincipalName&`$top=999"
    do {
        $andResp = Invoke-MgGraphRequest -Uri $andUrl -Method GET -ErrorAction Stop
        foreach ($d in @($andResp.value)) {
            $ver = $d.osVersion ?? ""
            $lbl = if ($ver -match '^(\d+\.\d+)') { "Android $($Matches[1])" }
                   elseif ($ver -match '^(\d+)') { "Android $($Matches[1]).0" }
                   else { "Android Unknown" }
            $androidProcessed.Add([PSCustomObject]@{
                DeviceName = $d.deviceName ?? "Unknown"
                Model      = ($d.model ?? "Unknown").Trim()
                OSVersion  = $ver
                OSLabel    = $lbl
                OwnerType  = $d.managedDeviceOwnerType ?? "unknown"
                Compliance = switch ($d.complianceState) {
                    "compliant"    { "Compliant" }
                    "noncompliant" { "Non-compliant" }
                    default        { $d.complianceState ?? "Unknown" }
                }
                User = $d.userDisplayName ?? $d.userPrincipalName ?? "No user"
            })
        }
        $andUrl = $andResp['@odata.nextLink']
    } while ($andUrl)
    Write-Status "  Android: $($androidProcessed.Count) devices" "Green"
} catch {
    Write-Status "  Android query error: $($_.Exception.Message -split '\r?\n' | Select-Object -First 1)" "DarkYellow"
}

#endregion

#region ── Statistics ───────────────────────────────────────────────────────────

$totalCount   = $processed.Count
$compliantCnt = ($processed | Where-Object { $_.Compliance -eq "Compliant" }).Count
$compliantPct = [math]::Round(($compliantCnt / $totalCount) * 100, 1)
$staleCnt     = ($processed | Where-Object { $_.DaysSince -gt 90 }).Count

# OS statistics
$osGroups = $processed | Group-Object OSFriendly | Sort-Object Count -Descending

# Cumulative Update Build → release date (source: Microsoft Windows Release Health)
$cuReleaseDates = @{
    # Windows 11 25H2 (26200) — from Sep 2025
    "10.0.26200.6584" = "Sep 2025"
    "10.0.26200.6899" = "Oct 2025"
    "10.0.26200.6901" = "Oct 2025"
    "10.0.26200.7019" = "Oct 2025"
    "10.0.26200.7092" = "Nov 2025"
    "10.0.26200.7171" = "Nov 2025"
    "10.0.26200.7309" = "Nov 2025"
    "10.0.26200.7392" = "Dec 2025"
    "10.0.26200.7462" = "Dec 2025"
    "10.0.26200.7623" = "Jan 2026"
    "10.0.26200.7627" = "Jan 2026"
    "10.0.26200.7628" = "Jan 2026"
    "10.0.26200.7705" = "Jan 2026"
    "10.0.26200.7781" = "Feb 2026"
    "10.0.26200.7840" = "Feb 2026"
    "10.0.26200.7922" = "Feb 2026"
    "10.0.26200.7979" = "Mar 2026"
    "10.0.26200.8037" = "Mar 2026"
    # Windows 11 24H2 (26100) — from Oct 2024
    "10.0.26100.1742" = "Oct 2024"
    "10.0.26100.2033" = "Oct 2024"
    "10.0.26100.2161" = "Oct 2024"
    "10.0.26100.2240" = "Nov 2024"
    "10.0.26100.2314" = "Nov 2024"
    "10.0.26100.2454" = "Nov 2024"
    "10.0.26100.2528" = "Dec 2024"
    "10.0.26100.2605" = "Dec 2024"
    "10.0.26100.2894" = "Jan 2025"
    "10.0.26100.3037" = "Jan 2025"
    "10.0.26100.3107" = "Feb 2025"
    "10.0.26100.3194" = "Feb 2025"
    "10.0.26100.3323" = "Feb 2025"
    "10.0.26100.3403" = "Mar 2025"
    "10.0.26100.3476" = "Mar 2025"
    "10.0.26100.3624" = "Mar 2025"
    "10.0.26100.3775" = "Apr 2025"
    "10.0.26100.3915" = "Apr 2025"
    "10.0.26100.3981" = "May 2025"
    "10.0.26100.4061" = "May 2025"
    "10.0.26100.4066" = "May 2025"
    "10.0.26100.4202" = "May 2025"
    "10.0.26100.4270" = "Jun 2025"
    "10.0.26100.4349" = "Jun 2025"
    "10.0.26100.4351" = "Jun 2025"
    "10.0.26100.4484" = "Jun 2025"
    "10.0.26100.4652" = "Jul 2025"
    "10.0.26100.4656" = "Jul 2025"
    "10.0.26100.4770" = "Jul 2025"
    "10.0.26100.4851" = "Aug 2025"
    "10.0.26100.4946" = "Aug 2025"
    "10.0.26100.5074" = "Aug 2025"
    "10.0.26100.6508" = "Sep 2025"
    "10.0.26100.6584" = "Sep 2025"
    "10.0.26100.6588" = "Sep 2025"
    "10.0.26100.6725" = "Sep 2025"
    "10.0.26100.6899" = "Oct 2025"
    "10.0.26100.6901" = "Oct 2025"
    "10.0.26100.6905" = "Oct 2025"
    "10.0.26100.7019" = "Oct 2025"
    "10.0.26100.7092" = "Nov 2025"
    "10.0.26100.7171" = "Nov 2025"
    "10.0.26100.7178" = "Nov 2025"
    "10.0.26100.7309" = "Nov 2025"
    "10.0.26100.7392" = "Dec 2025"
    "10.0.26100.7462" = "Dec 2025"
    "10.0.26100.7623" = "Jan 2026"
    "10.0.26100.7627" = "Jan 2026"
    "10.0.26100.7628" = "Jan 2026"
    "10.0.26100.7705" = "Jan 2026"
    "10.0.26100.7781" = "Feb 2026"
    "10.0.26100.7840" = "Feb 2026"
    "10.0.26100.7922" = "Feb 2026"
    "10.0.26100.7979" = "Mar 2026"
    "10.0.26100.8037" = "Mar 2026"
    # Windows 11 23H2 (22631) — from Oct 2023
    "10.0.22631.2428" = "Oct 2023"
    "10.0.22631.2506" = "Oct 2023"
    "10.0.22631.2715" = "Nov 2023"
    "10.0.22631.2792" = "Nov 2023"
    "10.0.22631.2861" = "Dec 2023"
    "10.0.22631.3007" = "Jan 2024"
    "10.0.22631.3085" = "Jan 2024"
    "10.0.22631.3155" = "Feb 2024"
    "10.0.22631.3235" = "Feb 2024"
    "10.0.22631.3296" = "Mar 2024"
    "10.0.22631.3374" = "Mar 2024"
    "10.0.22631.3447" = "Apr 2024"
    "10.0.22631.3527" = "Apr 2024"
    "10.0.22631.3593" = "May 2024"
    "10.0.22631.3672" = "May 2024"
    "10.0.22631.3737" = "Jun 2024"
    "10.0.22631.3810" = "Jun 2024"
    "10.0.22631.3880" = "Jul 2024"
    "10.0.22631.3958" = "Jul 2024"
    "10.0.22631.4037" = "Aug 2024"
    "10.0.22631.4112" = "Aug 2024"
    "10.0.22631.4169" = "Sep 2024"
    "10.0.22631.4249" = "Sep 2024"
    "10.0.22631.4317" = "Oct 2024"
    "10.0.22631.4391" = "Oct 2024"
    "10.0.22631.4460" = "Nov 2024"
    "10.0.22631.4541" = "Nov 2024"
    "10.0.22631.4602" = "Dec 2024"
    "10.0.22631.4751" = "Jan 2025"
    "10.0.22631.4830" = "Jan 2025"
    "10.0.22631.4890" = "Feb 2025"
    "10.0.22631.4974" = "Feb 2025"
    "10.0.22631.5039" = "Mar 2025"
    "10.0.22631.5126" = "Mar 2025"
    "10.0.22631.5189" = "Apr 2025"
    "10.0.22631.5192" = "Apr 2025"
    "10.0.22631.5262" = "Apr 2025"
    "10.0.22631.5335" = "May 2025"
    "10.0.22631.5413" = "May 2025"
    "10.0.22631.5415" = "May 2025"
    "10.0.22631.5472" = "Jun 2025"
    "10.0.22631.5549" = "Jun 2025"
    "10.0.22631.5624" = "Jul 2025"
    "10.0.22631.5699" = "Jul 2025"
    "10.0.22631.5768" = "Aug 2025"
    "10.0.22631.5771" = "Aug 2025"
    "10.0.22631.5840" = "Aug 2025"
    "10.0.22631.5909" = "Sep 2025"
    "10.0.22631.5984" = "Sep 2025"
    "10.0.22631.6060" = "Oct 2025"
    "10.0.22631.6133" = "Oct 2025"
    "10.0.22631.6199" = "Nov 2025"
    "10.0.22631.6276" = "Nov 2025"
    "10.0.22631.6345" = "Dec 2025"
    "10.0.22631.6491" = "Jan 2026"
    "10.0.22631.6494" = "Jan 2026"
    "10.0.22631.6495" = "Jan 2026"
    "10.0.22631.6649" = "Feb 2026"
    "10.0.22631.6783" = "Mar 2026"
    # Windows 11 22H2 (22621)
    "10.0.22621.3296" = "Mar 2024"
    "10.0.22621.3374" = "Mar 2024"
    "10.0.22621.3447" = "Apr 2024"
    "10.0.22621.3527" = "Apr 2024"
    "10.0.22621.3593" = "May 2024"
    "10.0.22621.3672" = "May 2024"
    "10.0.22621.3737" = "Jun 2024"
    "10.0.22621.3810" = "Jun 2024"
    "10.0.22621.3880" = "Jul 2024"
    "10.0.22621.3958" = "Jul 2024"
    "10.0.22621.4037" = "Aug 2024"
    "10.0.22621.4112" = "Aug 2024"
    "10.0.22621.4169" = "Sep 2024"
    "10.0.22621.4249" = "Sep 2024"
    "10.0.22621.4317" = "Oct 2024"
    "10.0.22621.4391" = "Oct 2024"
    "10.0.22621.4460" = "Nov 2024"
    "10.0.22621.4541" = "Nov 2024"
    "10.0.22621.4602" = "Dec 2024"
    "10.0.22621.4751" = "Jan 2025"
    "10.0.22621.4830" = "Jan 2025"
    "10.0.22621.4890" = "Feb 2025"
    "10.0.22621.4974" = "Feb 2025"
    "10.0.22621.5039" = "Mar 2025"
    "10.0.22621.5126" = "Mar 2025"
    "10.0.22621.5189" = "Apr 2025"
    "10.0.22621.5192" = "Apr 2025"
    "10.0.22621.5262" = "Apr 2025"
    "10.0.22621.5335" = "May 2025"
    "10.0.22621.5413" = "May 2025"
    "10.0.22621.5415" = "May 2025"
    "10.0.22621.5472" = "Jun 2025"
    "10.0.22621.5549" = "Jun 2025"
    "10.0.22621.5624" = "Jul 2025"
    "10.0.22621.5768" = "Aug 2025"
    "10.0.22621.5771" = "Aug 2025"
    "10.0.22621.5909" = "Sep 2025"
    "10.0.22621.6060" = "Oct 2025"
    # Windows 10 22H2 (19045)
    "10.0.19045.4412" = "Apr 2024"
    "10.0.19045.4529" = "May 2024"
    "10.0.19045.4651" = "Jun 2024"
    "10.0.19045.4717" = "Jul 2024"
    "10.0.19045.4842" = "Aug 2024"
    "10.0.19045.4957" = "Sep 2024"
    "10.0.19045.5073" = "Oct 2024"
    "10.0.19045.5198" = "Nov 2024"
    "10.0.19045.5371" = "Dec 2024"
    "10.0.19045.5487" = "Jan 2025"
    "10.0.19045.5608" = "Feb 2025"
    "10.0.19045.5737" = "Mar 2025"
}

# OS drilldown: FriendlyName → list of exact build numbers with count + date
$osDrilldown = @{}
foreach ($g in $osGroups) {
    $builds = $processed | Where-Object { $_.OSFriendly -eq $g.Name } |
              Group-Object OSRaw | Sort-Object Count -Descending |
              Select-Object @{n="build";e={$_.Name}}, @{n="count";e={$_.Count}},
                            @{n="releaseDate";e={ $cuReleaseDates[$_.Name] ?? "" }}
    $osDrilldown[$g.Name] = $builds
}

# BIOS statistics per model
$biosModelStats = $processed | Group-Object Model | Sort-Object Count -Descending | ForEach-Object {
    $modelDevs  = $_.Group
    $modelName  = $_.Name
    $latestVer  = ($biosCache[$modelName] ?? "Unknown")
    $biosVers   = $modelDevs | Group-Object BiosInstalled | Sort-Object Count -Descending |
                  Select-Object @{n="version";e={$_.Name}}, @{n="count";e={$_.Count}},
                                @{n="status";e={Compare-Versions -Installed $_.Name -Latest $latestVer}}
    [PSCustomObject]@{
        model      = $modelName
        total      = $modelDevs.Count
        latestBios = $latestVer
        current    = @($modelDevs | Where-Object { $_.BiosStatus -eq "current"  }).Count
        outdated   = @($modelDevs | Where-Object { $_.BiosStatus -eq "outdated" }).Count
        unknown    = @($modelDevs | Where-Object { $_.BiosStatus -eq "unknown"  }).Count
        versions   = $biosVers
    }
}

# Compliance & model statistics (for pie charts)
$compStats  = $processed | Group-Object Compliance  | Sort-Object Count -Descending |
              Select-Object @{n="label";e={$_.Name}}, @{n="count";e={$_.Count}}
$secureBootStats = $processed | Group-Object SecureBoot | Sort-Object Count -Descending |
              Select-Object @{n="label";e={$_.Name}}, @{n="count";e={$_.Count}}
$modelStats = $processed | Group-Object Model | Sort-Object Count -Descending | Select-Object -First 15 |
              Select-Object @{n="label";e={$_.Name}}, @{n="count";e={$_.Count}}
$osReleaseDateMap = @{}
foreach ($d in $processed) {
    if (-not $osReleaseDateMap.ContainsKey($d.OSFriendly)) { $osReleaseDateMap[$d.OSFriendly] = $d.OSReleaseDate }
}
$osStats    = $osGroups   | Select-Object @{n="label";e={$_.Name}}, @{n="count";e={$_.Count}},
                                          @{n="releaseDate";e={ $osReleaseDateMap[$_.Name] ?? "" }}

# JSON
$deviceJson     = $processed | Select-Object DeviceName, Model, OSFriendly, OSBuild, OSReleaseDate, BiosInstalled, BiosLatest, BiosStatus, Compliance, User, LastSync, DaysSince, ComplianceIssues, SecureBoot, Encrypted, CertStatus | ConvertTo-Json -Depth 5 -Compress
$osJson         = $osStats        | ConvertTo-Json -Compress
$osDrillJson    = $osDrilldown    | ConvertTo-Json -Depth 5 -Compress
$biosModelJson  = $biosModelStats | ConvertTo-Json -Depth 5 -Compress
$compJson       = $compStats      | ConvertTo-Json -Compress
$modelJson      = $modelStats     | ConvertTo-Json -Compress
$secureBootJson  = ConvertTo-Json -InputObject @($secureBootStats) -Compress
$biosDistStats   = $processed | Group-Object BiosStatus | Sort-Object Count -Descending |
                   Select-Object @{n="label";e={$_.Name}}, @{n="count";e={$_.Count}}
$biosDistJson    = @($biosDistStats) | ConvertTo-Json -Compress
$sbCertStats      = $processed | Group-Object CertStatus | Sort-Object Count -Descending |
                    Select-Object @{n="label";e={$_.Name}}, @{n="count";e={$_.Count}}
$sbCertJson       = ConvertTo-Json -InputObject @($sbCertStats) -Compress
$iosCorp           = @($iosProcessed     | Where-Object { $_.OwnerType -eq 'company' })
$iosPersonal       = @($iosProcessed     | Where-Object { $_.OwnerType -ne 'company' })
$andCorp           = @($androidProcessed | Where-Object { $_.OwnerType -eq 'company' })
$andPersonal       = @($androidProcessed | Where-Object { $_.OwnerType -ne 'company' })
$iosCorpJson       = ConvertTo-Json -InputObject @($iosCorp     | Group-Object OSLabel | Sort-Object Count -Descending | Select-Object @{n="label";e={$_.Name}},@{n="count";e={$_.Count}}) -Compress
$iosPersonalJson   = ConvertTo-Json -InputObject @($iosPersonal | Group-Object OSLabel | Sort-Object Count -Descending | Select-Object @{n="label";e={$_.Name}},@{n="count";e={$_.Count}}) -Compress
$andCorpJson       = ConvertTo-Json -InputObject @($andCorp     | Group-Object OSLabel | Sort-Object Count -Descending | Select-Object @{n="label";e={$_.Name}},@{n="count";e={$_.Count}}) -Compress
$andPersonalJson   = ConvertTo-Json -InputObject @($andPersonal | Group-Object OSLabel | Sort-Object Count -Descending | Select-Object @{n="label";e={$_.Name}},@{n="count";e={$_.Count}}) -Compress
$iosCorpDevJson    = ConvertTo-Json -InputObject @($iosCorp)     -Compress
$iosPersonalDevJson= ConvertTo-Json -InputObject @($iosPersonal) -Compress
$andCorpDevJson    = ConvertTo-Json -InputObject @($andCorp)     -Compress
$andPersonalDevJson= ConvertTo-Json -InputObject @($andPersonal) -Compress
$iosModelJson      = ConvertTo-Json -InputObject @($iosCorp  | Group-Object Model | Sort-Object Count -Descending | Select-Object -First 15 | Select-Object @{n="label";e={$_.Name}},@{n="count";e={$_.Count}}) -Compress
$andModelJson      = ConvertTo-Json -InputObject @($andCorp  | Group-Object Model | Sort-Object Count -Descending | Select-Object -First 15 | Select-Object @{n="label";e={$_.Name}},@{n="count";e={$_.Count}}) -Compress

# KPI summary for Apple and Android
$iosTotalCnt     = $iosProcessed.Count
$iosCorpCnt      = $iosCorp.Count
$iosPersonalCnt  = $iosPersonal.Count
$iosCompliantCnt = @($iosProcessed | Where-Object { $_.Compliance -eq 'Compliant' }).Count
$iosCompliantPct = if ($iosTotalCnt -gt 0) { [int](($iosCompliantCnt / $iosTotalCnt) * 100) } else { 0 }
$iosNonCompliant = $iosTotalCnt - $iosCompliantCnt

$andTotalCnt     = $androidProcessed.Count
$andCorpCnt      = $andCorp.Count
$andPersonalCnt  = $andPersonal.Count
$andCompliantCnt = @($androidProcessed | Where-Object { $_.Compliance -eq 'Compliant' }).Count
$andCompliantPct = if ($andTotalCnt -gt 0) { [int](($andCompliantCnt / $andTotalCnt) * 100) } else { 0 }
$andNonCompliant = $andTotalCnt - $andCompliantCnt

$reportDate = Get-Date -Format "dd.MM.yyyy HH:mm"

#endregion

#region ── Generate HTML ───────────────────────────────────────────────────────

Write-Status "Generating HTML report..."

$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>HP Intune Report v2</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.js"></script>
<style>
:root{
  --bg:#0f1117;--bg2:#1a1d27;--bg3:#21253a;--card:#1e2235;--brd:rgba(255,255,255,0.08);
  --txt:#e4e6f0;--mut:#8b90a8;--acc:#4f8ef7;--grn:#3ecf8e;--red:#f76e6e;--amb:#f7b84b;
  --pur:#a78bfa;--tel:#2dd4bf;--font:'Segoe UI',system-ui,sans-serif;
}
*{box-sizing:border-box;margin:0;padding:0;}
body{background:var(--bg);color:var(--txt);font-family:var(--font);font-size:14px;min-height:100vh;}

/* ── Header ── */
.hdr{background:linear-gradient(135deg,#0d1829,#1a2140,#0f1a2e);border-bottom:1px solid var(--brd);padding:20px 36px;display:flex;align-items:center;justify-content:space-between;}
.hbadge{min-width:44px;height:44px;padding:0 10px;background:#0096D6;border-radius:9px;display:flex;align-items:center;justify-content:center;font-weight:700;font-size:13px;color:#fff;flex-shrink:0;text-transform:uppercase;letter-spacing:.5px;}
.hdr h1{font-size:20px;font-weight:600;margin-left:14px;}
.hdr p{color:var(--mut);font-size:12px;margin-top:2px;margin-left:14px;}
.hdr-r{text-align:right;color:var(--mut);font-size:11px;line-height:1.9;}

/* ── Layout ── */
.main{max-width:1440px;margin:0 auto;padding:28px 36px;}
.sec{font-size:10px;font-weight:600;letter-spacing:1.2px;text-transform:uppercase;color:var(--mut);margin-bottom:12px;}

/* ── KPI Cards ── */
.metrics{display:grid;grid-template-columns:repeat(5,1fr);gap:12px;margin-bottom:28px;}
.met{background:var(--card);border:1px solid var(--brd);border-radius:10px;padding:16px;position:relative;overflow:hidden;}
.met::before{content:'';position:absolute;top:0;left:0;right:0;height:3px;border-radius:10px 10px 0 0;}
.met.bl::before{background:var(--acc)}.met.gn::before{background:var(--grn)}.met.rd::before{background:var(--red)}.met.am::before{background:var(--amb)}.met.pu::before{background:var(--pur)}
.ml{font-size:10px;color:var(--mut);text-transform:uppercase;letter-spacing:.7px;}
.mv{font-size:26px;font-weight:700;margin:4px 0 2px;letter-spacing:-1px;}
.ms{font-size:11px;color:var(--mut);}

/* ── Chart-Grid ── */
.cgrid{display:grid;gap:16px;margin-bottom:28px;}
.cgrid-5{grid-template-columns:repeat(5,1fr);}
.cgrid-4{grid-template-columns:repeat(4,1fr);}
.cgrid-3{grid-template-columns:repeat(3,1fr);}
.cgrid-2{grid-template-columns:repeat(2,1fr);}
@media(max-width:1300px){.cgrid-5{grid-template-columns:repeat(3,1fr);}}
@media(max-width:1100px){.cgrid-5,.cgrid-4{grid-template-columns:repeat(2,1fr);}}
@media(max-width:900px){.cgrid-5,.cgrid-4,.cgrid-3,.cgrid-2{grid-template-columns:1fr;}}
.cc{background:var(--card);border:1px solid var(--brd);border-radius:10px;padding:20px;}
.cc h3{font-size:13px;font-weight:600;margin-bottom:2px;}
.ccsub{font-size:11px;color:var(--mut);margin-bottom:14px;}
.cwrap{position:relative;height:210px;}
.cwrap.tall{height:420px;}
.leg{margin-top:10px;display:flex;flex-wrap:wrap;gap:7px;}
.li{display:flex;align-items:center;gap:5px;font-size:11px;color:var(--mut);cursor:pointer;padding:2px 4px;border-radius:4px;transition:background .15s;}
.li:hover{background:rgba(255,255,255,0.06);}
.ld{width:9px;height:9px;border-radius:2px;flex-shrink:0;}
.lc{color:var(--txt);font-weight:600;}

/* ── OS Drilldown Panel ── */
.drill-wrap{background:var(--card);border:1px solid var(--brd);border-radius:10px;overflow:hidden;margin-bottom:28px;display:none;}
.drill-wrap.open{display:block;}
.drill-hdr{padding:14px 20px;background:var(--bg3);display:flex;align-items:center;justify-content:space-between;border-bottom:1px solid var(--brd);}
.drill-hdr h3{font-size:13px;font-weight:600;}
.drill-close{background:none;border:none;color:var(--mut);font-size:18px;cursor:pointer;line-height:1;padding:2px 6px;border-radius:4px;}
.drill-close:hover{color:var(--txt);background:rgba(255,255,255,0.08);}
.drill-body{padding:20px;display:grid;grid-template-columns:1fr 1fr;gap:20px;}
.build-list{display:flex;flex-direction:column;gap:8px;}
.build-row{display:flex;align-items:center;gap:10px;}
.build-bar-wrap{flex:1;background:rgba(255,255,255,0.06);border-radius:4px;height:8px;overflow:hidden;}
.build-bar{height:100%;border-radius:4px;background:var(--acc);transition:width .4s ease;}
.build-lbl{font-size:12px;color:var(--mut);min-width:140px;font-family:monospace;}
.build-cnt{font-size:12px;font-weight:600;min-width:36px;text-align:right;}
.drill-devices{overflow-y:auto;max-height:300px;}
.drill-devices table{width:100%;border-collapse:collapse;font-size:12px;}
.drill-devices th{background:var(--bg3);color:var(--mut);font-size:10px;letter-spacing:.5px;text-transform:uppercase;padding:8px 12px;text-align:left;position:sticky;top:0;}
.drill-devices td{padding:8px 12px;border-bottom:1px solid var(--brd);}
.drill-devices tr:last-child td{border-bottom:none;}
.drill-devices tr:hover td{background:rgba(255,255,255,0.03);}
.drill-devices tr.dev-row{cursor:pointer;}
.drill-devices tr.dev-row td{transition:background .12s;}
.comp-detail-row{display:none;}
.comp-detail-row.open{display:table-row;}
.comp-detail-inner{padding:0 0 4px 0;}
.comp-detail-table{width:100%;border-collapse:collapse;font-size:11px;}
.comp-detail-table th{background:rgba(0,0,0,0.25);color:var(--mut);font-size:10px;letter-spacing:.4px;text-transform:uppercase;padding:5px 12px;text-align:left;}
.comp-detail-table td{padding:5px 12px;border-top:1px solid rgba(255,255,255,0.04);}
.comp-detail-table tr:last-child td{border-bottom:none;}

/* ── BIOS Model Cards ── */
.bios-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(340px,1fr));gap:14px;margin-bottom:28px;}
.bios-card{background:var(--card);border:1px solid var(--brd);border-radius:10px;overflow:hidden;}
.bios-card-hdr{padding:14px 18px;border-bottom:1px solid var(--brd);display:flex;align-items:flex-start;justify-content:space-between;gap:8px;}
.bios-card-hdr h4{font-size:13px;font-weight:600;line-height:1.4;}
.bios-latest-badge{font-size:10px;padding:3px 9px;border-radius:20px;white-space:nowrap;flex-shrink:0;font-weight:600;}
.bios-card-stats{padding:12px 18px;display:flex;gap:16px;border-bottom:1px solid var(--brd);}
.bstat{display:flex;flex-direction:column;gap:2px;}
.bstat-val{font-size:18px;font-weight:700;letter-spacing:-0.5px;}
.bstat-lbl{font-size:10px;color:var(--mut);}
.bios-versions{padding:12px 18px;}
.bv-row{display:flex;align-items:center;gap:8px;padding:5px 0;border-bottom:1px solid rgba(255,255,255,0.04);}
.bv-row:last-child{border-bottom:none;}
.bv-ver{font-family:monospace;font-size:12px;min-width:90px;color:var(--pur);}
.bv-bar-wrap{flex:1;background:rgba(255,255,255,0.06);border-radius:3px;height:6px;overflow:hidden;}
.bv-bar{height:100%;border-radius:3px;transition:width .4s ease;}
.bv-cnt{font-size:12px;font-weight:600;min-width:30px;text-align:right;}
.bv-badge{font-size:10px;padding:2px 7px;border-radius:10px;font-weight:600;white-space:nowrap;}

/* ── Badges ── */
.badge{display:inline-block;padding:2px 9px;border-radius:20px;font-size:10px;font-weight:600;}
.b-grn,.b-ok{background:rgba(62,207,142,.15);color:var(--grn);}
.b-red,.b-err{background:rgba(247,110,110,.15);color:var(--red);}
.b-amb,.b-warn{background:rgba(247,184,75,.15);color:var(--amb);}
.b-pur{background:rgba(167,139,250,.15);color:var(--pur);}
.b-gry,.b-unk{background:rgba(139,144,168,.15);color:var(--mut);}
.b-blue{background:rgba(79,142,247,.15);color:var(--acc);}

/* ── Table ── */
.tcard{background:var(--card);border:1px solid var(--brd);border-radius:10px;overflow:hidden;margin-bottom:20px;}
.ttop{padding:14px 18px;display:flex;align-items:center;gap:10px;border-bottom:1px solid var(--brd);flex-wrap:wrap;}
.ttop h3{font-size:13px;font-weight:600;flex:1;}
.si{background:var(--bg2);border:1px solid var(--brd);color:var(--txt);border-radius:7px;padding:6px 12px;font-size:12px;width:200px;outline:none;}
.si:focus{border-color:var(--acc);}
.fsel{background:var(--bg2);border:1px solid var(--brd);color:var(--txt);border-radius:7px;padding:6px 10px;font-size:12px;outline:none;cursor:pointer;}
table{width:100%;border-collapse:collapse;font-size:12px;}
th{background:var(--bg3);color:var(--mut);font-weight:600;font-size:10px;letter-spacing:.5px;text-transform:uppercase;padding:9px 14px;text-align:left;cursor:pointer;user-select:none;white-space:nowrap;}
th:hover{color:var(--txt);}
td{padding:10px 14px;border-bottom:1px solid var(--brd);}
tr:last-child td{border-bottom:none;}
tr:hover td{background:rgba(255,255,255,0.03);}
.tfoot{padding:10px 18px;color:var(--mut);font-size:11px;border-top:1px solid var(--brd);display:flex;align-items:center;justify-content:space-between;}
.exp-btn{background:var(--acc);color:#fff;border:none;border-radius:7px;padding:7px 14px;font-size:11px;font-weight:600;cursor:pointer;transition:opacity .15s;}
.exp-btn:hover{opacity:.85;}
</style>
</head>
<body>

<div class="hdr">
  <div style="display:flex;align-items:center;">
    <div class="hbadge">$CustomerShortname</div>
    <div><h1>Microsoft Intune Deep Insights</h1><p>$tenantName</p></div>
  </div>
  <div class="hdr-r">
    <div>As of: $reportDate</div>
    <div>$runningUser</div>
  </div>
</div>

<div class="main">

  <!-- Charts Row 1: Windows Devices -->
  <div class="sec">Windows Devices</div>
  <div class="metrics">
    <div class="met bl"><div class="ml">Total Devices</div><div class="mv" style="color:var(--acc);" id="k-total">$totalCount</div><div class="ms">HP Windows Devices</div></div>
    <div class="met gn"><div class="ml">Compliant</div><div class="mv" style="color:var(--grn);" id="k-comp">$compliantCnt</div><div class="ms">$compliantPct% of devices</div></div>
    <div class="met rd"><div class="ml">Non-compliant</div><div class="mv" style="color:var(--red);" id="k-ncomp">–</div><div class="ms">Action required</div></div>
    <div class="met am" onclick="openInactiveDrill()" style="cursor:pointer;" title="Click for details"><div class="ml">Inactive &gt;90 Days</div><div class="mv" style="color:var(--amb);">$staleCnt</div><div class="ms">No sync — Details ▶</div></div>
    <div class="met pu"><div class="ml">BIOS outdated</div><div class="mv" style="color:var(--pur);" id="k-bios-old">–</div><div class="ms">Update available</div></div>
  </div>
  <div class="cgrid cgrid-3">
    <div class="cc">
      <h3>Windows Models &ndash; Corporate</h3>
      <div class="ccsub">Top HP models by count</div>
      <div class="cwrap tall"><canvas id="modelChart"></canvas></div>
    </div>
    <div class="cc">
      <h3>Windows Versions</h3>
      <div class="ccsub">Click segment &rarr; build drilldown</div>
      <div class="cwrap"><canvas id="osChart"></canvas></div>
      <div class="leg" id="osLeg"></div>
    </div>
    <div class="cc">
      <h3>Compliance Status</h3>
      <div class="ccsub">Click segment &rarr; drilldown with causes</div>
      <div class="cwrap"><canvas id="compChart"></canvas></div>
      <div class="leg" id="compLeg"></div>
    </div>
  </div>

  <!-- Charts Row 2: Apple Devices -->
  <div class="sec">Apple Devices</div>
  <div class="metrics">
    <div class="met bl" onclick="openIosMetricDrill('all')" style="cursor:pointer;" title="Show all iOS/iPadOS devices"><div class="ml">Total Devices</div><div class="mv" style="color:var(--acc);">$iosTotalCnt</div><div class="ms">iOS / iPadOS</div></div>
    <div class="met gn" onclick="openIosMetricDrill('compliant')" style="cursor:pointer;" title="Show compliant devices"><div class="ml">Compliant</div><div class="mv" style="color:var(--grn);">$iosCompliantCnt</div><div class="ms">$iosCompliantPct% of devices</div></div>
    <div class="met rd" onclick="openIosMetricDrill('noncompliant')" style="cursor:pointer;" title="Show non-compliant devices"><div class="ml">Non-compliant</div><div class="mv" style="color:var(--red);">$iosNonCompliant</div><div class="ms">Action required</div></div>
    <div class="met am" onclick="openIosCorpDrill(null)" style="cursor:pointer;" title="Show corporate devices"><div class="ml">Corporate</div><div class="mv" style="color:var(--amb);">$iosCorpCnt</div><div class="ms">Corporate devices</div></div>
    <div class="met pu" onclick="openIosPersonalDrill(null)" style="cursor:pointer;" title="Show personal devices"><div class="ml">Personal</div><div class="mv" style="color:var(--pur);">$iosPersonalCnt</div><div class="ms">Personal devices</div></div>
  </div>
  <div class="cgrid cgrid-3">
    <div class="cc">
      <h3>Apple Models &ndash; Corporate</h3>
      <div class="ccsub">iPhone / iPad by model</div>
      <div class="cwrap tall"><canvas id="iosModelChart"></canvas></div>
    </div>
    <div class="cc">
      <h3>Apple &ndash; Corporate</h3>
      <div class="ccsub">Corporate devices &middot; Click for drilldown</div>
      <div class="cwrap" id="iosCorpChartWrap"><canvas id="iosCorpChart"></canvas></div>
      <div class="leg" id="iosCorpLeg"></div>
    </div>
    <div class="cc">
      <h3>iOS / iPadOS &ndash; Personal</h3>
      <div class="ccsub">Personal devices &middot; Click for drilldown</div>
      <div class="cwrap" id="iosPersonalChartWrap"><canvas id="iosPersonalChart"></canvas></div>
      <div class="leg" id="iosPersonalLeg"></div>
    </div>
  </div>

  <!-- Charts Row 3: Android Devices -->
  <div class="sec">Android Devices</div>
  <div class="metrics">
    <div class="met bl" onclick="openAndMetricDrill('all')" style="cursor:pointer;" title="Show all Android devices"><div class="ml">Total Devices</div><div class="mv" style="color:var(--acc);">$andTotalCnt</div><div class="ms">Android Devices</div></div>
    <div class="met gn" onclick="openAndMetricDrill('compliant')" style="cursor:pointer;" title="Show compliant devices"><div class="ml">Compliant</div><div class="mv" style="color:var(--grn);">$andCompliantCnt</div><div class="ms">$andCompliantPct% of devices</div></div>
    <div class="met rd" onclick="openAndMetricDrill('noncompliant')" style="cursor:pointer;" title="Show non-compliant devices"><div class="ml">Non-compliant</div><div class="mv" style="color:var(--red);">$andNonCompliant</div><div class="ms">Action required</div></div>
    <div class="met am" onclick="openAndCorpDrill(null)" style="cursor:pointer;" title="Show corporate devices"><div class="ml">Corporate</div><div class="mv" style="color:var(--amb);">$andCorpCnt</div><div class="ms">Corporate devices</div></div>
    <div class="met pu" onclick="openAndPersonalDrill(null)" style="cursor:pointer;" title="Show personal devices"><div class="ml">Personal</div><div class="mv" style="color:var(--pur);">$andPersonalCnt</div><div class="ms">Personal devices</div></div>
  </div>
  <div class="cgrid cgrid-3">
    <div class="cc">
      <h3>Android Models &ndash; Corporate</h3>
      <div class="ccsub">Android devices by model</div>
      <div class="cwrap tall"><canvas id="andModelChart"></canvas></div>
    </div>
    <div class="cc">
      <h3>Android &ndash; Corporate</h3>
      <div class="ccsub">Corporate devices &middot; Click for drilldown</div>
      <div class="cwrap" id="andCorpChartWrap"><canvas id="andCorpChart"></canvas></div>
      <div class="leg" id="andCorpLeg"></div>
    </div>
    <div class="cc">
      <h3>Android &ndash; Personal</h3>
      <div class="ccsub">Personal devices &middot; Click for drilldown</div>
      <div class="cwrap" id="andPersonalChartWrap"><canvas id="andPersonalChart"></canvas></div>
      <div class="leg" id="andPersonalLeg"></div>
    </div>
  </div>

  <!-- Software & Security -->
  <div class="sec">Software &amp; Security</div>
  <div class="cgrid cgrid-3" style="margin-bottom:28px;">
    <div class="cc">
      <h3>BIOS Status</h3>
      <div class="ccsub">Click segment &rarr; drilldown</div>
      <div class="cwrap" id="encChartWrap"><canvas id="encChart"></canvas></div>
      <div class="leg" id="encLeg"></div>
    </div>
    <div class="cc">
      <h3>Secure Boot</h3>
      <div class="ccsub">Device status &middot; Click for drilldown</div>
      <div class="cwrap" id="sbChartWrap"><canvas id="sbChart"></canvas></div>
      <div class="leg" id="sbLeg"></div>
    </div>
    <div class="cc">
      <h3>Secure Boot Certificate</h3>
      <div class="ccsub">Secure Boot Servicing &middot; Click for drilldown</div>
      <div class="cwrap" id="certChartWrap"><canvas id="certChart"></canvas></div>
      <div class="leg" id="certLeg"></div>
    </div>
  </div>


  <!-- Secure Boot Drilldown Panel -->
  <div class="drill-wrap" id="sbDrillPanel" style="display:none;">
    <div class="drill-hdr">
      <span id="sbDrillTitle"></span>
      <button onclick="document.getElementById('sbDrillPanel').style.display='none'">&#x2715;</button>
    </div>
    <input type="text" placeholder="Search device name, user..." oninput="drillSearch(this.value,'sbDrillBody',false)" class="drill-search">
    <div class="tbl-wrap">
      <table class="dtbl">
        <thead><tr><th>Device Name</th><th>Model</th><th>User</th><th>OS</th><th>Compliance</th><th>Secure Boot</th></tr></thead>
        <tbody id="sbDrillBody"></tbody>
      </table>
    </div>
  </div>

  <!-- BIOS Status Drilldown Panel -->
  <div class="drill-wrap" id="biosDrillPanel" style="display:none;">
    <div class="drill-hdr">
      <span id="biosDrillTitle"></span>
      <button onclick="document.getElementById('biosDrillPanel').style.display='none'">&#x2715;</button>
    </div>
    <input type="text" placeholder="Search device name, model, user..." oninput="drillSearch(this.value,'biosDrillBody',false)" class="drill-search">
    <div class="tbl-wrap">
      <table class="dtbl">
        <thead><tr><th>Device Name</th><th>Model</th><th>User</th><th>OS</th><th>BIOS Installed</th><th>BIOS Latest</th><th>Status</th></tr></thead>
        <tbody id="biosDrillBody"></tbody>
      </table>
    </div>
  </div>


  <!-- SB Certificate Drilldown Panel -->
  <div class="drill-wrap" id="certDrillPanel">
    <div class="drill-hdr">
      <span id="certDrillTitle"></span>
      <button onclick="document.getElementById('certDrillPanel').style.display='none'">&#x2715;</button>
    </div>
    <input type="text" placeholder="Search device name, user..." oninput="drillSearch(this.value,'certDrillBody',false)" class="drill-search">
    <div class="tbl-wrap">
      <table class="dtbl">
        <thead><tr><th>Device Name</th><th>Model</th><th>User</th><th>OS</th><th>Compliance</th><th>SB Certificate</th></tr></thead>
        <tbody id="certDrillBody"></tbody>
      </table>
    </div>
  </div>

  <!-- iOS Metric Drilldown Panel (Total / Compliant / Non-compliant) -->
  <div class="drill-wrap" id="iosMetricDrillPanel">
    <div class="drill-hdr">
      <span id="iosMetricDrillTitle"></span>
      <button onclick="document.getElementById('iosMetricDrillPanel').style.display='none'">&#x2715;</button>
    </div>
    <input type="text" placeholder="Search device name, user..." oninput="drillSearch(this.value,'iosMetricDrillBody',false)" class="drill-search">
    <div class="tbl-wrap">
      <table class="dtbl">
        <thead><tr><th>Device Name</th><th>Model</th><th>User</th><th>Version</th><th>Compliance</th><th>Type</th></tr></thead>
        <tbody id="iosMetricDrillBody"></tbody>
      </table>
    </div>
  </div>

  <!-- Android Metric Drilldown Panel (Total / Compliant / Non-compliant) -->
  <div class="drill-wrap" id="andMetricDrillPanel">
    <div class="drill-hdr">
      <span id="andMetricDrillTitle"></span>
      <button onclick="document.getElementById('andMetricDrillPanel').style.display='none'">&#x2715;</button>
    </div>
    <input type="text" placeholder="Search device name, user..." oninput="drillSearch(this.value,'andMetricDrillBody',false)" class="drill-search">
    <div class="tbl-wrap">
      <table class="dtbl">
        <thead><tr><th>Device Name</th><th>Model</th><th>User</th><th>Version</th><th>Compliance</th><th>Type</th></tr></thead>
        <tbody id="andMetricDrillBody"></tbody>
      </table>
    </div>
  </div>

  <!-- iOS Corporate Drilldown Panel -->
  <div class="drill-wrap" id="iosCorpDrillPanel">
    <div class="drill-hdr">
      <span id="iosCorpDrillTitle"></span>
      <button onclick="document.getElementById('iosCorpDrillPanel').style.display='none'">&#x2715;</button>
    </div>
    <input type="text" placeholder="Search device name, user..." oninput="drillSearch(this.value,'iosCorpDrillBody',false)" class="drill-search">
    <div class="tbl-wrap">
      <table class="dtbl">
        <thead><tr><th>Device Name</th><th>Model</th><th>User</th><th>Version</th><th>Compliance</th></tr></thead>
        <tbody id="iosCorpDrillBody"></tbody>
      </table>
    </div>
  </div>

  <!-- iOS Personal Drilldown Panel -->
  <div class="drill-wrap" id="iosPersonalDrillPanel">
    <div class="drill-hdr">
      <span id="iosPersonalDrillTitle"></span>
      <button onclick="document.getElementById('iosPersonalDrillPanel').style.display='none'">&#x2715;</button>
    </div>
    <input type="text" placeholder="Search device name, user..." oninput="drillSearch(this.value,'iosPersonalDrillBody',false)" class="drill-search">
    <div class="tbl-wrap">
      <table class="dtbl">
        <thead><tr><th>Device Name</th><th>Model</th><th>User</th><th>Version</th><th>Compliance</th></tr></thead>
        <tbody id="iosPersonalDrillBody"></tbody>
      </table>
    </div>
  </div>

  <!-- Android Corporate Drilldown Panel -->
  <div class="drill-wrap" id="andCorpDrillPanel">
    <div class="drill-hdr">
      <span id="andCorpDrillTitle"></span>
      <button onclick="document.getElementById('andCorpDrillPanel').style.display='none'">&#x2715;</button>
    </div>
    <input type="text" placeholder="Search device name, user..." oninput="drillSearch(this.value,'andCorpDrillBody',false)" class="drill-search">
    <div class="tbl-wrap">
      <table class="dtbl">
        <thead><tr><th>Device Name</th><th>Model</th><th>User</th><th>Version</th><th>Compliance</th></tr></thead>
        <tbody id="andCorpDrillBody"></tbody>
      </table>
    </div>
  </div>

  <!-- Android Personal Drilldown Panel -->
  <div class="drill-wrap" id="andPersonalDrillPanel">
    <div class="drill-hdr">
      <span id="andPersonalDrillTitle"></span>
      <button onclick="document.getElementById('andPersonalDrillPanel').style.display='none'">&#x2715;</button>
    </div>
    <input type="text" placeholder="Search device name, user..." oninput="drillSearch(this.value,'andPersonalDrillBody',false)" class="drill-search">
    <div class="tbl-wrap">
      <table class="dtbl">
        <thead><tr><th>Device Name</th><th>Model</th><th>User</th><th>Version</th><th>Compliance</th></tr></thead>
        <tbody id="andPersonalDrillBody"></tbody>
      </table>
    </div>
  </div>

  <!-- OS Drilldown Panel (hidden, appears on click) -->
  <div class="drill-wrap" id="drillPanel">
    <div class="drill-hdr">
      <h3 id="drillTitle">Drilldown</h3>
      <button class="drill-close" onclick="closeDrill()">&#x2715;</button>
    </div>
    <div class="drill-body">
      <div>
        <div class="sec" style="margin-bottom:10px;">Build Numbers</div>
        <div class="build-list" id="drillBuilds"></div>
      </div>
      <div>
        <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:10px;">
          <div class="sec" style="margin-bottom:0;">Devices on this OS version</div>
          <input class="si" style="width:150px;" id="osDrillSearch" type="text" placeholder="Search device..." oninput="drillSearch(this.value,'drillDevices',false)">
        </div>
        <div class="drill-devices"><table><thead><tr><th>Device</th><th>Model</th><th>Build</th><th>Compliance</th></tr></thead><tbody id="drillDevices"></tbody></table></div>
      </div>
    </div>
  </div>

  <!-- Compliance Drilldown Panel -->
  <div class="drill-wrap" id="compDrillPanel">
    <div class="drill-hdr">
      <h3 id="compDrillTitle">Drilldown</h3>
      <button class="drill-close" onclick="closeCompDrill()">&#x2715;</button>
    </div>
    <div class="drill-body">
      <div>
        <div class="sec" style="margin-bottom:10px;">Most common causes</div>
        <div class="build-list" id="compDrillIssues"></div>
      </div>
      <div>
        <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:10px;">
          <div class="sec" style="margin-bottom:0;">Devices with this status</div>
          <input class="si" style="width:150px;" id="compDrillSearch" type="text" placeholder="Search device..." oninput="drillSearch(this.value,'compDrillDevices',true)">
        </div>
        <div class="drill-devices"><table><thead><tr><th>Device &#x25B6; Details</th><th>User</th><th>Policies</th></tr></thead><tbody id="compDrillDevices"></tbody></table></div>
      </div>
    </div>
  </div>

  <!-- Inactive Devices Drilldown Panel -->
  <div class="drill-wrap" id="inactiveDrillPanel">
    <div class="drill-hdr">
      <h3 id="inactiveDrillTitle">Drilldown</h3>
      <button class="drill-close" onclick="closeInactiveDrill()">&#x2715;</button>
    </div>
    <div class="drill-body" style="grid-template-columns:1fr;">
      <div>
        <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:10px;">
          <div class="sec" style="margin-bottom:0;">Inactive devices (no sync &gt;90 days)</div>
          <input class="si" style="width:150px;" id="inactiveDrillSearch" type="text" placeholder="Search device..." oninput="drillSearch(this.value,'inactiveDrillDevices',false)">
        </div>
        <div class="drill-devices"><table><thead><tr><th>Device</th><th>Model</th><th>User</th><th>Last Sync</th><th>Days inactive</th><th>Compliance</th></tr></thead><tbody id="inactiveDrillDevices"></tbody></table></div>
      </div>
    </div>
  </div>

  <!-- BIOS per model -->
  <div class="bios-grid" id="biosGrid"></div>


</div><!-- /main -->

<script>
// ── Data ──────────────────────────────────────────────────────────────────────
const DEVS       = $deviceJson;
const OS_DATA    = $osJson;
const OS_DRILL   = $osDrillJson;
const BIOS_STATS = $biosModelJson;
const COMP_DATA  = $compJson;
const MODEL_DATA = $modelJson;
const SB_DATA    = $secureBootJson;
const ENC_DATA   = $biosDistJson;
const CERT_DATA  = $sbCertJson;
const IOS_CORP_DATA     = $iosCorpJson;
const IOS_CORP_DEVS     = $iosCorpDevJson;
const IOS_PER_DATA      = $iosPersonalJson;
const IOS_PER_DEVS      = $iosPersonalDevJson;
const AND_CORP_DATA     = $andCorpJson;
const AND_CORP_DEVS     = $andCorpDevJson;
const AND_PER_DATA      = $andPersonalJson;
const IOS_MODEL_DATA    = $iosModelJson;
const AND_MODEL_DATA    = $andModelJson;
const AND_PER_DEVS      = $andPersonalDevJson;
const IOS_ALL_DEVS      = [...IOS_CORP_DEVS, ...IOS_PER_DEVS];
const AND_ALL_DEVS      = [...AND_CORP_DEVS, ...AND_PER_DEVS];

// ── Colors ────────────────────────────────────────────────────────────────────
const PAL=['#4f8ef7','#3ecf8e','#f7b84b','#a78bfa','#f76e6e','#2dd4bf','#fb923c','#e879f9','#34d399','#f472b6','#60a5fa','#fbbf24','#c084fc','#4ade80','#f87171'];
const CMAP={'Compliant':'#3ecf8e','Non-compliant':'#f76e6e','Grace Period':'#f7b84b','Conflict':'#a78bfa','Error':'#f76e6e','Unknown':'#8b90a8'};
const SBMAP={'Current':'#3ecf8e','Not current':'#f76e6e','Not applicable':'#8b90a8','Enabled':'#3ecf8e','Disabled':'#f76e6e','Unknown':'#8b90a8'};
const ENCMAP={'current':'#3ecf8e','outdated':'#f76e6e','unknown':'#8b90a8'};

// ── KPIs ──────────────────────────────────────────────────────────────────────
document.getElementById('k-ncomp').textContent    = (COMP_DATA.find(d=>d.label==='Non-compliant')?.count ?? 0);
document.getElementById('k-bios-old').textContent = DEVS.filter(d=>d.BiosStatus==='outdated').length;

// ── Pie chart helper ──────────────────────────────────────────────────────────
function buildPie(canvasId, legId, data, colorFn, onClick, drillFn) {
  const colors = data.map((d,i) => colorFn ? colorFn(d.label) : PAL[i%PAL.length]);
  const chart = new Chart(document.getElementById(canvasId), {
    type:'doughnut',
    data:{labels:data.map(d=>d.label),datasets:[{data:data.map(d=>d.count),backgroundColor:colors,borderColor:'#1e2235',borderWidth:2,hoverBorderWidth:0,hoverOffset:6}]},
    options:{responsive:true,maintainAspectRatio:false,cutout:'60%',
      plugins:{legend:{display:false},tooltip:{backgroundColor:'#0f1117',borderColor:'rgba(255,255,255,0.1)',borderWidth:1,
        callbacks:{label:c=>{const t=c.chart.data.datasets[0].data.reduce((a,b)=>a+b,0);return ' '+c.raw+' devices ('+((c.raw/t)*100).toFixed(1)+'%)';}}}},
      onClick: onClick ? (_,els)=>{ if(els.length>0) onClick(data[els[0].index].label, colors[els[0].index]); } : undefined
    }
  });
  if(legId){
    const total=data.reduce((a,d)=>a+d.count,0);
    const fn = drillFn || 'openDrill';
    document.getElementById(legId).innerHTML=data.map((d,i)=>
      '<span class="li" onclick="'+(onClick ? fn+'(\''+d.label.replace(/'/g,"\\'")+'\')' : 'void(0)')+'">'+
      '<span class="ld" style="background:'+colors[i]+'"></span>'+
      '<span>'+d.label+'</span><span class="lc">'+d.count+'</span></span>'
    ).join('');
  }
  return chart;
}

// ── OS chart with drilldown ───────────────────────────────────────────────────
buildPie('osChart','osLeg', OS_DATA, null, (label) => openDrill(label), 'openDrill');

// ── Mobile charts helper ──────────────────────────────────────────────────────
function buildMobileChart(chartId, legId, wrapId, data, drillFn, fnName, emptyMsg) {
  if (data && data.length > 0) {
    buildPie(chartId, legId, data, null, lbl => drillFn(lbl), fnName);
  } else {
    document.getElementById(wrapId).innerHTML =
      '<p style="color:var(--mut);text-align:center;padding:32px 12px;font-size:11px;">' + emptyMsg + '</p>';
  }
}
function mobileDrillRows(devs) {
  return devs.map(d =>
    '<tr><td>' + (d.DeviceName||'') + '</td><td>' + (d.Model||'') + '</td>' +
    '<td>' + (d.User||'') + '</td><td><code style="font-size:11px;color:var(--acc)">' + (d.OSVersion||'') + '</code></td>' +
    '<td>' + compBadge(d.Compliance) + '</td></tr>'
  ).join('');
}
function mobileDrillRowsWithType(devs) {
  return devs.map(d =>
    '<tr><td>' + (d.DeviceName||'') + '</td><td>' + (d.Model||'') + '</td>' +
    '<td>' + (d.User||'') + '</td><td><code style="font-size:11px;color:var(--acc)">' + (d.OSVersion||'') + '</code></td>' +
    '<td>' + compBadge(d.Compliance) + '</td>' +
    '<td><span class="badge ' + (d.OwnerType==='company'?'b-amb':'b-gry') + '">' + (d.OwnerType==='company'?'Corporate':'Personal') + '</span></td></tr>'
  ).join('');
}
function openMobileDrill(panelId, titleId, bodyId, devs, icon, title, label) {
  devs.sort((a,b) => a.DeviceName.localeCompare(b.DeviceName));
  document.getElementById(bodyId).innerHTML = mobileDrillRows(devs);
  document.getElementById(titleId).textContent =
    icon + ' ' + title + ' \u2014 ' + devs.length + ' devices' + (label ? ' \u2014 ' + label : '');
  const p = document.getElementById(panelId);
  p.style.display = 'block';
  p.scrollIntoView({behavior:'smooth'});
}
function openMobileDrillWithType(panelId, titleId, bodyId, devs, icon, title) {
  devs.sort((a,b) => a.DeviceName.localeCompare(b.DeviceName));
  document.getElementById(bodyId).innerHTML = mobileDrillRowsWithType(devs);
  document.getElementById(titleId).textContent = icon + ' ' + title + ' \u2014 ' + devs.length + ' devices';
  const p = document.getElementById(panelId);
  p.style.display = 'block';
  p.scrollIntoView({behavior:'smooth'});
}

// ── iOS metric drilldowns (Total / Compliant / Non-compliant) ─────────────────
function openIosMetricDrill(filter) {
  let devs = IOS_ALL_DEVS;
  let title = 'iOS/iPadOS \u2014 All Devices';
  if      (filter === 'compliant')    { devs = devs.filter(d => d.Compliance === 'Compliant');     title = 'iOS/iPadOS \u2014 Compliant'; }
  else if (filter === 'noncompliant') { devs = devs.filter(d => d.Compliance !== 'Compliant');     title = 'iOS/iPadOS \u2014 Non-compliant'; }
  openMobileDrillWithType('iosMetricDrillPanel','iosMetricDrillTitle','iosMetricDrillBody', devs, '\uD83D\uDCF1', title);
}

// ── Android metric drilldowns (Total / Compliant / Non-compliant) ─────────────
function openAndMetricDrill(filter) {
  let devs = AND_ALL_DEVS;
  let title = 'Android \u2014 All Devices';
  if      (filter === 'compliant')    { devs = devs.filter(d => d.Compliance === 'Compliant');     title = 'Android \u2014 Compliant'; }
  else if (filter === 'noncompliant') { devs = devs.filter(d => d.Compliance !== 'Compliant');     title = 'Android \u2014 Non-compliant'; }
  openMobileDrillWithType('andMetricDrillPanel','andMetricDrillTitle','andMetricDrillBody', devs, '\uD83E\uDD16', title);
}

// ── iOS Corporate ──────────────────────────────────────────────────────────────
buildMobileChart('iosCorpChart','iosCorpLeg','iosCorpChartWrap', IOS_CORP_DATA,
  lbl => openIosCorpDrill(lbl), 'openIosCorpDrill', 'No corporate<br>iOS/iPadOS devices.');
function openIosCorpDrill(label) {
  const devs = label ? IOS_CORP_DEVS.filter(d => d.OSLabel === label) : IOS_CORP_DEVS;
  openMobileDrill('iosCorpDrillPanel','iosCorpDrillTitle','iosCorpDrillBody', devs, '\uD83D\uDCF1', 'iOS/iPadOS Corporate', label);
}

// ── iOS Personal ───────────────────────────────────────────────────────────────
buildMobileChart('iosPersonalChart','iosPersonalLeg','iosPersonalChartWrap', IOS_PER_DATA,
  lbl => openIosPersonalDrill(lbl), 'openIosPersonalDrill', 'No personal<br>iOS/iPadOS devices.');
function openIosPersonalDrill(label) {
  const devs = label ? IOS_PER_DEVS.filter(d => d.OSLabel === label) : IOS_PER_DEVS;
  openMobileDrill('iosPersonalDrillPanel','iosPersonalDrillTitle','iosPersonalDrillBody', devs, '\uD83D\uDCF1', 'iOS/iPadOS Personal', label);
}

// ── Android Corporate ──────────────────────────────────────────────────────────
buildMobileChart('andCorpChart','andCorpLeg','andCorpChartWrap', AND_CORP_DATA,
  lbl => openAndCorpDrill(lbl), 'openAndCorpDrill', 'No corporate<br>Android devices.');
function openAndCorpDrill(label) {
  const devs = label ? AND_CORP_DEVS.filter(d => d.OSLabel === label) : AND_CORP_DEVS;
  openMobileDrill('andCorpDrillPanel','andCorpDrillTitle','andCorpDrillBody', devs, '\uD83E\uDD16', 'Android Corporate', label);
}

// ── Android Personal ───────────────────────────────────────────────────────────
buildMobileChart('andPersonalChart','andPersonalLeg','andPersonalChartWrap', AND_PER_DATA,
  lbl => openAndPersonalDrill(lbl), 'openAndPersonalDrill', 'No personal<br>Android devices.');
function openAndPersonalDrill(label) {
  const devs = label ? AND_PER_DEVS.filter(d => d.OSLabel === label) : AND_PER_DEVS;
  openMobileDrill('andPersonalDrillPanel','andPersonalDrillTitle','andPersonalDrillBody', devs, '\uD83E\uDD16', 'Android Personal', label);
}

// ── Compliance chart with drilldown ───────────────────────────────────────────
buildPie('compChart','compLeg', COMP_DATA, l => CMAP[l]||'#8b90a8', (label) => openCompDrill(label), 'openCompDrill');

// ── Model chart (horizontal bar) ──────────────────────────────────────────────
(function(){
  const canvas = document.getElementById('modelChart');
  canvas.parentElement.style.height = Math.max(120, MODEL_DATA.length * 40) + 'px';
})();
new Chart(document.getElementById('modelChart'),{
  type:'bar',
  data:{labels:MODEL_DATA.map(d=>d.label),datasets:[{data:MODEL_DATA.map(d=>d.count),backgroundColor:PAL,borderRadius:4,borderSkipped:false,maxBarThickness:24,barPercentage:1.0,categoryPercentage:0.6}]},
  options:{indexAxis:'y',responsive:true,maintainAspectRatio:false,
    plugins:{legend:{display:false},tooltip:{backgroundColor:'#0f1117',borderColor:'rgba(255,255,255,0.1)',borderWidth:1}},
    layout:{padding:{left:0,right:0,top:0,bottom:0}},
    scales:{x:{grid:{color:'rgba(255,255,255,0.05)'},ticks:{color:'#8b90a8'}},
            y:{grid:{display:false},ticks:{color:'#e4e6f0',font:{size:11},
               crossAlign:'far',padding:8,
               callback:function(val,i){const l=this.getLabelForValue(i);return l.length>32?l.slice(0,31)+'\u2026':l;}},
               afterFit(axis){axis.paddingTop=0;axis.paddingBottom=0;}}}
  }
});

// ── Apple models Corporate (horizontal bar) ───────────────────────────────────
function buildModelBar(canvasId, data) {
  if (!data || data.length === 0) {
    document.getElementById(canvasId).parentElement.innerHTML =
      '<p style="color:var(--mut);text-align:center;padding:60px 20px;font-size:12px;">No data available</p>';
    return;
  }
  // Size height to content so bars always align to top
  const itemHeight = 40;
  const minHeight = 120;
  const canvas = document.getElementById(canvasId);
  canvas.parentElement.style.height = Math.max(minHeight, data.length * itemHeight) + 'px';
  new Chart(canvas, {
    type:'bar',
    data:{labels:data.map(d=>d.label),datasets:[{data:data.map(d=>d.count),backgroundColor:PAL,borderRadius:4,borderSkipped:false,maxBarThickness:24,barPercentage:1.0,categoryPercentage:0.6}]},
    options:{indexAxis:'y',responsive:true,maintainAspectRatio:false,
      plugins:{legend:{display:false},tooltip:{backgroundColor:'#0f1117',borderColor:'rgba(255,255,255,0.1)',borderWidth:1}},
      layout:{padding:{left:0,right:0,top:0,bottom:0}},
      scales:{x:{grid:{color:'rgba(255,255,255,0.05)'},ticks:{color:'#8b90a8'}},
              y:{grid:{display:false},ticks:{color:'#e4e6f0',font:{size:11},
                 crossAlign:'far',padding:8,
                 callback:function(val,i){const l=this.getLabelForValue(i);return l.length>28?l.slice(0,27)+'\u2026':l;}},
                 afterFit(axis){axis.paddingTop=0;axis.paddingBottom=0;}}}
    }
  });
}
buildModelBar('iosModelChart', IOS_MODEL_DATA);
buildModelBar('andModelChart', AND_MODEL_DATA);

// ── BIOS Status Chart ──────────────────────────────────────────────────────────
if (ENC_DATA && ENC_DATA.length > 0) {
  buildPie('encChart','encLeg', ENC_DATA, l => ({'current':'#3ecf8e','outdated':'#f76e6e','unknown':'#8b90a8'}[l]||'#8b90a8'), lbl => openBiosStatusDrill(lbl), 'openBiosStatusDrill');
} else {
  document.getElementById('encChartWrap').innerHTML =
    '<p style="color:var(--mut);text-align:center;padding:60px 20px;font-size:12px;">No BIOS status data available</p>';
}

// ── Secure Boot Chart ──────────────────────────────────────────────────────────
if (SB_DATA && SB_DATA.length > 0) {
  buildPie('sbChart','sbLeg', SB_DATA, l => SBMAP[l]||'#8b90a8', lbl => openSbDrill(lbl), 'openSbDrill');
} else {
  document.getElementById('sbChartWrap').innerHTML =
    '<p style="color:var(--mut);text-align:center;padding:60px 20px;font-size:12px;">No Secure Boot data</p>';
}

// ── SB Certificate Chart ───────────────────────────────────────────────────────
const CERTMAP = {'Current':'#3ecf8e','Not current':'#f76e6e','Not applicable':'#8b90a8','Unknown':'#8b90a8'};
const certHasData = CERT_DATA && CERT_DATA.length > 0 &&
  !(CERT_DATA.length === 1 && CERT_DATA[0].label === 'Unknown');
if (certHasData) {
  buildPie('certChart','certLeg', CERT_DATA, l => CERTMAP[l]||'#8b90a8', lbl => openCertDrill(lbl), 'openCertDrill');
} else {
  document.getElementById('certChartWrap').innerHTML =
    '<p style="color:var(--mut);text-align:center;padding:32px 12px;font-size:11px;">No Health Script found for<br>Secure Boot.<br><span style="color:var(--acc);">Set up Proactive Remediation<br>in Intune.</span></p>';
}

function openCertDrill(label) {
  const devs = label ? DEVS.filter(d => d.CertStatus === label) : DEVS;
  devs.sort((a,b) => a.DeviceName.localeCompare(b.DeviceName));
  const cmap = {'Current':'b-ok','Not current':'b-err','Not applicable':'b-unk','Unknown':'b-unk'};
  document.getElementById('certDrillBody').innerHTML = devs.map(d =>
    '<tr><td>' + (d.DeviceName||'') + '</td><td>' + (d.Model||'') + '</td>' +
    '<td>' + (d.User||'') + '</td><td>' + (d.OSFriendly||'') + '</td>' +
    '<td><span class="badge ' + (cmap[d.Compliance]||'b-unk') + '">' + (d.Compliance||'') + '</span></td>' +
    '<td><span class="badge ' + (cmap[d.CertStatus]||'b-unk') + '">' + (d.CertStatus||'Unknown') + '</span></td>' +
    '</tr>'
  ).join('');
  document.getElementById('certDrillTitle').textContent =
    '\uD83D\uDD12 SB Certificate \u2014 ' + devs.length + ' devices' + (label ? ' \u2014 ' + label : '');
  const p = document.getElementById('certDrillPanel');
  p.style.display = 'block';
  p.scrollIntoView({behavior:'smooth'});
}

function openSbDrill(label) {
  const devs = label ? DEVS.filter(d => d.SecureBoot === label) : DEVS;
  devs.sort((a,b) => a.DeviceName.localeCompare(b.DeviceName));
  const sbcmap = {'Enabled':'b-ok','Disabled':'b-err','Unknown':'b-unk'};
  const tbody = document.getElementById('sbDrillBody');
  tbody.innerHTML = devs.map(d =>
    '<tr>' +
    '<td>' + (d.DeviceName||'') + '</td>' +
    '<td>' + (d.Model||'') + '</td>' +
    '<td>' + (d.User||'') + '</td>' +
    '<td>' + (d.OSFriendly||'') + '</td>' +
    '<td><span class="badge ' + (sbcmap[d.Compliance]||'b-unk') + '">' + (d.Compliance||'') + '</span></td>' +
    '<td><span class="badge ' + (sbcmap[d.SecureBoot]||'b-unk') + '">' + (d.SecureBoot||'Unknown') + '</span></td>' +
    '</tr>'
  ).join('');
  document.getElementById('sbDrillTitle').textContent = '\uD83D\uDD0D Secure Boot \u2014 ' + devs.length + ' devices' + (label ? ' \u2014 ' + label : '');
  document.getElementById('sbDrillPanel').style.display = 'block';
  document.getElementById('sbDrillPanel').scrollIntoView({behavior:'smooth'});
}

// ── BIOS Status Drilldown ──────────────────────────────────────────────────────
function openBiosStatusDrill(label) {
  const devs = (label ? DEVS.filter(d => d.BiosStatus === label) : DEVS)
    .slice().sort((a,b) => a.DeviceName.localeCompare(b.DeviceName));
  const labelMap = {'current':'Current','outdated':'Outdated','unknown':'Unknown'};
  document.getElementById('biosDrillBody').innerHTML = devs.map(d =>
    '<tr>' +
    '<td>' + (d.DeviceName||'') + '</td>' +
    '<td>' + (d.Model||'') + '</td>' +
    '<td>' + (d.User||'') + '</td>' +
    '<td>' + (d.OSFriendly||'') + '</td>' +
    '<td><code style="font-size:11px;color:var(--pur)">' + (d.BiosInstalled||'\u2013') + '</code></td>' +
    '<td><code style="font-size:11px;color:var(--tel)">' + (d.BiosLatest||'\u2013') + '</code></td>' +
    '<td>' + biosStatusBadge(d.BiosStatus, false) + '</td>' +
    '</tr>'
  ).join('');
  const lbl = label ? (labelMap[label] || label) : 'All';
  document.getElementById('biosDrillTitle').textContent = '\uD83D\uDDA5\uFE0F BIOS Status \u2014 ' + lbl + ' \u2014 ' + devs.length + ' devices';
  document.getElementById('biosDrillPanel').style.display = 'block';
  document.getElementById('biosDrillPanel').scrollIntoView({behavior:'smooth'});
}

// ── OS Drilldown ───────────────────────────────────────────────────────────────
function openDrill(osLabel) {
  const panel = document.getElementById('drillPanel');
  const builds = OS_DRILL[osLabel] || [];
  const devs   = DEVS.filter(d => d.OSFriendly === osLabel);
  const maxC   = Math.max(...builds.map(b=>b.count),1);

  const osEntry = OS_DATA.find(d => d.label === osLabel);
  const relDate = osEntry?.releaseDate ? ' \u00B7 Released: ' + osEntry.releaseDate : '';
  document.getElementById('drillTitle').textContent = '\uD83D\uDD0D Drilldown: ' + osLabel + ' \u2014 ' + devs.length + ' devices' + relDate;

  // Build bars
  document.getElementById('drillBuilds').innerHTML = builds.map(b=>
    '<div class="build-row">'+
    '<span class="build-lbl">'+b.build+'</span>'+
    (b.releaseDate?'<span style="color:var(--mut);font-size:10px;min-width:58px;">'+b.releaseDate+'</span>':'<span style="min-width:58px;"></span>')+
    '<div class="build-bar-wrap"><div class="build-bar" style="width:'+Math.round((b.count/maxC)*100)+'%"></div></div>'+
    '<span class="build-cnt">'+b.count+'</span>'+
    '</div>'
  ).join('') || '<p style="color:var(--mut);font-size:12px;">No data</p>';

  // Device table in panel
  document.getElementById('drillDevices').innerHTML = devs.map(d=>
    '<tr><td><strong>'+d.DeviceName+'</strong></td><td style="color:var(--mut)">'+d.Model+'</td>'+
    '<td><code style="font-size:11px;color:var(--acc)">'+d.OSBuild+'</code></td>'+
    '<td>'+compBadge(d.Compliance)+'</td></tr>'
  ).join('');

  const osSi = document.getElementById('osDrillSearch');
  if (osSi) osSi.value = '';

  panel.classList.add('open');
  panel.scrollIntoView({behavior:'smooth',block:'nearest'});
}

function closeDrill() {
  document.getElementById('drillPanel').classList.remove('open');
}

// ── Compliance Drilldown ───────────────────────────────────────────────────────
function openCompDrill(compLabel) {
  const panel = document.getElementById('compDrillPanel');
  const devs  = DEVS.filter(d => d.Compliance === compLabel);
  document.getElementById('compDrillTitle').textContent = '\uD83D\uDD0D Drilldown: ' + compLabel + ' \u2014 ' + devs.length + ' devices';

  // Aggregate causes across all devices
  const issueMap = {};
  devs.forEach(d => {
    if (d.ComplianceIssues && d.ComplianceIssues.length) {
      d.ComplianceIssues.forEach(i => {
        const key = (i.Setting && i.Setting.trim()) ? i.Setting.trim() : (i.Policy || 'Unknown');
        issueMap[key] = (issueMap[key] || 0) + 1;
      });
    }
  });
  const issues = Object.entries(issueMap).sort((a,b) => b[1]-a[1]).slice(0,15);
  const maxC   = issues.length > 0 ? issues[0][1] : 1;

  document.getElementById('compDrillIssues').innerHTML = issues.length > 0
    ? issues.map(([k,v]) =>
        '<div class="build-row">'+
        '<span class="build-lbl" title="'+k+'" style="min-width:190px;max-width:190px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">'+k+'</span>'+
        '<div class="build-bar-wrap"><div class="build-bar" style="width:'+Math.round((v/maxC)*100)+'%;background:var(--red)"></div></div>'+
        '<span class="build-cnt">'+v+'</span>'+
        '</div>'
      ).join('')
    : '<p style="color:var(--mut);font-size:12px;">No details \u2014 re-run script without <code>-SkipComplianceDetails</code></p>';

  // Device table with expandable detail rows
  document.getElementById('compDrillDevices').innerHTML = devs.map((d, idx) => {
    const policies   = d.ComplianceIssues ? [...new Set(d.ComplianceIssues.map(i => i.Policy).filter(Boolean))].slice(0,3) : [];
    const issueCount = d.ComplianceIssues ? d.ComplianceIssues.length : 0;
    const rowId      = 'cd_'+idx;

    // Detail sub-table for this row
    const detailHtml = (d.ComplianceIssues && d.ComplianceIssues.length)
      ? '<div class="comp-detail-inner">'+
          '<table class="comp-detail-table">'+
          '<thead><tr><th>Policy</th><th>Setting</th><th>Issue</th></tr></thead>'+
          '<tbody>'+
          d.ComplianceIssues.map(i =>
            '<tr>'+
            '<td style="color:var(--mut)">'+i.Policy+'</td>'+
            '<td style="color:var(--acc)">'+i.Setting+'</td>'+
            '<td style="color:var(--red)">'+( i.ErrorDesc || '\u2014' )+'</td>'+
            '</tr>'
          ).join('')+
          '</tbody></table></div>'
      : '<p style="color:var(--mut);font-size:11px;padding:8px 14px;margin:0">No details available</p>';

    const summaryRow =
      '<tr class="dev-row" onclick="toggleCompDetail(\''+rowId+'\')">'+
      '<td><strong>'+d.DeviceName+'</strong> <span class="arr-'+rowId+'" style="font-size:10px;color:var(--mut)">\u25B6</span></td>'+
      '<td style="color:var(--mut);font-size:11px">'+d.User+'</td>'+
      '<td>'+(policies.length > 0
        ? policies.map(p => '<span class="badge b-red" style="margin:1px;font-size:9px">'+p+'</span>').join(' ')+
          (issueCount > 0 ? ' <span style="color:var(--mut);font-size:10px">('+issueCount+')</span>' : '')
        : '<span class="badge b-gry">No details</span>'
      )+'</td>'+
      '</tr>';

    const detailRow =
      '<tr id="'+rowId+'" class="comp-detail-row">'+
      '<td colspan="3" style="padding:0;background:rgba(0,0,0,0.18)">'+detailHtml+'</td>'+
      '</tr>';

    return summaryRow + detailRow;
  }).join('');

  const compSi = document.getElementById('compDrillSearch');
  if (compSi) compSi.value = '';

  panel.classList.add('open');
  panel.scrollIntoView({behavior:'smooth',block:'nearest'});
}

function closeCompDrill() {
  document.getElementById('compDrillPanel').classList.remove('open');
}

function toggleCompDetail(rowId) {
  const row   = document.getElementById(rowId);
  const open  = row.classList.toggle('open');
  document.querySelectorAll('.arr-'+rowId).forEach(el => el.textContent = open ? '\u25BC' : '\u25B6');
}

// ── Drill search (generic) ────────────────────────────────────────────────────
function drillSearch(q, tbodyId, paired) {
  q = q.toLowerCase();
  const tbody = document.getElementById(tbodyId);
  if (!tbody) return;
  const rows = [...tbody.querySelectorAll('tr')];
  let i = 0;
  while (i < rows.length) {
    const row = rows[i];
    if (paired && row.classList.contains('comp-detail-row')) { i++; continue; }
    const match = !q || row.textContent.toLowerCase().includes(q);
    row.style.display = match ? '' : 'none';
    if (paired && i+1 < rows.length && rows[i+1].classList.contains('comp-detail-row')) {
      if (!match) rows[i+1].style.display = 'none';
      i += 2;
    } else {
      i++;
    }
  }
}

// ── Inactive Devices Drilldown ────────────────────────────────────────────────
function openInactiveDrill() {
  const panel = document.getElementById('inactiveDrillPanel');
  const devs  = DEVS.filter(d => d.DaysSince > 90).sort((a,b) => b.DaysSince - a.DaysSince);
  document.getElementById('inactiveDrillTitle').textContent = '\uD83D\uDD0D Inactive Devices \u2014 ' + devs.length + ' devices without sync >90 days';

  document.getElementById('inactiveDrillDevices').innerHTML = devs.map(d =>
    '<tr>'+
    '<td><strong>'+d.DeviceName+'</strong></td>'+
    '<td style="color:var(--mut)">'+d.Model+'</td>'+
    '<td style="color:var(--mut);font-size:11px">'+d.User+'</td>'+
    '<td style="color:var(--mut);font-size:11px">'+d.LastSync+'</td>'+
    '<td><span class="badge b-amb">'+d.DaysSince+' days</span></td>'+
    '<td>'+compBadge(d.Compliance)+'</td>'+
    '</tr>'
  ).join('');

  const si = document.getElementById('inactiveDrillSearch');
  if (si) si.value = '';

  panel.classList.add('open');
  panel.scrollIntoView({behavior:'smooth',block:'nearest'});
}

function closeInactiveDrill() {
  document.getElementById('inactiveDrillPanel').classList.remove('open');
}

// ── BIOS cards ────────────────────────────────────────────────────────────────
function biosStatusBadge(status, small) {
  if(status==='current')  return '<span class="badge b-grn"'+(small?' style="font-size:9px"':'')+'>&#x2713; Current</span>';
  if(status==='outdated') return '<span class="badge b-red"'+(small?' style="font-size:9px"':'')+'>&#x2191; Outdated</span>';
  return '<span class="badge b-gry"'+(small?' style="font-size:9px"':'')+'>? Unknown</span>';
}

const biosGrid = document.getElementById('biosGrid');
// Check if all BIOS versions are unknown → show setup hint
const biosAllUnknown = BIOS_STATS.length > 0 && BIOS_STATS.every(m => m.latestBios === 'Unknown' && m.current === 0 && m.outdated === 0);
if (biosAllUnknown) {
  biosGrid.innerHTML = '<div style="grid-column:1/-1;background:var(--card);border:1px solid var(--brd);border-radius:10px;padding:28px 32px;display:flex;gap:24px;align-items:flex-start;">'
    + '<div style="font-size:28px;flex-shrink:0;">\u2699\uFE0F</div>'
    + '<div>'
    + '<div style="font-size:14px;font-weight:700;margin-bottom:8px;color:var(--fg);">BIOS data not available</div>'
    + '<div style="font-size:12px;color:var(--mut);line-height:1.7;">'
    + 'The BIOS firmware versions could not be retrieved automatically because the Intune <strong style="color:var(--fg);">Proactive Remediation Script</strong> has not been configured yet.<br>'
    + '<strong style="color:var(--acc);">One-time setup (requires Intune Plan 2 license):</strong><br>'
    + '<code style="background:rgba(255,255,255,.06);padding:4px 10px;border-radius:5px;font-size:11px;display:inline-block;margin:6px 0;">.'
    + '\\Intune-Deep-Insights-v2.ps1 -SetupBiosScript</code><br>'
    + 'Afterwards assign the created script <strong style="color:var(--fg);">"HP Report - BIOS Version"</strong> to all HP devices in Intune, wait a few hours, then re-run the report.'
    + '</div>'
    + '</div>'
    + '</div>';
} else {
biosGrid.innerHTML = BIOS_STATS.map(m => {
  const maxC = Math.max(...m.versions.map(v=>v.count), 1);
  const pctCurrent = m.total > 0 ? Math.round((m.current/m.total)*100) : 0;
  const hdrColor = m.outdated > m.current ? 'var(--red)' : m.current === m.total ? 'var(--grn)' : 'var(--amb)';
  const bars = m.versions.map(v => {
    const barColor = v.status==='current' ? 'var(--grn)' : v.status==='outdated' ? 'var(--red)' : 'var(--mut)';
    return '<div class="bv-row">'+
      '<span class="bv-ver">'+v.version+'</span>'+
      '<div class="bv-bar-wrap"><div class="bv-bar" style="width:'+Math.round((v.count/maxC)*100)+'%;background:'+barColor+'"></div></div>'+
      '<span class="bv-cnt">'+v.count+'</span>'+
      biosStatusBadge(v.status, true)+
      '</div>';
  }).join('');
  return '<div class="bios-card">'+
    '<div class="bios-card-hdr">'+
    '<div><h4>'+m.model+'</h4><span style="font-size:11px;color:var(--mut);">'+m.total+' devices total</span></div>'+
    '<div style="text-align:right;">'+
      '<div style="font-size:10px;color:var(--mut);margin-bottom:3px;">Latest version</div>'+
      '<div style="font-family:monospace;font-size:13px;font-weight:600;color:var(--tel);">'+m.latestBios+'</div>'+
    '</div>'+
    '</div>'+
    '<div class="bios-card-stats">'+
      '<div class="bstat"><div class="bstat-val" style="color:var(--grn)">'+m.current+'</div><div class="bstat-lbl">Current</div></div>'+
      '<div class="bstat"><div class="bstat-val" style="color:var(--red)">'+m.outdated+'</div><div class="bstat-lbl">Outdated</div></div>'+
      '<div class="bstat"><div class="bstat-val" style="color:var(--mut)">'+m.unknown+'</div><div class="bstat-lbl">Unknown</div></div>'+
      '<div class="bstat" style="margin-left:auto;">'+
        '<div class="bstat-val" style="color:'+hdrColor+'">'+pctCurrent+'%</div>'+
        '<div class="bstat-lbl">up to date</div>'+
      '</div>'+
    '</div>'+
    '<div class="bios-versions">'+bars+'</div>'+
    '</div>';
}).join('');
} // end biosAllUnknown else

function compBadge(c){
  if(c==='Compliant')     return '<span class="badge b-grn">&#x2713; Compliant</span>';
  if(c==='Non-compliant') return '<span class="badge b-red">&#x2717; Non-compliant</span>';
  if(c==='Grace Period')  return '<span class="badge b-amb">~ Grace Period</span>';
  if(c==='Conflict')      return '<span class="badge b-pur">&#x26A1; Conflict</span>';
  return '<span class="badge b-gry">'+c+'</span>';
}

</script>
</body>
</html>
"@

#endregion

#region ── Output ───────────────────────────────────────────────────────────────

$html | Out-File -FilePath $OutputPath -Encoding UTF8 -Force
Write-Status "Report saved: $OutputPath" "Green"
try { Start-Process $OutputPath } catch {}

Disconnect-MgGraph
Write-Host ""
Write-Host "  ✓ Done! Report: $OutputPath" -ForegroundColor Green
Write-Host "  ✓ Devices: $totalCount | Compliant: $compliantPct% | BIOS Lookup: $(-not $SkipBiosLookup)" -ForegroundColor Cyan
Write-Host ""

#endregion
