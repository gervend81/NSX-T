# Version 1.7.0
<#
.SYNOPSIS
    STEP 2 of 2 — Imports NSX Distributed Firewall objects from CSV files into NSX 9.

.DESCRIPTION
    Reads CSV files produced by Export-NSX-DFW.ps1 (and optionally sanitized by
    Sanitize-NSX.ps1) and creates/updates objects on an NSX 9 Manager via the
    Policy REST API. Import order respects dependencies:
      1. IP Sets
      2. Services (plain) and/or Service Groups — each independently controllable
      3. Security Groups
      4. Context Profiles
      5. DFW Policies + Rules
      6. VM Tags

    Services and Service Groups are imported in a single dependency-ordered pass
    when both flags are enabled, ensuring service groups are always created after
    the plain services they reference. When only one flag is set, only that CSV
    file is requested and processed.

    FILE RESOLUTION
    ---------------
    All required CSV file dialogs open upfront at the start of the script,
    before any import work begins, based on the -Import* flags you specified.
    A standard Windows file browser dialog opens for each enabled import type,
    filtered to CSV files and starting in -InputFolder.

    The dialog aborts with an error if:
      - The dialog is cancelled without selecting a file
      - System.Windows.Forms is unavailable (non-Windows / no GUI)

.PARAMETER NSXManager
    FQDN or IP of the destination NSX 9 Manager.

.PARAMETER InputFolder
    Folder containing the CSV files to import from.

.PARAMETER ConflictAction
    How to handle objects that already exist on the destination.
    Values: Skip | Overwrite | Prompt | Abort
    Default: Skip

.PARAMETER DomainId
    NSX Policy domain. Default: "default"

.PARAMETER ImportIPSets
    Import IP Sets. Default: $false

.PARAMETER ImportServices
    Import plain Services (NSX_Services.csv). Default: $false

.PARAMETER ImportServiceGroups
    Import Service Groups (NSX_ServiceGroups.csv). Default: $false
    Set this independently of -ImportServices when the source environment
    has no service groups and the CSV does not exist.

.PARAMETER ImportGroups
    Import Security Groups. Default: $false

.PARAMETER ImportProfiles
    Import custom Context Profiles (NSX_Profiles.csv). Default: $false
    Must be imported before policies and rules, as rules may reference profiles
    by path. System-owned profiles are present on every NSX instance and do not
    need to be imported.

.PARAMETER ImportPolicies
    Import DFW Policies and Rules. Default: $false

.PARAMETER ImportTags
    Import VM tags onto fabric VMs. Default: $false

.PARAMETER LogFile
    Path to a log file. Required when -LogTarget is 'File' or 'Both'.

.PARAMETER LogTarget
    Controls where log output is written.
      Screen : colored output to the console only (default)
      File   : write to -LogFile only, no console output
      Both   : colored console output AND written to -LogFile

.EXAMPLE
    # Import from a sanitized export folder — picker opens for any file whose
    # default name is not found.
    .\Import-NSX-DFW.ps1 -NSXManager nsx9.corp.local `
        -InputFolder .\NSX_DFW_Export_20250101_120000 `
        -ImportGroups $true -ImportPolicies $true

.EXAMPLE
    # Dry run — shows what would be imported without making changes.
    .\Import-NSX-DFW.ps1 -NSXManager nsx9.corp.local `
        -InputFolder .\NSX_DFW_Export_20250101_120000 `
        -ImportGroups $true -ImportPolicies $true -WhatIf

.EXAMPLE
    # Import plain services only — no service groups in source environment
    .\Import-NSX-DFW.ps1 -NSXManager nsx9.corp.local `
        -InputFolder .\NSX_DFW_Export_20250101_120000 `
        -ImportServices $true
.NOTES
    Changelog:
      1.0.0  Initial release.
      1.1.0  Added $ScriptVersion variable and startup version log line.
      1.2.0  Replaced hardcoded CSV filenames with auto-detection + Out-GridView
             fallback picker. Errors if file cannot be resolved.
      1.2.1  Fixed variable name collision in Import-Policies: $polPath was used
             for both the CSV file path and the API path, causing a parse error.
      1.2.2  Fixed "$label:" being parsed as a scope modifier — wrapped in $().
      1.2.3  Renamed reserved automatic variable $pid to $policyId.
      1.3.0  Removed auto-detection of default filenames. Out-GridView picker
             now always opens for every enabled import type.
      1.4.0  Replaced Out-GridView picker with a standard Windows file browser
             dialog (System.Windows.Forms.OpenFileDialog), filtered to CSV files
             and starting in -InputFolder.
      1.5.0  (previous release)
      1.6.0  All CSV file dialogs now open upfront at script start (after
             credentials), based on selected -Import* parameters, before any
             import work or NSX connectivity check begins. Each Import-* function
             now consumes the pre-resolved path variable instead of calling
             Resolve-CsvFile itself.
      1.7.0  Added -ImportProfiles flag and Import-Profiles function to support
             custom Context Profiles (NSX_Profiles.csv). Profiles are imported
             after Security Groups and before DFW Policies + Rules.
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$NSXManager,
    [Parameter(Mandatory)][string]$InputFolder,
    [ValidateSet('Skip','Overwrite','Prompt','Abort')]
    [string]$ConflictAction   = 'Skip',
    [string]$DomainId         = 'default',
    [bool]$ImportIPSets       = $false,
    [bool]$ImportServices     = $false,
    [bool]$ImportServiceGroups = $false,
    [bool]$ImportGroups       = $false,
    [bool]$ImportProfiles     = $false,
    [bool]$ImportPolicies     = $false,
    [bool]$ImportTags         = $false,
    [string]$LogFile   = (Join-Path $InputFolder "Import-NSX-DFW_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"),
    [ValidateSet('Screen','File','Both')]
    [string]$LogTarget = 'Both'
)

$ScriptVersion = '1.7.0'

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ─────────────────────────────────────────────────────────────
# LOGGING
# ─────────────────────────────────────────────────────────────
function Write-Log {
    param(
        [string]$Message,
        [ValidateSet('INFO','WARN','ERROR','SUCCESS')][string]$Level = 'INFO'
    )
    $ts    = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $line  = "[$ts][$Level] $Message"
    $color = switch ($Level) {
        'WARN'    { 'Yellow' }
        'ERROR'   { 'Red'    }
        'SUCCESS' { 'Green'  }
        default   { 'Cyan'   }
    }

    if ($LogTarget -eq 'Screen' -or $LogTarget -eq 'Both') {
        Write-Host $line -ForegroundColor $color
    }

    if (($LogTarget -eq 'File' -or $LogTarget -eq 'Both') -and $LogFile) {
        try {
            Add-Content -Path $LogFile -Value $line -Encoding UTF8
        } catch {
            Write-Host "[WARN] Could not write to log file: $_" -ForegroundColor Yellow
            Write-Host $line -ForegroundColor $color
        }
    }
}

Write-Log "Import-NSX-DFW.ps1 v$ScriptVersion" INFO

# ─────────────────────────────────────────────────────────────
# IGNORE SELF-SIGNED CERTIFICATES
# ─────────────────────────────────────────────────────────────
if (-not ([System.Management.Automation.PSTypeName]'TrustAllCerts').Type) {
    Add-Type @"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class TrustAllCerts : ICertificatePolicy {
    public bool CheckValidationResult(ServicePoint sp, X509Certificate cert,
        WebRequest req, int problem) { return true; }
}
"@
}
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCerts
[System.Net.ServicePointManager]::SecurityProtocol  = [System.Net.SecurityProtocolType]::Tls12

# ─────────────────────────────────────────────────────────────
# CREDENTIALS
# ─────────────────────────────────────────────────────────────
Write-Log "Enter credentials for destination NSX Manager: $NSXManager"
$Cred    = Get-Credential -Message "NSX 9 ($NSXManager) credentials"
$pair    = "$($Cred.UserName):$($Cred.GetNetworkCredential().Password)"
$bytes   = [System.Text.Encoding]::ASCII.GetBytes($pair)
$Headers = @{
    Authorization  = "Basic $([Convert]::ToBase64String($bytes))"
    'Content-Type' = 'application/json'
}

# ─────────────────────────────────────────────────────────────
# VALIDATE INPUT FOLDER
# ─────────────────────────────────────────────────────────────
if (-not (Test-Path $InputFolder)) {
    Write-Log "Input folder not found: $InputFolder" ERROR
    exit 1
}
$InputFolder = (Resolve-Path $InputFolder).Path

# ─────────────────────────────────────────────────────────────
# FILE RESOLUTION
#
# Resolve-CsvFile opens a standard Windows file browser dialog
# filtered to CSV files. The initial directory is set to
# $InputFolder so the user lands in the right place immediately.
# Aborts with an error if:
#   - The dialog is cancelled without selecting a file
#   - System.Windows.Forms is unavailable (non-Windows / no GUI)
# ─────────────────────────────────────────────────────────────
function Resolve-CsvFile {
    param(
        [string]$Label   # e.g. 'Security Groups' — shown in the dialog title
    )

    try {
        Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
    } catch {
        Write-Log "  [$($Label)]: System.Windows.Forms is not available on this platform." ERROR
        throw "File picker unavailable for '$($Label)'. Ensure you are running on Windows."
    }

    $dialog                  = New-Object System.Windows.Forms.OpenFileDialog
    $dialog.Title            = "[$Label] Select the CSV file to import"
    $dialog.InitialDirectory = $InputFolder
    $dialog.Filter           = 'CSV files (*.csv)|*.csv|All files (*.*)|*.*'
    $dialog.FilterIndex      = 1
    $dialog.Multiselect      = $false

    $result = $dialog.ShowDialog()

    if ($result -ne [System.Windows.Forms.DialogResult]::OK) {
        Write-Log "  [$($Label)] File picker cancelled — no file selected." ERROR
        throw "File picker cancelled for '$($Label)'. Import aborted."
    }

    Write-Log "  [$($Label)] Selected: $(Split-Path $dialog.FileName -Leaf)" SUCCESS
    return $dialog.FileName
}

# ─────────────────────────────────────────────────────────────
# UPFRONT CSV FILE SELECTION
#
# All required file dialogs open here, before any import work
# begins, so the user can select every CSV file at once.
# Each path is stored in a script-scoped variable consumed
# later by the corresponding Import-* function.
# ─────────────────────────────────────────────────────────────
Write-Log "════════════════════════════════════════════" INFO
Write-Log " FILE SELECTION — select all CSV files now" INFO
Write-Log "════════════════════════════════════════════" INFO

$Script:CsvPath_IPSets        = $null
$Script:CsvPath_Services      = $null
$Script:CsvPath_ServiceGroups = $null
$Script:CsvPath_Groups        = $null
$Script:CsvPath_Profiles      = $null
$Script:CsvPath_Policies      = $null
$Script:CsvPath_Rules         = $null
$Script:CsvPath_Tags          = $null

if ($ImportIPSets)        { $Script:CsvPath_IPSets        = Resolve-CsvFile -Label 'IP Sets'        }
if ($ImportServices)      { $Script:CsvPath_Services      = Resolve-CsvFile -Label 'Services'        }
if ($ImportServiceGroups) { $Script:CsvPath_ServiceGroups = Resolve-CsvFile -Label 'Service Groups'  }
if ($ImportGroups)        { $Script:CsvPath_Groups        = Resolve-CsvFile -Label 'Security Groups' }
if ($ImportProfiles)      { $Script:CsvPath_Profiles      = Resolve-CsvFile -Label 'Context Profiles'}
if ($ImportPolicies) {
    $Script:CsvPath_Policies = Resolve-CsvFile -Label 'DFW Policies'
    $Script:CsvPath_Rules    = Resolve-CsvFile -Label 'DFW Rules'
}
if ($ImportTags)          { $Script:CsvPath_Tags          = Resolve-CsvFile -Label 'VM Tags'         }

Write-Log " All CSV files selected — proceeding with import." INFO
Write-Log "════════════════════════════════════════════" INFO


function Invoke-NSXGet {
    param([string]$Path)
    $uri = "https://$NSXManager$Path"
    try {
        return Invoke-RestMethod -Uri $uri -Method GET -Headers $Headers
    } catch {
        Write-Log "GET $uri failed: $_" ERROR
        return $null
    }
}

function Invoke-NSXPatch {
    param([string]$Path, [string]$JsonBody)
    $uri = "https://$NSXManager$Path"
    try {
        Invoke-RestMethod -Uri $uri -Method PATCH -Headers $Headers -Body $JsonBody | Out-Null
        return $true
    } catch {
        $detail = if ($_.ErrorDetails -and $_.ErrorDetails.Message) { " | Detail: $($_.ErrorDetails.Message)" } else { '' }
        Write-Log "PATCH $uri failed: $_$detail" ERROR
        return $false
    }
}

function Test-ObjectExists {
    param([string]$Path)
    $uri = "https://$NSXManager$Path"
    try {
        Invoke-RestMethod -Uri $uri -Method GET -Headers $Headers | Out-Null
        return $true
    } catch { return $false }
}

# ─────────────────────────────────────────────────────────────
# CSV HELPER
# Loads a CSV from an already-resolved absolute path.
# ─────────────────────────────────────────────────────────────
function Read-CsvFile {
    param([string]$ResolvedPath, [string]$Label)
    $rows = Import-Csv -Path $ResolvedPath -Encoding UTF8
    Write-Log "  [$Label] Loaded $(@($rows).Count) rows from $(Split-Path $ResolvedPath -Leaf)" INFO
    return $rows
}

# ─────────────────────────────────────────────────────────────
# CONFLICT RESOLUTION
# ─────────────────────────────────────────────────────────────
function Resolve-Conflict {
    param([string]$ObjectType, [string]$ObjectId)
    switch ($ConflictAction) {
        'Skip'      { Write-Log "SKIP: $ObjectType '$ObjectId' already exists." WARN; return $false }
        'Overwrite' { Write-Log "OVERWRITE: $ObjectType '$ObjectId'." WARN; return $true }
        'Abort'     { Write-Log "ABORT: $ObjectType '$ObjectId' already exists." ERROR; throw "Conflict on $ObjectType '$ObjectId'. Aborting." }
        'Prompt'    { $answer = Read-Host "[$ObjectType] '$ObjectId' exists on destination. Overwrite? (y/N)"; return ($answer -match '^[Yy]$') }
    }
}

# ─────────────────────────────────────────────────────────────
# STATISTICS
# ─────────────────────────────────────────────────────────────
$Stats = @{ IPSets=0; Services=0; ServiceGroups=0; Groups=0; Profiles=0; Policies=0; Rules=0; Tags=0; TagErrors=0; Skipped=0; Errors=0 }

# ═════════════════════════════════════════════════════════════
# 1. IMPORT IP SETS
# ═════════════════════════════════════════════════════════════
function Import-IPSets {
    Write-Log "━━━ Importing IP Sets ━━━" INFO
    $csvPath = $Script:CsvPath_IPSets
    $rows    = Read-CsvFile -ResolvedPath $csvPath -Label 'IP Sets'
    if (-not $rows) { return }

    foreach ($row in $rows) {
        $id   = $row.Id
        $path = "/api/v1/ip-sets/$id"

        if (Test-ObjectExists -Path $path) {
            if (-not (Resolve-Conflict -ObjectType 'IPSet' -ObjectId $id)) { $Stats.Skipped++; continue }
        }

        if ($PSCmdlet.ShouldProcess($id, "Import IP Set")) {
            $ok = Invoke-NSXPatch -Path $path -JsonBody $row.RawJson
            if ($ok) { $Stats.IPSets++; Write-Log "  ✔ IP Set: $id ($($row.DisplayName))" SUCCESS }
            else      { $Stats.Errors++ }
        }
    }
}

# ═════════════════════════════════════════════════════════════
# 2. IMPORT SERVICES & SERVICE GROUPS
# ═════════════════════════════════════════════════════════════
function Get-ServiceDependencies {
    param([string]$RawJson)
    $deps = @()
    try {
        $obj = $RawJson | ConvertFrom-Json
        $members = if ($obj.PSObject.Properties['members']) { $obj.members } else { @() }
        foreach ($member in $members) {
            $mPath = if ($member.PSObject.Properties['path']) { $member.path } else { $null }
            if ($mPath -and $mPath -match '/services/([^/]+)$') { $deps += $Matches[1] }
        }
        $entries = if ($obj.PSObject.Properties['service_entries']) { $obj.service_entries } else { @() }
        foreach ($entry in $entries) {
            $resType = if ($entry.PSObject.Properties['resource_type']) { $entry.resource_type } else { '' }
            if ($resType -eq 'NestedServiceServiceEntry') {
                $nPath = if ($entry.PSObject.Properties['nested_service_path']) { $entry.nested_service_path } else { $null }
                if ($nPath -and $nPath -match '/services/([^/]+)$') { $deps += $Matches[1] }
            }
        }
    } catch { Write-Log "    Could not parse service dependencies: $_" WARN }
    return $deps | Select-Object -Unique
}

function Sort-ServicesByDependency {
    param([object[]]$ServiceRows, [object[]]$ServiceGroupRows)
    $allRows = @($ServiceRows) + @($ServiceGroupRows)
    $lookup  = @{}
    $depMap  = @{}
    foreach ($r in $allRows) {
        $lookup[$r.Id] = $r
        $depMap[$r.Id] = @(Get-ServiceDependencies -RawJson $r.RawJson)
    }

    $sorted   = [System.Collections.Generic.List[object]]::new()
    $visited  = @{}
    $inResult = @{}

    foreach ($startId in $lookup.Keys) {
        if ($visited[$startId] -eq 2) { continue }
        $stack = [System.Collections.Generic.Stack[hashtable]]::new()
        $stack.Push(@{ Id = $startId; Deps = @($depMap[$startId]); Index = 0 })
        $visited[$startId] = 1

        while ($stack.Count -gt 0) {
            $frame = $stack.Peek()
            $id    = $frame.Id
            $deps  = $frame.Deps
            $idx   = $frame.Index

            if ($idx -lt $deps.Count) {
                $frame.Index++
                $depId = $deps[$idx]
                if (-not $lookup.ContainsKey($depId)) { continue }
                $depState = if ($visited.ContainsKey($depId)) { $visited[$depId] } else { 0 }
                if ($depState -eq 1) { Write-Log "    Circular service dependency between '$id' and '$depId' — continuing." WARN; continue }
                if ($depState -eq 2) { continue }
                $visited[$depId] = 1
                $stack.Push(@{ Id = $depId; Deps = @($depMap[$depId]); Index = 0 })
            } else {
                $stack.Pop() | Out-Null
                $visited[$id] = 2
                if (-not $inResult[$id] -and $lookup.ContainsKey($id)) { $sorted.Add($lookup[$id]); $inResult[$id] = $true }
            }
        }
    }
    return $sorted.ToArray()
}

function Import-Services {
    # Determine which types are active and build a meaningful header label
    $typeLabel = switch ($true) {
        ($ImportServices -and $ImportServiceGroups) { 'Services & Service Groups' }
        $ImportServices                             { 'Services' }
        $ImportServiceGroups                        { 'Service Groups' }
    }
    Write-Log "━━━ Importing $typeLabel ━━━" INFO

    # Only open the file picker for types that are enabled
    $svcRows = @()
    $sgRows  = @()

    if ($ImportServices) {
        $svcPath = $Script:CsvPath_Services
        $svcRows = @(Read-CsvFile -ResolvedPath $svcPath -Label 'Services')
    }

    if ($ImportServiceGroups) {
        $sgPath = $Script:CsvPath_ServiceGroups
        $sgRows = @(Read-CsvFile -ResolvedPath $sgPath -Label 'Service Groups')
    }

    if (-not $svcRows -and -not $sgRows) {
        Write-Log "  No rows loaded — nothing to import." WARN
        return
    }

    Write-Log "  Resolving service dependency order..." INFO
    $orderedRows = Sort-ServicesByDependency -ServiceRows $svcRows -ServiceGroupRows $sgRows
    Write-Log "  Import order resolved for $(@($orderedRows).Count) item(s)." INFO

    foreach ($row in $orderedRows) {
        $id         = $row.Id
        $path       = "/policy/api/v1/infra/services/$id"
        $isGroup    = $row.ObjectType -eq 'ServiceGroup'
        $objectType = if ($isGroup) { 'ServiceGroup' } else { 'Service' }
        $label      = if ($isGroup) { 'Service Group' } else { 'Service' }

        if (Test-ObjectExists -Path $path) {
            if (-not (Resolve-Conflict -ObjectType $objectType -ObjectId $id)) { $Stats.Skipped++; continue }
        }

        if ($PSCmdlet.ShouldProcess($id, "Import $label")) {
            $ok = Invoke-NSXPatch -Path $path -JsonBody $row.RawJson
            if ($ok) {
                if ($isGroup) { $Stats.ServiceGroups++ } else { $Stats.Services++ }
                Write-Log "  ✔ $($label): $id ($($row.DisplayName))" SUCCESS
            } else { $Stats.Errors++ }
        }
    }
}

# ═════════════════════════════════════════════════════════════
# 3. IMPORT SECURITY GROUPS
# ═════════════════════════════════════════════════════════════
function Get-GroupDependencies {
    param([string]$RawJson)
    $deps = @()
    try {
        $obj = $RawJson | ConvertFrom-Json
        $expressions = if ($obj.PSObject.Properties['expression']) { $obj.expression } else { @() }
        foreach ($expr in $expressions) {
            $resType = if ($expr.PSObject.Properties['resource_type']) { $expr.resource_type } else { '' }
            if ($resType -eq 'NestedExpression') {
                $nestedExprs = if ($expr.PSObject.Properties['expressions']) { $expr.expressions } else { @() }
                foreach ($ne in $nestedExprs) {
                    $nePath = if ($ne.PSObject.Properties['path']) { $ne.path } else { $null }
                    if ($nePath -and $nePath -match '/groups/([^/]+)$') { $deps += $Matches[1] }
                }
            }
            if ($resType -eq 'PathExpression') {
                $paths = if ($expr.PSObject.Properties['paths']) { $expr.paths } else { @() }
                foreach ($p in $paths) {
                    if ($p -match '/groups/([^/]+)$') { $deps += $Matches[1] }
                }
            }
        }
    } catch { Write-Log "    Could not parse group dependencies: $_" WARN }
    return $deps | Select-Object -Unique
}

function Sort-GroupsByDependency {
    param([object[]]$Rows)
    $lookup  = @{}
    $depMap  = @{}
    foreach ($r in $Rows) {
        $lookup[$r.Id] = $r
        $depMap[$r.Id] = @(Get-GroupDependencies -RawJson $r.RawJson)
    }

    $sorted   = [System.Collections.Generic.List[object]]::new()
    $visited  = @{}
    $inResult = @{}

    foreach ($startId in $lookup.Keys) {
        if ($visited[$startId] -eq 2) { continue }
        $stack = [System.Collections.Generic.Stack[hashtable]]::new()
        $stack.Push(@{ Id = $startId; Deps = @($depMap[$startId]); Index = 0 })
        $visited[$startId] = 1

        while ($stack.Count -gt 0) {
            $frame = $stack.Peek()
            $id    = $frame.Id
            $deps  = $frame.Deps
            $idx   = $frame.Index

            if ($idx -lt $deps.Count) {
                $frame.Index++
                $depId = $deps[$idx]
                if (-not $lookup.ContainsKey($depId)) { continue }
                $depState = if ($visited.ContainsKey($depId)) { $visited[$depId] } else { 0 }
                if ($depState -eq 1) { Write-Log "    Circular group dependency detected between '$id' and '$depId' — continuing." WARN; continue }
                if ($depState -eq 2) { continue }
                $visited[$depId] = 1
                $stack.Push(@{ Id = $depId; Deps = @($depMap[$depId]); Index = 0 })
            } else {
                $stack.Pop() | Out-Null
                $visited[$id] = 2
                if (-not $inResult[$id] -and $lookup.ContainsKey($id)) { $sorted.Add($lookup[$id]); $inResult[$id] = $true }
            }
        }
    }
    return $sorted.ToArray()
}

function Import-Groups {
    Write-Log "━━━ Importing Security Groups ━━━" INFO
    $csvPath = $Script:CsvPath_Groups
    $rows    = Read-CsvFile -ResolvedPath $csvPath -Label 'Security Groups'
    if (-not $rows) { return }

    Write-Log "  Resolving group dependency order..." INFO
    $rows = Sort-GroupsByDependency -Rows @($rows)
    Write-Log "  Import order resolved for $(@($rows).Count) groups." INFO

    foreach ($row in $rows) {
        $id   = $row.Id
        $path = "/policy/api/v1/infra/domains/$DomainId/groups/$id"

        if (Test-ObjectExists -Path $path) {
            if (-not (Resolve-Conflict -ObjectType 'Group' -ObjectId $id)) { $Stats.Skipped++; continue }
        }

        if ($PSCmdlet.ShouldProcess($id, "Import Group")) {
            $ok = Invoke-NSXPatch -Path $path -JsonBody $row.RawJson
            if ($ok) { $Stats.Groups++; Write-Log "  ✔ Group: $id ($($row.DisplayName))" SUCCESS }
            else      { $Stats.Errors++ }
        }
    }
}

# ═════════════════════════════════════════════════════════════
# 4. IMPORT CONTEXT PROFILES
# ═════════════════════════════════════════════════════════════
function Import-Profiles {
    Write-Log "━━━ Importing Context Profiles ━━━" INFO
    $csvPath = $Script:CsvPath_Profiles
    $rows    = Read-CsvFile -ResolvedPath $csvPath -Label 'Context Profiles'
    if (-not $rows) { return }

    foreach ($row in $rows) {
        $id   = $row.Id
        $path = "/policy/api/v1/infra/context-profiles/$id"

        if (Test-ObjectExists -Path $path) {
            if (-not (Resolve-Conflict -ObjectType 'ContextProfile' -ObjectId $id)) { $Stats.Skipped++; continue }
        }

        if ($PSCmdlet.ShouldProcess($id, "Import Context Profile")) {
            $ok = Invoke-NSXPatch -Path $path -JsonBody $row.RawJson
            if ($ok) { $Stats.Profiles++; Write-Log "  ✔ Context Profile: $id ($($row.DisplayName))" SUCCESS }
            else      { $Stats.Errors++ }
        }
    }
}

# ═════════════════════════════════════════════════════════════
# 5. IMPORT DFW POLICIES & RULES
# ═════════════════════════════════════════════════════════════
function Import-Policies {
    Write-Log "━━━ Importing DFW Policies ━━━" INFO

    $polCsvPath  = $Script:CsvPath_Policies
    $ruleCsvPath = $Script:CsvPath_Rules
    $policyRows  = Read-CsvFile -ResolvedPath $polCsvPath  -Label 'DFW Policies'
    $ruleRows    = Read-CsvFile -ResolvedPath $ruleCsvPath -Label 'DFW Rules'

    if (-not $policyRows) { return }

    $rulesByPolicy = @{}
    foreach ($rRow in $ruleRows) {
        $policyId = $rRow.PolicyId
        if (-not $rulesByPolicy[$policyId]) { $rulesByPolicy[$policyId] = @() }
        $rulesByPolicy[$policyId] += $rRow
    }

    $policyRows = $policyRows | Sort-Object { [int]$_.SequenceNumber }

    foreach ($pRow in $policyRows) {
        $polId   = $pRow.Id
        $polPath = "/policy/api/v1/infra/domains/$DomainId/security-policies/$polId"

        if (Test-ObjectExists -Path $polPath) {
            if (-not (Resolve-Conflict -ObjectType 'DFW Policy' -ObjectId $polId)) { $Stats.Skipped++; continue }
        }

        if ($PSCmdlet.ShouldProcess($polId, "Import DFW Policy")) {
            $ok = Invoke-NSXPatch -Path $polPath -JsonBody $pRow.RawJson
            if ($ok) {
                $Stats.Policies++
                Write-Log "  ✔ Policy: $polId ($($pRow.DisplayName)) [seq $($pRow.SequenceNumber)]" SUCCESS
            } else { $Stats.Errors++; continue }
        }

        $rules = $rulesByPolicy[$polId]
        if ($rules) {
            $rules = $rules | Sort-Object { [int]$_.SequenceNumber }
            foreach ($rRow in $rules) {
                $ruleId      = $rRow.Id
                $ruleApiPath = "/policy/api/v1/infra/domains/$DomainId/security-policies/$polId/rules/$ruleId"

                if ($PSCmdlet.ShouldProcess($ruleId, "Import Rule in Policy $polId")) {
                    $ok = Invoke-NSXPatch -Path $ruleApiPath -JsonBody $rRow.RawJson
                    if ($ok) { $Stats.Rules++; Write-Log "    ✔ Rule: $ruleId ($($rRow.DisplayName)) — $($rRow.Action)" SUCCESS }
                    else      { $Stats.Errors++ }
                }
            }
        }
    }
}

# ═════════════════════════════════════════════════════════════
# 6. IMPORT VM TAGS
# ═════════════════════════════════════════════════════════════
function Import-Tags {
    Write-Log "━━━ Importing VM Tags ━━━" INFO
    Write-Log "  NOTE: VMs must already exist in the destination NSX/vCenter inventory." WARN

    $csvPath = $Script:CsvPath_Tags
    $rows    = Read-CsvFile -ResolvedPath $csvPath -Label 'VM Tags'
    if (-not $rows) { return }

    $tagsByVM = @{}
    foreach ($row in $rows) {
        $eid = $row.ExternalId
        if (-not $tagsByVM[$eid]) { $tagsByVM[$eid] = @{ DisplayName = $row.VMDisplayName; Tags = @() } }
        $tagsByVM[$eid].Tags += @{ scope = $row.TagScope; tag = $row.TagValue }
    }

    foreach ($eid in $tagsByVM.Keys) {
        $vmName = $tagsByVM[$eid].DisplayName
        $tags   = $tagsByVM[$eid].Tags

        $checkUri = "https://$NSXManager/api/v1/fabric/virtual-machines?external_id=$eid&included_fields=display_name"
        try {
            $checkResp = Invoke-RestMethod -Uri $checkUri -Method GET -Headers $Headers
            if (-not $checkResp.results -or $checkResp.results.Count -eq 0) {
                Write-Log "  SKIP: VM '$vmName' (external_id: $eid) not found in destination inventory." WARN
                $Stats.Skipped++; continue
            }
        } catch {
            Write-Log "  SKIP: Could not verify VM '$vmName' ($eid) in destination: $_" WARN
            $Stats.Skipped++; continue
        }

        $body    = @{ external_id = $eid; tags = $tags } | ConvertTo-Json -Depth 5 -Compress
        $postUri = "https://$NSXManager/api/v1/fabric/virtual-machines?action=update_tags"

        if ($PSCmdlet.ShouldProcess($vmName, "Apply $($tags.Count) tag(s)")) {
            try {
                Invoke-RestMethod -Uri $postUri -Method POST -Headers $Headers -Body $body | Out-Null
                $Stats.Tags++
                $tagSummary = ($tags | ForEach-Object { "$($_.scope):$($_.tag)" }) -join ', '
                Write-Log "  ✔ VM: $vmName — $tagSummary" SUCCESS
            } catch {
                Write-Log "  ✗ Failed to apply tags to '$vmName' ($eid): $_" ERROR
                $Stats.TagErrors++
            }
        }
    }
}

# ═════════════════════════════════════════════════════════════
# MAIN
# ═════════════════════════════════════════════════════════════
$anyAction = $ImportIPSets -or $ImportServices -or $ImportServiceGroups -or $ImportGroups -or $ImportProfiles -or $ImportPolicies -or $ImportTags
if (-not $anyAction) {
    Write-Log "No import actions selected. Specify at least one -Import* flag." WARN
    Write-Log "Example: -ImportPolicies `$true -ImportGroups `$true" WARN
    exit 0
}

Write-Log "════════════════════════════════════════════" INFO
Write-Log " NSX DFW IMPORT" INFO
Write-Log " Destination : $NSXManager" INFO
Write-Log " Input folder: $InputFolder" INFO
Write-Log " Conflict    : $ConflictAction" INFO
Write-Log " Domain      : $DomainId" INFO
Write-Log "════════════════════════════════════════════" INFO
Write-Log " Import IP Sets      : $ImportIPSets" INFO
Write-Log " Import Services     : $ImportServices" INFO
Write-Log " Import Svc Groups   : $ImportServiceGroups" INFO
Write-Log " Import Groups       : $ImportGroups" INFO
Write-Log " Import Profiles     : $ImportProfiles" INFO
Write-Log " Import Policies     : $ImportPolicies" INFO
Write-Log " Import Tags         : $ImportTags" INFO
Write-Log " CSV files are selected upfront before import starts." INFO
Write-Log "════════════════════════════════════════════" INFO

try {
    Write-Log "Verifying connectivity to $NSXManager..." INFO
    $info = Invoke-NSXGet -Path "/api/v1/node"
    if ($info) { Write-Log "  Connected: NSX $($info.product_version)" SUCCESS }
    else        { throw "Cannot connect to NSX Manager $NSXManager." }

    if ($ImportIPSets)                            { Import-IPSets   }
    if ($ImportServices -or $ImportServiceGroups) { Import-Services }
    if ($ImportGroups)                            { Import-Groups   }
    if ($ImportProfiles)                          { Import-Profiles }
    if ($ImportPolicies)                          { Import-Policies }
    if ($ImportTags)                              { Import-Tags     }

} catch {
    Write-Log "FATAL: $_" ERROR
    exit 1
} finally {
    Write-Log "════════════════════════════════════════════" INFO
    Write-Log " IMPORT SUMMARY" INFO
    Write-Log "────────────────────────────────────────────" INFO
    Write-Log "  IP Sets imported        : $($Stats.IPSets)"        INFO
    Write-Log "  Services imported       : $($Stats.Services)"      INFO
    Write-Log "  Svc Groups imported     : $($Stats.ServiceGroups)" INFO
    Write-Log "  Groups imported         : $($Stats.Groups)"        INFO
    Write-Log "  Profiles imported       : $($Stats.Profiles)"      INFO
    Write-Log "  Policies imported       : $($Stats.Policies)"      INFO
    Write-Log "  Rules imported          : $($Stats.Rules)"         INFO
    Write-Log "  VMs tagged              : $($Stats.Tags)"          INFO
    Write-Log "  Tag errors              : $($Stats.TagErrors)"     $(if ($Stats.TagErrors -gt 0) { 'ERROR' } else { 'INFO' })
    Write-Log "  Skipped (conflicts)     : $($Stats.Skipped)"       WARN
    Write-Log "  Errors                  : $($Stats.Errors)"        $(if ($Stats.Errors -gt 0) { 'ERROR' } else { 'INFO' })
    Write-Log "════════════════════════════════════════════" INFO
}