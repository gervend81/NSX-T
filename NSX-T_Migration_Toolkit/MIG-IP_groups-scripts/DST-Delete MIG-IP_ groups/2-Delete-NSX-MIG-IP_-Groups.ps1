# Version 1.0.0
<#
.SYNOPSIS
    STEP 2 of 2 — Removes MIG-IP Helper Groups and restores original group logic using NSX_MIGIP_Groups_Final.csv.

.DESCRIPTION
    This script reverses the VM-to-IP group migration performed in Step 1. It operates
    in two cleanup phases driven by a single input file, with an optional rollback safety net.

    1. PATCH PHASE (-PatchVMGroups):
       Reads 'UpdatedRawJson' from the CSV to patch original groups, removing all
       MIG-IP_ PathExpression references. Uses a dependency sorter to ensure nested
       groups are processed in the correct order.

    2. DELETE PHASE (-DeleteMIGIPGroups):
       Reads rows where Id starts with 'MIG-IP_' and deletes those helper groups
       from NSX. Should only be run after Phase 1 to avoid leaving broken references.

    3. ROLLBACK PHASE (-RollbackVMGroups):
       Reads 'RawJson' from the CSV to restore original groups back to their
       MIG-IP_ referencing state. Only processes rows that have a valid UpdatedRawJson,
       meaning they were touched in Phase 1.

    FILE RESOLUTION
    ---------------
    A single Windows file browser dialog opens at the start of the script to select
    'NSX_MIGIP_Groups_Final.csv'. This file must contain the following headers:
    Id, DisplayName, RawJson, and UpdatedRawJson.

.PARAMETER NSXManager
    FQDN or IP of the target NSX Manager.

.PARAMETER InputFolder
    Initial directory for the file picker dialog. Must exist on the local filesystem.

.PARAMETER PatchVMGroups
    Phase 1: Patches original groups using UpdatedRawJson to remove MIG-IP references.
    Default: $false

.PARAMETER DeleteMIGIPGroups
    Phase 2: Deletes MIG-IP_ helper groups from NSX. Run after -PatchVMGroups.
    Default: $false

.PARAMETER RollbackVMGroups
    Safety: Re-applies RawJson to restore MIG-IP references into original groups.
    Includes a confirmation prompt. Default: $false

.EXAMPLE
    # Full Cleanup (recommended order — patch first, then delete)
    # Removes MIG-IP references from original groups, then deletes the helper groups.
    .\Remove-NSX-MIGIPGroups.ps1 -NSXManager nsx01.local `
        -InputFolder C:\Migration -PatchVMGroups $true -DeleteMIGIPGroups $true

.EXAMPLE
    # Dry Run (What-If)
    # Shows which groups would be patched or deleted without making any changes.
    # Highly recommended before live execution.
    .\Remove-NSX-MIGIPGroups.ps1 -NSXManager nsx01.local `
        -InputFolder C:\Migration -PatchVMGroups $true -DeleteMIGIPGroups $true -WhatIf

.EXAMPLE
    # Full Cleanup (recommended order — patch first, then delete)
    # Removes MIG-IP references from original groups, then deletes the helper groups.
    .\Remove-NSX-MIGIPGroups.ps1 -NSXManager nsx01.local `
        -InputFolder C:\Migration -PatchVMGroups $true -DeleteMIGIPGroups $true

.EXAMPLE
    # Dry Run — Full Cleanup (What-If)
    # Shows which groups would be patched or deleted without making any changes.
    # Highly recommended before live execution.
    .\Remove-NSX-MIGIPGroups.ps1 -NSXManager nsx01.local `
        -InputFolder C:\Migration -PatchVMGroups $true -DeleteMIGIPGroups $true -WhatIf

.EXAMPLE
    # Phase 1 Only — Patch original groups (remove MIG-IP references)
    # Use this if you want to verify NSX is stable before proceeding to deletion.
    .\Remove-NSX-MIGIPGroups.ps1 -NSXManager nsx01.local `
        -InputFolder C:\Migration -PatchVMGroups $true

.EXAMPLE
    # Dry Run — Phase 1 Only (What-If)
    .\Remove-NSX-MIGIPGroups.ps1 -NSXManager nsx01.local `
        -InputFolder C:\Migration -PatchVMGroups $true -WhatIf

.EXAMPLE
    # Phase 2 Only — Delete MIG-IP helper groups
    # Only use this after Phase 1 has been completed and verified.
    .\Remove-NSX-MIGIPGroups.ps1 -NSXManager nsx01.local `
        -InputFolder C:\Migration -DeleteMIGIPGroups $true

.EXAMPLE
    # Dry Run — Phase 2 Only (What-If)
    .\Remove-NSX-MIGIPGroups.ps1 -NSXManager nsx01.local `
        -InputFolder C:\Migration -DeleteMIGIPGroups $true -WhatIf

.EXAMPLE
    # Rollback — restore MIG-IP references into original groups
    # Use this if Phase 1 needs to be undone. Includes a safety confirmation prompt.
    .\Remove-NSX-MIGIPGroups.ps1 -NSXManager nsx01.local `
        -InputFolder C:\Migration -RollbackVMGroups $true

.EXAMPLE
    # Dry Run — Rollback (What-If)
    # Shows which groups would be restored without making any changes.
    .\Remove-NSX-MIGIPGroups.ps1 -NSXManager nsx01.local `
        -InputFolder C:\Migration -RollbackVMGroups $true -WhatIf

.NOTES
    Changelog:
      1.0.0  Initial release.
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$NSXManager,
    [Parameter(Mandatory)][string]$InputFolder,
    [ValidateSet('Skip','Overwrite','Prompt','Abort')]
    [string]$ConflictAction   = 'Skip',
    [string]$DomainId         = 'default',
    [bool]$DeleteMIGIPGroups  = $false,
    [bool]$PatchVMGroups      = $false,
	[bool]$RollbackVMGroups = $false,
    [string]$LogFile   = (Join-Path $InputFolder "Delete-NSX-MIG-IP_-Groups_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"),
    [ValidateSet('Screen','File','Both')]
    [string]$LogTarget = 'Both'
)

$ScriptVersion = '1.0.0'

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
            # Explicitly set -WhatIf:$false so logs are written even during dry runs
			Add-Content -Path $LogFile -Value $line -Encoding UTF8 -WhatIf:$false
        } catch {
            Write-Host "[WARN] Could not write to log file: $_" -ForegroundColor Yellow
            Write-Host $line -ForegroundColor $color
        }
    }
}

Write-Log "Delete-NSX-MIG-IP_-Groups.ps1 v$ScriptVersion" INFO

# ─────────────────────────────────────────────────────────────
# IGNORE SELF-SIGNED CERTIFICATES
# ─────────────────────────────────────────────────────────────
<# if (-not ([System.Management.Automation.PSTypeName]'TrustAllCerts').Type) {
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
[System.Net.ServicePointManager]::SecurityProtocol  = [System.Net.SecurityProtocolType]::Tls12 #>

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

#$Script:CsvPath_MIGIPGroups        = $null
#$Script:CsvPath_VMGroups           = $null
$Script:CsvPath_FinalGroups = $null

#if ($CreateMIGIPGroups)        { $Script:CsvPath_MIGIPGroups   = Resolve-CsvFile -Label 'MIG-IP_ Groups' }
#if ($PatchVMGroups)            { $Script:CsvPath_VMGroups      = Resolve-CsvFile -Label 'Security VM Groups' }

# Only trigger the picker if at least one action is requested
if ($DeleteMIGIPGroups -or $PatchVMGroups -or $RollbackVMGroups) {
    $Script:CsvPath_FinalGroups = Resolve-CsvFile -Label 'NSX_MIGIP_Groups_Final.csv'
}

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

function Invoke-NSXDelete {
    param([string]$Path)
    $uri = "https://$NSXManager$Path"
    try {
        Invoke-RestMethod -Uri $uri -Method DELETE -Headers $Headers | Out-Null
        return $true
    } catch {
        $detail = if ($_.ErrorDetails -and $_.ErrorDetails.Message) { " | Detail: $($_.ErrorDetails.Message)" } else { '' }
        Write-Log "DELETE $uri failed: $_$detail" ERROR
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
$Stats = @{ 
    MIGIP_Deleted       = 0; 
    VMGroupsPatched     = 0; 
    GroupsRestored      = 0;
    Skipped             = 0; 
    Errors              = 0; 
    WhatIf_MIGIPCount   = 0; 
    WhatIf_VMGroupCount = 0;
    WhatIf_RollbackCount= 0
}

# ═════════════════════════════════════════════════════════════
# 1. DELETE MIG-IP GROUPS
# ═════════════════════════════════════════════════════════════
function Delete-MIGIPGroups {
    Write-Log "━━━ Phase 2: Deleting MIG-IP Helper Groups ━━━" INFO
    $csvPath = $Script:CsvPath_FinalGroups
    $rows    = Read-CsvFile -ResolvedPath $csvPath -Label 'NSX_MIGIP_Groups_Final.csv'
    if (-not $rows) { return }

    foreach ($row in $rows) {
        # Only process rows where Id starts with MIG-IP_
        if ($row.Id -notlike 'MIG-IP_*') {
            continue
        }

        $migName = $row.Id
        $path    = "/policy/api/v1/infra/domains/$DomainId/groups/$migName"

        # Skip if group doesn't exist — nothing to delete
        if (-not (Test-ObjectExists -Path $path)) {
            Write-Log "  Group $migName not found. Skipping deletion." INFO
            $Stats.Skipped++
            continue
        }

        if ($PSCmdlet.ShouldProcess($migName, "Delete MIG-IP Group")) {
            $ok = Invoke-NSXDelete -Path $path
            if ($ok) {
                $Stats.MIGIP_Deleted++
                Write-Log "  ✔ Deleted: $migName" SUCCESS
            } else {
                $Stats.Errors++
            }
        }
        else {
            $Stats.WhatIf_MIGIPCount++
        }
    }
}

# ═════════════════════════════════════════════════════════════
# DEPENDENCY HELPER FUNCTIONS
# ═════════════════════════════════════════════════════════════
function Get-GroupDependencies {
    param([string]$JsonPayload)
    $deps = @()
    if ([string]::IsNullOrWhiteSpace($JsonPayload)) { return $deps }

    try {
        $obj = $JsonPayload | ConvertFrom-Json
        # Check if 'expression' property exists
        $expressions = if ($obj.PSObject.Properties['expression']) { @($obj.expression) } else { @() }
        
        foreach ($expr in $expressions) {
            $resType = if ($expr.PSObject.Properties['resource_type']) { $expr.resource_type } else { '' }

            # CASE 1: Nested Expressions (Original NSX Logic)
            if ($resType -eq 'NestedExpression') {
                $nestedExprs = if ($expr.PSObject.Properties['expressions']) { @($expr.expressions) } else { @() }
                foreach ($ne in $nestedExprs) {
                    $nePath = if ($ne.PSObject.Properties['path']) { $ne.path } else { $null }
                    # Regex extracts 'GroupName' from '/infra/domains/default/groups/GroupName'
                    if ($nePath -and $nePath -match '/groups/([^/]+)$') { $deps += $Matches[1] }
                }
            }
            
            # CASE 2: Path Expressions (This includes your new MIG-IP references)
            if ($resType -eq 'PathExpression') {
                $paths = if ($expr.PSObject.Properties['paths']) { @($expr.paths) } else { @() }
                foreach ($p in $paths) {
                    if ($p -match '/groups/([^/]+)$') { $deps += $Matches[1] }
                }
            }
        }
    } catch { 
        Write-Log "    Could not parse group dependencies: $_" WARN 
    }
    return $deps | Select-Object -Unique
}

function Sort-GroupsByDependency {
    param([object[]]$Rows)
    
    $lookup = @{}
    $depMap = @{}

    foreach ($r in $Rows) {
        # Determine which JSON to analyze for dependencies
        # Use UpdatedRawJson if it exists and isn't an error, otherwise fallback to RawJson
        $jsonToAnalyze = if (-not [string]::IsNullOrWhiteSpace($r.UpdatedRawJson) -and $r.UpdatedRawJson -ne "ERROR_PARSING") {
            $r.UpdatedRawJson
        } else {
            $r.RawJson
        }

        $lookup[$r.Id] = $r
        $depMap[$r.Id] = @(Get-GroupDependencies -JsonPayload $jsonToAnalyze)
    }

    $sorted   = [System.Collections.Generic.List[object]]::new()
    $visited  = @{} # 0=unvisited, 1=visiting, 2=visited
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
                
                # If the dependency is not in our CSV (e.g., a system group), skip it
                if (-not $lookup.ContainsKey($depId)) { continue }

                $depState = if ($visited.ContainsKey($depId)) { $visited[$depId] } else { 0 }
                
                if ($depState -eq 1) { 
                    Write-Log "    Circular group dependency detected between '$id' and '$depId' — continuing." WARN 
                    continue 
                }
                
                if ($depState -eq 2) { continue }

                $visited[$depId] = 1
                $stack.Push(@{ Id = $depId; Deps = @($depMap[$depId]); Index = 0 })
            } else {
                # Finished processing all dependencies for this node
                $stack.Pop() | Out-Null
                $visited[$id] = 2
                if (-not $inResult[$id] -and $lookup.ContainsKey($id)) { 
                    $sorted.Add($lookup[$id])
                    $inResult[$id] = $true 
                }
            }
        }
    }
    return $sorted.ToArray()
}

# ═════════════════════════════════════════════════════════════
# 2. PATCH SECURITY VM GROUPS with MIG-IP_ groups
# ═════════════════════════════════════════════════════════════
function Patch-ExistingGroupsWithoutMIGIP {
    Write-Log "━━━ Phase 1: Patching Original Groups — Removing MIG-IP References ━━━" INFO
    #$csvPath = $Script:CsvPath_VMGroups
	$csvPath = $Script:CsvPath_FinalGroups
    #$rows    = Read-CsvFile -ResolvedPath $csvPath -Label 'Security VM Groups'
    $rows    = Read-CsvFile -ResolvedPath $csvPath -Label 'NSX_MIGIP_Groups_Final.csv'
	if (-not $rows) { return }

    # 1. We must sort because Group A might be a member of Group B
    Write-Log "  Sorting original groups by dependency..." INFO
    $sortedRows = Sort-GroupsByDependency -Rows @($rows)

    foreach ($row in $sortedRows) {
        # Only process if we have an UpdatedRawJson (meaning a patch is required)
        if ([string]::IsNullOrWhiteSpace($row.UpdatedRawJson) -or $row.UpdatedRawJson -eq "ERROR_PARSING") {
            Write-Log "  Skipping $($row.DisplayName): No updates required." INFO
            continue
        }

        $id   = $row.Id
        $path = "/policy/api/v1/infra/domains/$DomainId/groups/$id"

        # Note: We use PATCH here to update the existing group
        if ($PSCmdlet.ShouldProcess($id, "Patch Group without MIG-IP_ group Logic")) {
            $ok = Invoke-NSXPatch -Path $path -JsonBody $row.UpdatedRawJson
            if ($ok) { 
                $Stats.VMGroupsPatched++
                Write-Log "  ✔ Patched: $id ($($row.DisplayName))" SUCCESS 
            } else { 
                $Stats.Errors++ 
            }
        }
		else {
			$Stats.WhatIf_VMGroupCount++
		}
	}
}

# ═════════════════════════════════════════════════════════════
# 3. ROLLBACK SECURITY VM GROUPS
# ═════════════════════════════════════════════════════════════
function Restore-OriginalGroups {
    Write-Log "━━━ ROLLBACK: Restoring Original VM Group Logic ━━━" WARN
    
    # Safety Prompt
    $title   = "Confirm NSX Rollback"
    $message = "This will overwrite existing NSX group configurations with the original 'RawJson' data from your CSV. Are you sure you want to proceed?"
    if (-not $PSCmdlet.ShouldContinue($message, $title)) {
        Write-Log "Rollback cancelled by user." WARN
        return
    }

    #$csvPath = $Script:CsvPath_VMGroups
    $csvPath = $Script:CsvPath_FinalGroups
	#$rows    = Read-CsvFile -ResolvedPath $csvPath -Label 'Security VM Groups'
    $rows    = Read-CsvFile -ResolvedPath $csvPath -Label 'NSX_MIGIP_Groups_Final.csv'
	if (-not $rows) { return }

    Write-Log "  Sorting groups for safe restoration..." INFO
    $sortedRows = Sort-GroupsByDependency -Rows @($rows)

    foreach ($row in $sortedRows) {
		# Only process rows where Id does NOT start with MIG-IP_
        if ($row.Id -like 'MIG-IP_*') {
            continue
        }

        # Only rollback rows that were actually patched in the forward pass
        if ([string]::IsNullOrWhiteSpace($row.UpdatedRawJson) -or $row.UpdatedRawJson -eq "ERROR_PARSING") {
            Write-Log "  Skipping $($row.DisplayName): No patch was applied, nothing to restore." INFO
            $Stats.Skipped++
            continue
        }
		
        $id   = $row.Id
        $path = "/policy/api/v1/infra/domains/$DomainId/groups/$id"

        if ($PSCmdlet.ShouldProcess($id, "Restore Original Logic")) {
            $ok = Invoke-NSXPatch -Path $path -JsonBody $row.RawJson
            if ($ok) {
                Write-Log "  ✔ Restored: $id ($($row.DisplayName))" SUCCESS
                $Stats.GroupsRestored++
            } else {
                $Stats.Errors++
            }
        } else {
            $Stats.WhatIf_RollbackCount++
        }
    }
}

# ═════════════════════════════════════════════════════════════
# MAIN
# ═════════════════════════════════════════════════════════════
$anyAction = $DeleteMIGIPGroups -or $PatchVMGroups -or $RollbackVMGroups
if (-not $anyAction) {
    Write-Log "No actions selected. Specify at least one -Create*, -Patch* or -Rollback* flag." WARN
    Write-Log "Example: -CreateMIGIPGroups `$true -PatchVMGroups `$true" WARN
    exit 0
}

Write-Log "══════════════════════════════════════════════════" INFO
Write-Log " NSX VM-TO-IP GROUP IMPORT" INFO
Write-Log " Destination : $NSXManager" INFO
Write-Log " Input folder: $InputFolder" INFO
Write-Log " Conflict    : $ConflictAction" INFO
Write-Log " Domain      : $DomainId" INFO
Write-Log "══════════════════════════════════════════════════" INFO
Write-Log " Delete MIG-IP_ groups     : $DeleteMIGIPGroups" INFO
Write-Log " Patch Security VM Groups  : $PatchVMGroups" INFO
Write-Log " Rollback VM Groups        : $RollbackVMGroups" INFO
Write-Log " CSV files are selected upfront before import starts." INFO
Write-Log "══════════════════════════════════════════════════" INFO

try {
    Write-Log "Verifying connectivity to $NSXManager..." INFO
    $info = Invoke-NSXGet -Path "/api/v1/node"
    if ($info) { Write-Log "  Connected: NSX $($info.product_version)" SUCCESS }
    else        { throw "Cannot connect to NSX Manager $NSXManager." }

    if ($DeleteMIGIPGroups) { Delete-MIGIPGroups   }
	if ($PatchVMGroups) { Patch-ExistingGroupsWithoutMIGIP   }
	if ($RollbackVMGroups) { Restore-OriginalGroups }
    
} catch {
    Write-Log "FATAL: $_" ERROR
    exit 1
} finally {
    Write-Log "════════════════════════════════════════════════════════" INFO
    Write-Log " IMPORT SUMMARY" INFO
    Write-Log "────────────────────────────────────────────────────────" INFO
    
    # Dry Run Logic
    if ($Stats.WhatIf_MIGIPCount -gt 0 -or $Stats.WhatIf_VMGroupCount -gt 0 -or $Stats.WhatIf_RollbackCount -gt 0) {
        Write-Log " [DRY RUN - NO CHANGES WERE MADE]" WARN
        if ($Stats.WhatIf_MIGIPCount -gt 0)    { Write-Log "  MIG-IP Groups to Delete     : $($Stats.WhatIf_MIGIPCount)" INFO }
        if ($Stats.WhatIf_VMGroupCount -gt 0)  { Write-Log "  VM Groups to Patch          : $($Stats.WhatIf_VMGroupCount)" INFO }
        if ($Stats.WhatIf_RollbackCount -gt 0) { Write-Log "  VM Groups to Restore        : $($Stats.WhatIf_RollbackCount)" INFO }
    } 
    else {
        # Live Results logic
        if ($Stats.MIGIP_Deleted -gt 0)      { Write-Log "  MIG-IP Groups Deleted       : $($Stats.MIGIP_Deleted)" SUCCESS }
        if ($Stats.VMGroupsPatched -gt 0)    { Write-Log "  VM Groups Patched           : $($Stats.VMGroupsPatched)" SUCCESS }
        if ($Stats.GroupsRestored -gt 0)      { Write-Log "  VM Groups Restored          : $($Stats.GroupsRestored)" SUCCESS }
        
        if ($Stats.MIGIP_Deleted -eq 0 -and $Stats.VMGroupsPatched -eq 0 -and $Stats.GroupsRestored -eq 0 -and $Stats.Errors -eq 0) {
            Write-Log "  No changes performed. Environment is stable." SUCCESS
        }
    }

    Write-Log "  Skipped (Existing/Unchanged): $($Stats.Skipped)" WARN
    Write-Log "  Errors Encountered          : $($Stats.Errors)" $(if ($Stats.Errors -gt 0) { 'ERROR' } else { 'INFO' })
    Write-Log "────────────────────────────────────────────────────────" INFO
    Write-Log " Log file: $LogFile" INFO
    Write-Log "════════════════════════════════════════════════════════" INFO
}