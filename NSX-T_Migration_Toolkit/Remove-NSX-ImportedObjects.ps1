#Requires -Version 5.1
<#
.SYNOPSIS
    Removes NSX DFW objects that were previously imported using Import-NSX-DFW.ps1.

.DESCRIPTION
    Reads the same CSV files produced by Export-NSX-DFW.ps1 and deletes the
    corresponding objects from the destination NSX Manager. This allows you to
    cleanly roll back a migration and start over.

    Deletion order is the reverse of import order to respect dependencies:
      1. DFW Rules
      2. DFW Policies
      3. Security Groups
      4. Service Groups
      5. Services
      6. IP Sets

    VM tags are not deleted but can be cleared (set to empty) using -ClearVMTags.

    NOTE: This script does NOT touch system-owned objects.

.PARAMETER NSXManager
    FQDN or IP of the NSX Manager to clean up.

.PARAMETER InputFolder
    Folder containing the CSV files from the export step.

.PARAMETER DomainId
    NSX Policy domain. Default: "default"

.PARAMETER RemoveIPSets
    Remove imported IP Sets. Default: $false

.PARAMETER RemoveServices
    Remove imported Services. Default: $false

.PARAMETER RemoveServiceGroups
    Remove imported Service Groups. Default: $false

.PARAMETER RemoveGroups
    Remove imported Security Groups. Default: $false

.PARAMETER RemovePolicies
    Remove imported DFW Policies and all their Rules. Default: $false

.PARAMETER ClearVMTags
    Clear (empty) tags on VMs listed in NSX_VMTags.csv. Default: $false

.PARAMETER LogFile
    Path to a log file. Required when -LogTarget is 'File' or 'Both'.

.PARAMETER LogTarget
    Controls where log output is written.
      Screen : colored output to the console only (default)
      File   : write to -LogFile only, no console output
      Both   : colored console output AND written to -LogFile

.EXAMPLE
    # Dry run first — see what would be deleted without making changes
    .\Remove-NSX-ImportedObjects.ps1 -NSXManager nsx9.corp.local -InputFolder .\NSX_DFW_Export_20250101_120000 -WhatIf

.EXAMPLE
    # Remove only policies and groups
    .\Remove-NSX-ImportedObjects.ps1 -NSXManager nsx9.corp.local -InputFolder .\NSX_DFW_Export_20250101_120000 `
        -RemovePolicies $true -RemoveGroups $true

.EXAMPLE
    # Remove everything including VM tags
    .\Remove-NSX-ImportedObjects.ps1 -NSXManager nsx9.corp.local -InputFolder .\NSX_DFW_Export_20250101_120000 `
        -RemovePolicies $true -RemoveGroups $true -RemoveServiceGroups $true `
        -RemoveServices $true -RemoveIPSets $true -ClearVMTags $true

.NOTES
    Changelog:
      1.0.0  Initial release.
      1.1.0  Added $ScriptVersion variable and startup version log line.
      1.1.1  Renamed reserved automatic variable $pid to $policyId.
      1.2.0  Merged Remove-ServiceGroups and Remove-Services into one
             dependency-ordered function. Service groups and services are
             now sorted topologically (dependents deleted first) using the
             same iterative DFS used for security groups.
	  1.3.0  DvG, modified csv file names to sanitized file names and made sure logging is written during -WhatIf. Added WhatIf stats also.
#>

[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory)][string]$NSXManager,
    [Parameter(Mandatory)][string]$InputFolder,
    [string]$DomainId            = 'default',
    [bool]$RemoveIPSets          = $false,
    [bool]$RemoveServices        = $false,
    [bool]$RemoveServiceGroups   = $false,
    [bool]$RemoveGroups          = $false,
    [bool]$RemovePolicies        = $false,
    [bool]$ClearVMTags           = $false,
    [string]$LogFile   = (Join-Path $InputFolder "Remove-NSX-ImportedObjects_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"),
    [ValidateSet('Screen','File','Both')]
    [string]$LogTarget = 'Both'
)

$ScriptVersion = '1.3.0'

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
            Add-Content -Path $LogFile -Value $line -Encoding UTF8 -WhatIf:$false
        } catch {
            Write-Host "[WARN] Could not write to log file: $_" -ForegroundColor Yellow
            Write-Host $line -ForegroundColor $color
        }
    }
}

Write-Log "Remove-NSX-ImportedObjects.ps1 v$ScriptVersion" INFO

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
Write-Log "Enter credentials for NSX Manager: $NSXManager"
$Cred    = Get-Credential -Message "NSX 9 ($NSXManager) credentials"
$pair    = "$($Cred.UserName):$($Cred.GetNetworkCredential().Password)"
$bytes   = [System.Text.Encoding]::ASCII.GetBytes($pair)
$Headers = @{
    Authorization  = "Basic $([Convert]::ToBase64String($bytes))"
    'Content-Type' = 'application/json'
}

# ─────────────────────────────────────────────────────────────
# REST HELPERS
# ─────────────────────────────────────────────────────────────
function Invoke-NSXGet {
    param([string]$Path)
    $uri = "https://$NSXManager$Path"
    try {
        return Invoke-RestMethod -Uri $uri -Method GET -Headers $Headers
    } catch { return $null }
}

function Invoke-NSXDelete {
    param([string]$Path)
    $uri = "https://$NSXManager$Path"
    try {
        Invoke-RestMethod -Uri $uri -Method DELETE -Headers $Headers | Out-Null
        return $true
    } catch {
        Write-Log "DELETE $uri failed: $_" ERROR
        return $false
    }
}

function Invoke-NSXPost {
    param([string]$Path, [string]$JsonBody)
    $uri = "https://$NSXManager$Path"
    try {
        Invoke-RestMethod -Uri $uri -Method POST -Headers $Headers -Body $JsonBody | Out-Null
        return $true
    } catch {
        Write-Log "POST $uri failed: $_" ERROR
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
# ─────────────────────────────────────────────────────────────
function Read-CsvFile {
    param([string]$FileName)
    $path = Join-Path $InputFolder $FileName
    if (-not (Test-Path $path)) {
        Write-Log "CSV not found, skipping: $path" WARN
        return @()
    }
    $rows = Import-Csv -Path $path -Encoding UTF8
    Write-Log "  Loaded $(@($rows).Count) rows from $FileName" INFO
    return $rows
}

# ─────────────────────────────────────────────────────────────
# STATISTICS
# ─────────────────────────────────────────────────────────────
$Stats = @{
	Policies=0;
	Rules=0;
	Groups=0;
	ServiceGroups=0;
	Services=0;
	IPSets=0;
	VMsCleared=0;
	NotFound=0;
	Errors=0;
	WhatIf_Policies=0;
	WhatIf_Rules=0;
	WhatIf_Groups=0;
	WhatIf_Services=0
}

# ═════════════════════════════════════════════════════════════
# 1. REMOVE DFW POLICIES
# ═════════════════════════════════════════════════════════════
function Remove-Policies {
    Write-Log "━━━ Removing DFW Policies ━━━" INFO
    $policyRows = Read-CsvFile 'NSX_Policies_sanitized.csv'
    $ruleRows   = Read-CsvFile 'NSX_Rules_sanitized.csv'
    if (-not $policyRows) { return }

    $ruleCount = @{}
    foreach ($r in $ruleRows) {
        $policyId = $r.PolicyId
        $ruleCount[$policyId] = ($ruleCount[$policyId] -as [int]) + 1
    }

    $policyRows = $policyRows | Sort-Object { [int]$_.SequenceNumber } -Descending

    foreach ($row in $policyRows) {
        $polId = $row.Id
        $path  = "/policy/api/v1/infra/domains/$DomainId/security-policies/$polId"

        if (-not (Test-ObjectExists -Path $path)) {
            Write-Log "  NOT FOUND: Policy '$polId' — already removed or never imported." WARN
            $Stats.NotFound++; continue
        }

        $rCount = if ($ruleCount[$polId]) { $ruleCount[$polId] } else { 0 }

        if ($PSCmdlet.ShouldProcess("Policy '$polId' ($($row.DisplayName)) + $rCount rule(s)", "DELETE")) {
            $ok = Invoke-NSXDelete -Path $path
            if ($ok) {
                $Stats.Policies++
                $Stats.Rules += $rCount
                Write-Log "  ✔ Deleted Policy: $polId ($($row.DisplayName)) — $rCount rule(s) removed" SUCCESS
            } else { $Stats.Errors++ }
        }
		else {
			$Stats.WhatIf_Policies++
			$Stats.WhatIf_Rules += $rCount
		}
    }
}

# ═════════════════════════════════════════════════════════════
# 2. REMOVE SECURITY GROUPS
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
    } catch {}
    return $deps | Select-Object -Unique
}

function Sort-GroupsForDeletion {
    param([object[]]$Rows)
    $lookup = @{}
    $depMap = @{}
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
                if ($depState -eq 1) { Write-Log "    Circular group dependency between '$id' and '$depId'." WARN; continue }
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

    $arr = $sorted.ToArray()
    [Array]::Reverse($arr)
    return $arr
}

function Remove-Groups {
    Write-Log "━━━ Removing Security Groups ━━━" INFO
    $rows = Read-CsvFile 'NSX_Groups_sanitized.csv'
    if (-not $rows) { return }

    Write-Log "  Resolving group deletion order..." INFO
    $rows = Sort-GroupsForDeletion -Rows @($rows)

    foreach ($row in $rows) {
        $id   = $row.Id
        $path = "/policy/api/v1/infra/domains/$DomainId/groups/$id"

        if (-not (Test-ObjectExists -Path $path)) {
            Write-Log "  NOT FOUND: Group '$id' — already removed or never imported." WARN
            $Stats.NotFound++; continue
        }

        if ($PSCmdlet.ShouldProcess("Group '$id' ($($row.DisplayName))", "DELETE")) {
            $ok = Invoke-NSXDelete -Path $path
            if ($ok) { $Stats.Groups++; Write-Log "  ✔ Deleted Group: $id ($($row.DisplayName))" SUCCESS }
            else      { $Stats.Errors++ }
        }
		else {
			$Stats.WhatIf_Groups++
		}
    }
}

# ═════════════════════════════════════════════════════════════
# 3 & 4. REMOVE SERVICE GROUPS AND SERVICES  (dependency-ordered)
#
# Service groups reference plain services via their members[] array.
# Plain services can also reference other services via
# NestedServiceServiceEntry. Both CSV files are combined into one
# dependency-ordered list and deleted dependents-first (service groups
# before the plain services they reference, nested services before the
# services that wrap them).
# ═════════════════════════════════════════════════════════════
function Get-ServiceDependencies {
    param([string]$RawJson)
    $deps = @()
    try {
        $obj = $RawJson | ConvertFrom-Json

        # ServiceGroup members[] — each member.path points to a service or
        # service group by /infra/services/<id>
        $members = if ($obj.PSObject.Properties['members']) { $obj.members } else { @() }
        foreach ($member in $members) {
            $mPath = if ($member.PSObject.Properties['path']) { $member.path } else { $null }
            if ($mPath -and $mPath -match '/services/([^/]+)$') { $deps += $Matches[1] }
        }

        # NestedServiceServiceEntry inside service_entries[]
        $entries = if ($obj.PSObject.Properties['service_entries']) { $obj.service_entries } else { @() }
        foreach ($entry in $entries) {
            $resType = if ($entry.PSObject.Properties['resource_type']) { $entry.resource_type } else { '' }
            if ($resType -eq 'NestedServiceServiceEntry') {
                $nPath = if ($entry.PSObject.Properties['nested_service_path']) { $entry.nested_service_path } else { $null }
                if ($nPath -and $nPath -match '/services/([^/]+)$') { $deps += $Matches[1] }
            }
        }
    } catch {}
    return $deps | Select-Object -Unique
}

function Sort-ServicesForDeletion {
    <# Topological sort in reverse using an iterative post-order DFS.
       Combines service group rows and plain service rows into one ordered list.
       Returns rows ordered so dependents (service groups, nested services) are
       deleted before the services they depend on. #>
    param([object[]]$Rows)

    $lookup = @{}
    $depMap = @{}
    foreach ($r in $Rows) {
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
                if ($depState -eq 1) { Write-Log "    Circular service dependency between '$id' and '$depId'." WARN; continue }
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

    # Reverse: dependents must be deleted before their dependencies
    $arr = $sorted.ToArray()
    [Array]::Reverse($arr)
    return $arr
}

function Remove-Services {
    Write-Log "━━━ Removing Service Groups and Services ━━━" INFO

    $sgRows  = Read-CsvFile 'NSX_ServiceGroups.csv'
    $svcRows = Read-CsvFile 'NSX_Services_sanitized.csv'

    $allRows = @($sgRows) + @($svcRows)
    if (-not $allRows) { Write-Log "  No Service Groups or Services found in CSVs." WARN; return }

    Write-Log "  Found $(@($sgRows).Count) service group(s) and $(@($svcRows).Count) service(s). Resolving deletion order..." INFO
    $ordered = Sort-ServicesForDeletion -Rows $allRows

    foreach ($row in $ordered) {
        $id      = $row.Id
        $path    = "/policy/api/v1/infra/services/$id"
        $isGroup = $row.ObjectType -eq 'ServiceGroup'
        $label   = if ($isGroup) { 'Service Group' } else { 'Service' }

        if (-not (Test-ObjectExists -Path $path)) {
            Write-Log "  NOT FOUND: $($label) '$id' — already removed or never imported." WARN
            $Stats.NotFound++; continue
        }

        if ($PSCmdlet.ShouldProcess("$($label) '$id' ($($row.DisplayName))", "DELETE")) {
            $ok = Invoke-NSXDelete -Path $path
            if ($ok) {
                if ($isGroup) { $Stats.ServiceGroups++ } else { $Stats.Services++ }
                Write-Log "  ✔ Deleted $($label): $id ($($row.DisplayName))" SUCCESS
            } else { $Stats.Errors++ }
        }
		else {
			$Stats.WhatIf_Services++
		}
    }
}

# ═════════════════════════════════════════════════════════════
# 5. REMOVE IP SETS
# ═════════════════════════════════════════════════════════════
function Remove-IPSets {
    Write-Log "━━━ Removing IP Sets ━━━" INFO
    $rows = Read-CsvFile 'NSX_IPSets.csv'
    if (-not $rows) { return }

    foreach ($row in $rows) {
        $id   = $row.Id
        $path = "/api/v1/ip-sets/$id"

        if (-not (Test-ObjectExists -Path $path)) {
            Write-Log "  NOT FOUND: IP Set '$id' — already removed or never imported." WARN
            $Stats.NotFound++; continue
        }

        if ($PSCmdlet.ShouldProcess("IP Set '$id' ($($row.DisplayName))", "DELETE")) {
            $ok = Invoke-NSXDelete -Path $path
            if ($ok) { $Stats.IPSets++; Write-Log "  ✔ Deleted IP Set: $id ($($row.DisplayName))" SUCCESS }
            else      { $Stats.Errors++ }
        }
    }
}

# ═════════════════════════════════════════════════════════════
# 6. CLEAR VM TAGS
# ═════════════════════════════════════════════════════════════
function Clear-VMTags {
    Write-Log "━━━ Clearing VM Tags ━━━" INFO
    $rows = Read-CsvFile 'NSX_VMTags.csv'
    if (-not $rows) { return }

    $vmIds = $rows | Select-Object -ExpandProperty ExternalId -Unique

    foreach ($eid in $vmIds) {
        $vmName   = ($rows | Where-Object { $_.ExternalId -eq $eid } | Select-Object -First 1).VMDisplayName
        $checkUri = "https://$NSXManager/api/v1/fabric/virtual-machines?external_id=$eid&included_fields=display_name"

        try {
            $checkResp = Invoke-RestMethod -Uri $checkUri -Method GET -Headers $Headers
            if (-not $checkResp.results -or $checkResp.results.Count -eq 0) {
                Write-Log "  NOT FOUND: VM '$vmName' ($eid) not in destination inventory." WARN
                $Stats.NotFound++; continue
            }
        } catch {
            Write-Log "  Could not verify VM '$vmName' ($eid): $_" WARN
            $Stats.NotFound++; continue
        }

        $body = @{ external_id = $eid; tags = @() } | ConvertTo-Json -Depth 3 -Compress

        if ($PSCmdlet.ShouldProcess("VM '$vmName' ($eid)", "Clear all tags")) {
            $ok = Invoke-NSXPost -Path "/api/v1/fabric/virtual-machines?action=update_tags" -JsonBody $body
            if ($ok) { $Stats.VMsCleared++; Write-Log "  ✔ Cleared tags on VM: $vmName" SUCCESS }
            else      { $Stats.Errors++ }
        }
    }
}

# ═════════════════════════════════════════════════════════════
# VALIDATE INPUT FOLDER
# ═════════════════════════════════════════════════════════════
if (-not (Test-Path $InputFolder)) {
    Write-Log "Input folder not found: $InputFolder" ERROR
    exit 1
}
$InputFolder = (Resolve-Path $InputFolder).Path

# ═════════════════════════════════════════════════════════════
# MAIN
# ═════════════════════════════════════════════════════════════
Write-Log "════════════════════════════════════════════" INFO
Write-Log " NSX DFW ROLLBACK / CLEANUP" INFO
Write-Log " Target       : $NSXManager" INFO
Write-Log " Input folder : $InputFolder" INFO
Write-Log " Domain       : $DomainId" INFO
Write-Log " Clear VM Tags: $ClearVMTags" INFO
Write-Log "════════════════════════════════════════════" INFO
Write-Log " WARNING: This will permanently delete imported objects!" WARN
Write-Log " Run with -WhatIf first to preview deletions." WARN
Write-Log "════════════════════════════════════════════" INFO

try {
    Write-Log "Verifying connectivity to $NSXManager..." INFO
    $info = Invoke-NSXGet -Path "/api/v1/node"
    if ($info) { Write-Log "  Connected: NSX $($info.product_version)" SUCCESS }
    else        { throw "Cannot connect to NSX Manager $NSXManager." }

    if ($RemovePolicies)                               { Remove-Policies }
    if ($RemoveGroups)                                 { Remove-Groups   }
    if ($RemoveServiceGroups -or $RemoveServices)      { Remove-Services }
    if ($RemoveIPSets)                                 { Remove-IPSets   }
    if ($ClearVMTags)                                  { Clear-VMTags    }

} catch {
    Write-Log "FATAL: $_" ERROR
    exit 1
} finally {
    Write-Log "════════════════════════════════════════════" INFO
    Write-Log " REMOVAL SUMMARY" INFO
    Write-Log "────────────────────────────────────────────" INFO
    Write-Log "  Policies deleted         : $($Stats.Policies)"      INFO
    Write-Log "  Rules removed (with pol) : $($Stats.Rules)"         INFO
    Write-Log "  Groups deleted           : $($Stats.Groups)"        INFO
    Write-Log "  Service Groups deleted   : $($Stats.ServiceGroups)" INFO
    Write-Log "  Services deleted         : $($Stats.Services)"      INFO
    Write-Log "  IP Sets deleted          : $($Stats.IPSets)"        INFO
    Write-Log "  VMs tags cleared         : $($Stats.VMsCleared)"    INFO
    Write-Log "  Not found (skipped)      : $($Stats.NotFound)"      WARN
    Write-Log "  Errors                   : $($Stats.Errors)"        $(if ($Stats.Errors -gt 0) { 'ERROR' } else { 'INFO' })
	Write-Log "  Policies to delete       : $($Stats.WhatIf_Policies)"      INFO
    Write-Log "  Rules to remove (with pol): $($Stats.WhatIf_Rules)"         INFO
    Write-Log "  Groups to delete         : $($Stats.WhatIf_Groups)"        INFO
    Write-Log "  Services to delete       : $($Stats.WhatIf_Services)"      INFO
    Write-Log "════════════════════════════════════════════" INFO
}