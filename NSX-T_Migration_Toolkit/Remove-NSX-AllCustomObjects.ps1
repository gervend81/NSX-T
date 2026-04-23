#Requires -Version 5.1
<#
.SYNOPSIS
    Removes all custom (non-system-owned) NSX DFW objects directly from inventory.

.DESCRIPTION
    Queries the NSX Manager live inventory and removes all user-created DFW objects.
    Unlike Remove-NSX-ImportedObjects.ps1, this script does NOT require CSV files —
    it discovers objects directly from the NSX Manager and removes them.

    Deletion order respects dependencies:
      1. DFW Rules
      2. DFW Policies
      3. Context Profiles
      4. Security Groups  (dependency-ordered)
      5. Service Groups
      6. Services
      7. IP Sets

    VM tags are never deleted automatically. Use -ClearVMTags $true to clear them,
    which will prompt for a tag scope filter to avoid wiping unrelated tags.

    All object types are opt-in and default to $false for safety.
    Use -WhatIf to preview all deletions before committing.

    NOTE: System-owned objects are never touched by this script.

.PARAMETER NSXManager
    FQDN or IP of the NSX Manager to clean up.

.PARAMETER DomainId
    NSX Policy domain. Default: "default"

.PARAMETER RemoveIPSets
    Remove all custom IP Sets. Default: $false

.PARAMETER RemoveServices
    Remove all custom Services. Default: $false

.PARAMETER RemoveServiceGroups
    Remove all custom Service Groups. Default: $false

.PARAMETER RemoveGroups
    Remove all custom Security Groups. Default: $false

.PARAMETER RemoveProfiles
    Remove all custom Context Profiles. Default: $false
    Only non-system-owned profiles are removed. System profiles bundled with
    NSX are never touched. Profiles are deleted after policies and rules,
    since rules may reference profiles by path.

.PARAMETER RemovePolicies
    Remove all custom DFW Policies and their Rules. Default: $false

.PARAMETER ClearVMTags
    Clear tags on all VMs in the NSX fabric inventory.
    You will be prompted for an optional tag scope filter (e.g. "env") to limit
    which tags are cleared. Leave blank to clear ALL tags on ALL VMs.
    Default: $false

.PARAMETER LogFile
    Path to a log file. Required when -LogTarget is 'File' or 'Both'.

.PARAMETER LogTarget
    Controls where log output is written.
      Screen : colored output to the console only (default)
      File   : write to -LogFile only, no console output
      Both   : colored console output AND written to -LogFile

.EXAMPLE
    # Preview everything that would be removed
    .\Remove-NSX-AllCustomObjects.ps1 -NSXManager nsx9.corp.local -WhatIf `
        -RemovePolicies $true -RemoveProfiles $true -RemoveGroups $true `
        -RemoveServiceGroups $true -RemoveServices $true -RemoveIPSets $true

.EXAMPLE
    # Remove only policies and groups
    .\Remove-NSX-AllCustomObjects.ps1 -NSXManager nsx9.corp.local `
        -RemovePolicies $true -RemoveGroups $true

.EXAMPLE
    # Full cleanup of all custom DFW objects
    .\Remove-NSX-AllCustomObjects.ps1 -NSXManager nsx9.corp.local `
        -RemovePolicies $true -RemoveProfiles $true -RemoveGroups $true `
        -RemoveServiceGroups $true -RemoveServices $true -RemoveIPSets $true

.EXAMPLE
    # Full cleanup including VM tags scoped to "env"
    .\Remove-NSX-AllCustomObjects.ps1 -NSXManager nsx9.corp.local `
        -RemovePolicies $true -RemoveProfiles $true -RemoveGroups $true `
        -RemoveServiceGroups $true -RemoveServices $true -RemoveIPSets $true `
        -ClearVMTags $true

.NOTES
    Changelog:
      1.0.0  Initial release.
      1.1.0  Merged Remove-ServiceGroups and Remove-Services into one
             dependency-ordered function. Service groups and services are
             now sorted topologically (dependents deleted first) using the
             same iterative DFS used for security groups.
      1.2.0  Added -RemoveProfiles flag and Remove-Profiles function for
             custom Context Profiles. Profiles are deleted after policies
             and rules (step 3) and before security groups.
#>

[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory)][string]$NSXManager,
    [string]$DomainId            = 'default',
    [bool]$RemoveIPSets          = $false,
    [bool]$RemoveServices        = $false,
    [bool]$RemoveServiceGroups   = $false,
    [bool]$RemoveGroups          = $false,
    [bool]$RemoveProfiles        = $false,
    [bool]$RemovePolicies        = $false,
    [bool]$ClearVMTags           = $false,
    [string]$LogFile   = '',
    [ValidateSet('Screen','File','Both')]
    [string]$LogTarget = 'Screen'
)

$ScriptVersion = '1.2.0'

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ─────────────────────────────────────────────────────────────
# Groups known to be system-managed but not flagged as _system_owned.
# These are provisioned by NSX Threat Intelligence, IDS/IPS, and related services.
# ─────────────────────────────────────────────────────────────
$pseudoSystemGroupIds = @(
    'DefaultMaliciousIpGroup',
    'DefaultUDAGroup',
    'Datacenter'
)

# ─────────────────────────────────────────────────────────────
# Policies known to be system-managed but not flagged as _system_owned.
# NSX will reject DELETE requests for these with a 400/403 error.
# ─────────────────────────────────────────────────────────────
$pseudoSystemPolicyIds = @(
    'default-layer-3-section',
    'default-malicious-ip-block-rules',
    'default-layer2-section'
)

# ─────────────────────────────────────────────────────────────
# LOGGING
# ─────────────────────────────────────────────────────────────
function Write-Log {
    <# Writes a timestamped log line to the screen, a file, or both.
       Controlled by the -LogTarget and -LogFile script parameters.
         Screen : colored output to the console only (default)
         File   : writes to $LogFile only (no console output)
         Both   : colored console output AND appends to $LogFile
    #>
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
            # Fall back to screen if file write fails
            Write-Host "[WARN] Could not write to log file: $_" -ForegroundColor Yellow
            Write-Host $line -ForegroundColor $color
        }
    }
}

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
$Cred    = Get-Credential -Message "NSX ($NSXManager) credentials"
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
    } catch {
        Write-Log "GET $uri failed: $_" ERROR
        return $null
    }
}

function Get-AllPages {
    param([string]$Path)
    $allResults = @()
    $cursor     = $null
    do {
        $url  = if ($cursor) { "${Path}?cursor=$cursor" } else { $Path }
        $resp = Invoke-NSXGet -Path $url
        if ($null -eq $resp) { break }
        if ($resp.PSObject.Properties['results'] -and $resp.results) { $allResults += $resp.results }
        $cursor = if ($resp.PSObject.Properties['cursor']) { $resp.cursor } else { $null }
    } while ($cursor)
    return $allResults
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

function Get-SafeProp {
    param([object]$Obj, [string]$Name)
    if ($Obj.PSObject.Properties[$Name]) { return $Obj.$Name }
    return $null
}

# ─────────────────────────────────────────────────────────────
# STATISTICS
# ─────────────────────────────────────────────────────────────
$Stats = @{ Policies=0; Rules=0; Profiles=0; Groups=0; ServiceGroups=0; Services=0; IPSets=0; VMsCleared=0; Errors=0 }

# ═════════════════════════════════════════════════════════════
# 1. REMOVE DFW POLICIES
# ═════════════════════════════════════════════════════════════
function Remove-Policies {
    Write-Log "━━━ Removing DFW Policies ━━━" INFO
    $policies = Get-AllPages -Path "/policy/api/v1/infra/domains/$DomainId/security-policies"
    $custom = $policies | Where-Object {
      if ((Get-SafeProp $_ '_system_owned') -eq $true) { return $false }
      if ($_.id -in $pseudoSystemPolicyIds) {
        Write-Log "  Skipping protected policy: $($_.id)" WARN
        return $false
      }
      return $true
   }

    if (-not $custom) { Write-Log "  No custom DFW Policies found." WARN; return }

    # Fetch rule counts for reporting, then delete highest sequence first
    $custom = $custom | Sort-Object -Property sequence_number -Descending

    foreach ($pol in $custom) {
        $polId = $pol.id
        $path  = "/policy/api/v1/infra/domains/$DomainId/security-policies/$polId"

        # Count rules for reporting
        $rules  = Get-AllPages -Path "/policy/api/v1/infra/domains/$DomainId/security-policies/$polId/rules"
        $rCount = @($rules).Count

        if ($PSCmdlet.ShouldProcess("Policy '$polId' ($($pol.display_name)) + $rCount rule(s)", "DELETE")) {
            $ok = Invoke-NSXDelete -Path $path
            if ($ok) {
                $Stats.Policies++
                $Stats.Rules += $rCount
                Write-Log "  ✔ Deleted Policy: $polId ($($pol.display_name)) — $rCount rule(s)" SUCCESS
            } else {
                $Stats.Errors++
            }
        }
    }
}

# ═════════════════════════════════════════════════════════════
# 3. REMOVE CONTEXT PROFILES
# ═════════════════════════════════════════════════════════════
function Remove-Profiles {
    Write-Log "━━━ Removing Context Profiles ━━━" INFO
    $all    = Get-AllPages -Path "/policy/api/v1/infra/context-profiles"
    $custom = $all | Where-Object { (Get-SafeProp $_ '_system_owned') -ne $true }

    if (-not $custom) { Write-Log "  No custom Context Profiles found." WARN; return }

    Write-Log "  Found $(@($custom).Count) custom Context Profile(s)." INFO

    foreach ($prof in $custom) {
        $id   = $prof.id
        $path = "/policy/api/v1/infra/context-profiles/$id"

        if ($PSCmdlet.ShouldProcess("Context Profile '$id' ($($prof.display_name))", "DELETE")) {
            $ok = Invoke-NSXDelete -Path $path
            if ($ok) { $Stats.Profiles++; Write-Log "  ✔ Deleted Context Profile: $id ($($prof.display_name))" SUCCESS }
            else      { $Stats.Errors++ }
        }
    }
}

# ═════════════════════════════════════════════════════════════
# 4. REMOVE SECURITY GROUPS  (dependency-ordered)
# ═════════════════════════════════════════════════════════════
function Get-GroupDependencies {
    param([object]$Grp)
    $deps       = @()
    $expressions = Get-SafeProp $Grp 'expression'
    if (-not $expressions) { return $deps }

    foreach ($expr in $expressions) {
        $resType = Get-SafeProp $expr 'resource_type'

        if ($resType -eq 'NestedExpression') {
            $nested = Get-SafeProp $expr 'expressions'
            if ($nested) {
                foreach ($ne in $nested) {
                    $nePath = Get-SafeProp $ne 'path'
                    if ($nePath -and $nePath -match '/groups/([^/]+)$') { $deps += $Matches[1] }
                }
            }
        }

        if ($resType -eq 'PathExpression') {
            $paths = Get-SafeProp $expr 'paths'
            if ($paths) {
                foreach ($p in $paths) {
                    if ($p -match '/groups/([^/]+)$') { $deps += $Matches[1] }
                }
            }
        }
    }
    return $deps | Select-Object -Unique
}

function Sort-GroupsForDeletion {
    <# Topological sort in reverse using an iterative post-order DFS.
       PowerShell does not support nested functions, so recursion is avoided.
       Returns groups ordered so dependents are deleted before their dependencies. #>
    param([object[]]$Groups)

    $lookup = @{}
    $depMap = @{}
    foreach ($g in $Groups) {
        $lookup[$g.id] = $g
        $depMap[$g.id] = @(Get-GroupDependencies -Grp $g)
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

                if ($depState -eq 1) {
                    Write-Log "    Circular group dependency between '$id' and '$depId'." WARN
                    continue
                }
                if ($depState -eq 2) { continue }

                $visited[$depId] = 1
                $stack.Push(@{ Id = $depId; Deps = @($depMap[$depId]); Index = 0 })
            } else {
                $stack.Pop() | Out-Null
                $visited[$id] = 2
                if (-not $inResult[$id] -and $lookup.ContainsKey($id)) {
                    $sorted.Add($lookup[$id])
                    $inResult[$id] = $true
                }
            }
        }
    }

    # Reverse: dependents must be deleted before their dependencies
    $arr = $sorted.ToArray()
    [Array]::Reverse($arr)
    return $arr
}

function Remove-Groups {
    Write-Log "━━━ Removing Security Groups ━━━" INFO
    $groups    = Get-AllPages -Path "/policy/api/v1/infra/domains/$DomainId/groups"
    $custom = $groups | Where-Object {
      if ((Get-SafeProp $_ '_system_owned') -ne $true -and (Get-SafeProp $_ '_create_user')  -ne 'system') { return $false }
      if ($_.id -notin $pseudoSystemGroupIds) {
        Write-Log " Skipping protected group: $($_.id)" WARN
        return $false
    }
      return $true
    }

    if (-not $custom) { Write-Log "  No custom Security Groups found." WARN; return }

    Write-Log "  Found $($custom.Count) custom groups. Resolving deletion order..." INFO
    $ordered = Sort-GroupsForDeletion -Groups $custom

    foreach ($grp in $ordered) {
        $id   = $grp.id
        $path = "/policy/api/v1/infra/domains/$DomainId/groups/$id"

        if ($PSCmdlet.ShouldProcess("Group '$id' ($($grp.display_name))", "DELETE")) {
            $ok = Invoke-NSXDelete -Path $path
            if ($ok) { $Stats.Groups++; Write-Log "  ✔ Deleted Group: $id ($($grp.display_name))" SUCCESS }
            else      { $Stats.Errors++ }
        }
    }
}

# ═════════════════════════════════════════════════════════════
# 5 & 6. REMOVE SERVICE GROUPS AND SERVICES  (dependency-ordered)
#
# Service groups reference plain services via their members[] array.
# Plain services can also wrap other services via NestedServiceServiceEntry.
# Both types are fetched together, sorted topologically, and deleted
# dependents-first so NSX never sees a DELETE on an object that still has
# an active reference — which would produce a 400 Bad Request.
# ═════════════════════════════════════════════════════════════
function Get-ServiceDependencies {
    param([object]$Svc)
    $deps = @()

    # ServiceGroup members[] — each member.path = /infra/services/<id>
    $members = Get-SafeProp $Svc 'members'
    if ($members) {
        foreach ($member in $members) {
            $mPath = Get-SafeProp $member 'path'
            if ($mPath -and $mPath -match '/services/([^/]+)$') { $deps += $Matches[1] }
        }
    }

    # NestedServiceServiceEntry inside service_entries[]
    $entries = Get-SafeProp $Svc 'service_entries'
    if ($entries) {
        foreach ($entry in $entries) {
            $resType = Get-SafeProp $entry 'resource_type'
            if ($resType -eq 'NestedServiceServiceEntry') {
                $nPath = Get-SafeProp $entry 'nested_service_path'
                if ($nPath -and $nPath -match '/services/([^/]+)$') { $deps += $Matches[1] }
            }
        }
    }

    return $deps | Select-Object -Unique
}

function Sort-ServicesForDeletion {
    <# Topological sort in reverse using an iterative post-order DFS.
       Returns objects ordered so dependents (service groups, nested wrappers)
       are deleted before the services they depend on. #>
    param([object[]]$Services)

    $lookup = @{}
    $depMap = @{}
    foreach ($s in $Services) {
        $lookup[$s.id] = $s
        $depMap[$s.id] = @(Get-ServiceDependencies -Svc $s)
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

                if ($depState -eq 1) {
                    Write-Log "    Circular service dependency between '$id' and '$depId'." WARN
                    continue
                }
                if ($depState -eq 2) { continue }

                $visited[$depId] = 1
                $stack.Push(@{ Id = $depId; Deps = @($depMap[$depId]); Index = 0 })
            } else {
                $stack.Pop() | Out-Null
                $visited[$id] = 2
                if (-not $inResult[$id] -and $lookup.ContainsKey($id)) {
                    $sorted.Add($lookup[$id])
                    $inResult[$id] = $true
                }
            }
        }
    }

    # Reverse: dependents must be deleted before their dependencies
    $arr = $sorted.ToArray()
    [Array]::Reverse($arr)
    return $arr
}

function Remove-ServicesAndGroups {
    Write-Log "━━━ Removing Service Groups and Services ━━━" INFO
    $all = Get-AllPages -Path "/policy/api/v1/infra/services"

    # Collect service groups and plain services into one list, excluding system-owned
    $custom = @($all | Where-Object { (Get-SafeProp $_ '_system_owned') -ne $true })

    if (-not $custom) { Write-Log "  No custom Services or Service Groups found." WARN; return }

    $sgCount  = @($custom | Where-Object { (Get-SafeProp $_ 'resource_type') -eq 'PolicyServiceGroup' }).Count
    $svcCount = $custom.Count - $sgCount
    Write-Log "  Found $sgCount service group(s) and $svcCount service(s). Resolving deletion order..." INFO

    $ordered = Sort-ServicesForDeletion -Services $custom

    foreach ($svc in $ordered) {
        $id      = $svc.id
        $path    = "/policy/api/v1/infra/services/$id"
        $isGroup = (Get-SafeProp $svc 'resource_type') -eq 'PolicyServiceGroup'
        $label   = if ($isGroup) { 'Service Group' } else { 'Service' }

        if ($PSCmdlet.ShouldProcess("${label} '$id' ($($svc.display_name))", "DELETE")) {
            $ok = Invoke-NSXDelete -Path $path
            if ($ok) {
                if ($isGroup) { $Stats.ServiceGroups++ } else { $Stats.Services++ }
                Write-Log "  ✔ Deleted ${label}: $id ($($svc.display_name))" SUCCESS
            } else {
                $Stats.Errors++
            }
        }
    }
}

# ═════════════════════════════════════════════════════════════
# 7. REMOVE IP SETS
# ═════════════════════════════════════════════════════════════
function Remove-IPSets {
    Write-Log "━━━ Removing IP Sets ━━━" INFO
    $all = Get-AllPages -Path "/api/v1/ip-sets"

    if (-not $all) { Write-Log "  No IP Sets found." WARN; return }

    foreach ($obj in $all) {
        # Management plane IP sets do not have _system_owned — all are user-created
        $id   = $obj.id
        $path = "/api/v1/ip-sets/$id"

        if ($PSCmdlet.ShouldProcess("IP Set '$id' ($($obj.display_name))", "DELETE")) {
            $ok = Invoke-NSXDelete -Path $path
            if ($ok) { $Stats.IPSets++; Write-Log "  ✔ Deleted IP Set: $id ($($obj.display_name))" SUCCESS }
            else      { $Stats.Errors++ }
        }
    }
}

# ═════════════════════════════════════════════════════════════
# 8. CLEAR VM TAGS  (optional, with scope filter)
# ═════════════════════════════════════════════════════════════
function Clear-VMTags {
    Write-Log "━━━ Clearing VM Tags ━━━" INFO

    # Prompt for an optional scope filter to avoid clearing unrelated tags
    $scopeFilter = Read-Host "  Enter tag scope to clear (e.g. 'env', 'tier') — leave blank to clear ALL tags on ALL VMs"

    if ($scopeFilter) {
        Write-Log "  Scope filter: '$scopeFilter' — only tags with this scope will be cleared." WARN
    } else {
        Write-Log "  No scope filter — ALL tags on ALL VMs will be cleared." WARN
        $confirm = Read-Host "  Are you sure you want to clear ALL tags on ALL VMs? Type YES to confirm"
        if ($confirm -ne 'YES') {
            Write-Log "  Aborted by user." WARN
            return
        }
    }

    $vms = Get-AllPages -Path "/api/v1/fabric/virtual-machines?included_fields=display_name,external_id,tags"
    if (-not $vms) { Write-Log "  No VMs found in fabric inventory." WARN; return }

    # Filter to VMs that actually have tags matching the scope filter
    $targetVMs = $vms | Where-Object {
        $tags = Get-SafeProp $_ 'tags'
        if (-not $tags) { return $false }
        if ($scopeFilter) {
            return ($tags | Where-Object { (Get-SafeProp $_ 'scope') -eq $scopeFilter }).Count -gt 0
        }
        return $true
    }

    if (-not $targetVMs) {
        Write-Log "  No VMs with matching tags found." WARN
        return
    }

    Write-Log "  Found $(@($targetVMs).Count) VMs with matching tags." INFO

    foreach ($vm in $targetVMs) {
        $eid    = $vm.external_id
        $name   = $vm.display_name
        $tags   = Get-SafeProp $vm 'tags'

        # If scope filter set: retain tags that do NOT match the scope
        # If no scope filter: send empty array to clear all tags
        $remainingTags = @()
        if ($scopeFilter -and $tags) {
            $remainingTags = @($tags | Where-Object { (Get-SafeProp $_ 'scope') -ne $scopeFilter })
        }

        $body = @{ external_id = $eid; tags = $remainingTags } | ConvertTo-Json -Depth 5 -Compress

        if ($PSCmdlet.ShouldProcess("VM '$name' ($eid)", "Clear tags$(if ($scopeFilter) { " with scope '$scopeFilter'" })")) {
            $ok = Invoke-NSXPost -Path "/api/v1/fabric/virtual-machines?action=update_tags" -JsonBody $body
            if ($ok) {
                $Stats.VMsCleared++
                Write-Log "  ✔ Cleared tags on VM: $name" SUCCESS
            } else {
                $Stats.Errors++
            }
        }
    }
}

# ═════════════════════════════════════════════════════════════
# MAIN
# ═════════════════════════════════════════════════════════════

# Guard — refuse to run if no action flags are set
$anyAction = $RemovePolicies -or $RemoveProfiles -or $RemoveGroups -or $RemoveServiceGroups -or
             $RemoveServices -or $RemoveIPSets -or $ClearVMTags

if (-not $anyAction) {
    Write-Log "No actions selected. Specify at least one -Remove* or -ClearVMTags flag." WARN
    Write-Log "Example: -RemovePolicies `$true -RemoveGroups `$true" WARN
    exit 0
}

Write-Log "════════════════════════════════════════════" INFO
Write-Log " NSX INVENTORY-BASED CLEANUP" INFO
Write-Log " Target          : $NSXManager" INFO
Write-Log " Domain          : $DomainId" INFO
Write-Log " Remove Policies : $RemovePolicies" INFO
Write-Log " Remove Profiles : $RemoveProfiles" INFO
Write-Log " Remove Groups   : $RemoveGroups" INFO
Write-Log " Remove Svc Grps : $RemoveServiceGroups" INFO
Write-Log " Remove Services : $RemoveServices" INFO
Write-Log " Remove IP Sets  : $RemoveIPSets" INFO
Write-Log " Clear VM Tags   : $ClearVMTags" INFO
Write-Log "════════════════════════════════════════════" INFO
Write-Log " WARNING: Deletes ALL custom objects of selected types!" WARN
Write-Log " Run with -WhatIf first to preview deletions." WARN
Write-Log "════════════════════════════════════════════" INFO

try {
    Write-Log "Verifying connectivity to $NSXManager..." INFO
    $info = Invoke-NSXGet -Path "/api/v1/node"
    if ($info) { Write-Log "  Connected: NSX $($info.product_version)" SUCCESS }
    else        { throw "Cannot connect to NSX Manager $NSXManager." }

    if ($RemovePolicies)                          { Remove-Policies          }
    if ($RemoveProfiles)                          { Remove-Profiles          }
    if ($RemoveServiceGroups -or $RemoveServices) { Remove-ServicesAndGroups }
    if ($RemoveGroups)                            { Remove-Groups            }
    if ($RemoveIPSets)                            { Remove-IPSets            }
    if ($ClearVMTags)                             { Clear-VMTags             }

} catch {
    Write-Log "FATAL: $_" ERROR
    exit 1
} finally {
    Write-Log "════════════════════════════════════════════" INFO
    Write-Log " CLEANUP SUMMARY" INFO
    Write-Log "────────────────────────────────────────────" INFO
    Write-Log "  Policies deleted         : $($Stats.Policies)"      INFO
    Write-Log "  Rules removed (with pol) : $($Stats.Rules)"         INFO
    Write-Log "  Profiles deleted         : $($Stats.Profiles)"      INFO
    Write-Log "  Groups deleted           : $($Stats.Groups)"        INFO
    Write-Log "  Service Groups deleted   : $($Stats.ServiceGroups)" INFO
    Write-Log "  Services deleted         : $($Stats.Services)"      INFO
    Write-Log "  IP Sets deleted          : $($Stats.IPSets)"        INFO
    Write-Log "  VMs tags cleared         : $($Stats.VMsCleared)"    INFO
    Write-Log "  Errors                   : $($Stats.Errors)"        $(if ($Stats.Errors -gt 0) { 'ERROR' } else { 'INFO' })
    Write-Log "════════════════════════════════════════════" INFO


}