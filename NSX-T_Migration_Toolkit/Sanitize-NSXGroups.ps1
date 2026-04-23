# =============================================================================
# Sanitize-NSXGroups.ps1
# Version 1.0.0
#
# PURPOSE
# -------
# In NSX exports, a group's Id (internal identifier) often differs from its
# DisplayName (human-readable label). For example:
#
#   Id: securitygroup-223   DisplayName: Datacenter
#   Id: ipset-286           DisplayName: IPNET_1314-ETZ_Beheer_ICT
#   Id: securitygroup-70    DisplayName: L2-Infra-ICT-management
#
# This script renames every group Id to match its DisplayName, and updates
# all group-to-group cross-references so paths remain consistent throughout
# the export.
#
# WHAT GETS CHANGED
# -----------------
# For each group where Id != DisplayName:
#
#   CSV columns:
#     - Id  ->  set to DisplayName
#     - Tags -> cleared (unless the tag is in use — see TAG SAFETY CHECK below)
#
#   Inside RawJson:
#     - "id":"<oldId>"             ->  "id":"<newId>"
#     - "relative_path":"<oldId>" ->  "relative_path":"<newId>"
#     - Any /groups/<oldId>/ or /groups/<oldId>" path segment
#       (covers path, parent_path, and paths[] arrays in PathExpressions)
#     - "tags":[...]               ->  "tags":[] (unless tag is in use)
#
# TAG SAFETY CHECK
# ----------------
# Before any tags are removed, this script queries the live NSX Manager API
# to discover which tag scope:value pairs are actively referenced inside
# security group Condition expressions (key = "Tag"). These are the tags that
# drive dynamic group membership — removing them would silently break firewall
# coverage without any API error.
#
# Behaviour when a tag IS found to be in use:
#   - The tag is KEPT in both the CSV Tags column and RawJson "tags" array.
#   - A WARNING is written to the console identifying the tag and the group(s)
#     that reference it.
#   - The sanitization run continues normally for all other objects.
#
# Provide -NSXManager and -Headers (or let the script prompt for credentials)
# to enable the live check. If -NSXManager is omitted, the check is skipped
# and ALL tags are removed (original behaviour — use with caution).
#
# OUTPUTS
# -------
#   <InputFile>_sanitized.csv  — groups CSV with corrected Ids and RawJson
#   <InputFile>_id_mapping.csv — audit log of every oldId -> newId rename
#                                (only written in standalone mode; the
#                                 orchestrator handles this itself)
#
# USAGE
# -----
#   # Standalone with tag safety check:
#   .\Sanitize-NSXGroups.ps1 -InputFile "groups.csv" -NSXManager "nsx4.corp.local"
#
#   # Standalone without tag check (original behaviour):
#   .\Sanitize-NSXGroups.ps1 -InputFile "groups.csv"
#
#   # Called from Sanitize-NSX.ps1 — returns the idMap hashtable directly:
#   $idMap = .\Sanitize-NSXGroups.ps1 -InputFile "groups.csv" `
#                -NSXManager "nsx4.corp.local" -Headers $Headers -PassThruMap
# =============================================================================

[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$InputFile,
    [string]$OutputFile  = ($InputFile -replace '\.csv$', '_sanitized.csv'),
    [string]$MappingFile = ($InputFile -replace '\.csv$', '_id_mapping.csv'),

    # NSX Manager connection — required for the live tag-in-use check.
    # If omitted the check is skipped and all tags are removed unconditionally.
    [string]   $NSXManager = '',
    [hashtable]$Headers    = @{},
    [string]   $DomainId   = 'default',

    # When set, skips writing the mapping CSV and returns the hashtable to the
    # caller (used by Sanitize-NSX.ps1 so it can pass the map straight to the
    # rules script without an intermediate file).
    [switch]$PassThruMap
)

Write-Host "Sanitize-NSXGroups.ps1 v1.0.0" -ForegroundColor Cyan

# ---------------------------------------------------------------------------
# 0. Dot-source the shared tag checker
# ---------------------------------------------------------------------------
$tagCheckerPath = Join-Path $PSScriptRoot 'Get-NSXTagsInUse.ps1'
if (Test-Path $tagCheckerPath) {
    . $tagCheckerPath
} else {
    Write-Warning "Get-NSXTagsInUse.ps1 not found alongside this script — tag safety check will be skipped."
}

# ---------------------------------------------------------------------------
# 1. Resolve NSX credentials if a manager was specified but no headers passed
# ---------------------------------------------------------------------------
$inUseTags = @{}

if ($NSXManager) {
    if ($Headers.Count -eq 0) {
        Write-Host "  [TagCheck] Enter credentials for NSX Manager: $NSXManager" -ForegroundColor Cyan
        $cred  = Get-Credential -Message "NSX ($NSXManager) credentials for tag check"
        $pair  = "$($cred.UserName):$($cred.GetNetworkCredential().Password)"
        $bytes = [System.Text.Encoding]::ASCII.GetBytes($pair)
        $Headers = @{
            Authorization  = "Basic $([Convert]::ToBase64String($bytes))"
            'Content-Type' = 'application/json'
        }

        # Trust self-signed certificates
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
    }

    if (Get-Command 'Get-NSXTagsInUse' -ErrorAction SilentlyContinue) {
        $inUseTags = Get-NSXTagsInUse -GroupsCsv $InputFile -NSXManager $NSXManager -Headers $Headers -DomainId $DomainId
    } else {
        Write-Warning "Get-NSXTagsInUse function not available — tag safety check skipped."
    }
} else {
    # No API — still run the CSV-only phase if the function is available
    if (Get-Command 'Get-NSXTagsInUse' -ErrorAction SilentlyContinue) {
        Write-Host "  [TagCheck] -NSXManager not provided — running CSV-only tag check (system-owned groups will not be scanned)." -ForegroundColor Yellow
        $inUseTags = Get-NSXTagsInUse -GroupsCsv $InputFile
    } else {
        Write-Host "  [TagCheck] Get-NSXTagsInUse not available — tag safety check skipped. ALL tags will be removed." -ForegroundColor Yellow
    }
}

# ---------------------------------------------------------------------------
# 2. Load the groups CSV
# ---------------------------------------------------------------------------
Write-Host "  [Groups] Reading: $InputFile" -ForegroundColor Cyan
$rows = Import-Csv -Path $InputFile

# ---------------------------------------------------------------------------
# 3. Build the old-ID -> new-ID mapping table
# ---------------------------------------------------------------------------
function Sanitize-Id {
    param([string]$value)
    return [regex]::Replace($value.Trim(), '[^a-zA-Z0-9_-]', '-')
}

$idMap = @{}

# Pass 1 — count occurrences of each sanitized DisplayName
$displayCount = @{}
foreach ($row in $rows) {
    $sanitized = Sanitize-Id $row.DisplayName
    if ($displayCount.ContainsKey($sanitized)) { $displayCount[$sanitized]++ }
    else                                        { $displayCount[$sanitized] = 1 }
}

# Pass 2 — assign newIds with deduplication suffixes
$displayCounter = @{}
foreach ($row in $rows) {
    $oldId     = $row.Id.Trim()
    $sanitized = Sanitize-Id $row.DisplayName

    if ($displayCount[$sanitized] -gt 1) {
        if (-not $displayCounter.ContainsKey($sanitized)) { $displayCounter[$sanitized] = 1 }
        $suffix = $displayCounter[$sanitized]
        $displayCounter[$sanitized]++
        $newId = "$sanitized-$suffix"
        Write-Warning "Duplicate DisplayName '$sanitized' — assigned '$newId' to Id '$oldId'."
    } else {
        $newId = $sanitized
    }

    if ($oldId -ne $newId) {
        if ($idMap.ContainsKey($oldId)) { Write-Warning "Duplicate old ID '$oldId' — skipping." }
        else                            { $idMap[$oldId] = $newId }
    }
}

Write-Host "  [Groups] $($idMap.Count) ID(s) need renaming." -ForegroundColor Yellow

# ---------------------------------------------------------------------------
# 4. Helpers
# ---------------------------------------------------------------------------

function Decode-UnicodeEscapes {
    <#
.SYNOPSIS
    Decodes Unicode escape sequences (e.g., \u0024) into their literal characters.
.DESCRIPTION
    This function uses a Regular Expression to find occurrences of '\u' followed by 
    four hexadecimal digits. For each match, it:
    1. Captures the 4-digit hex code (e.g., '0024').
    2. Converts that hex string into a 32-bit Integer (Base 16).
    3. Casts that Integer into a [char] to reveal the symbol (e.g., '$').
.PARAMETER text
    The string containing the Unicode escape sequences to be decoded.
.EXAMPLE
    Decode-UnicodeEscapes -text "The price is \u002410"
    # Output: The price is $10
#>
    param([string]$text)
    return [regex]::Replace($text, '\\u([0-9a-fA-F]{4})', {
        param($m)
        [char][convert]::ToInt32($m.Groups[1].Value, 16)
    })
}

function Update-GroupPaths {
    <#
.SYNOPSIS
    Updates group IDs within URL paths based on a provided mapping table.
.DESCRIPTION
    This function iterates through a mapping object ($idMap) to replace old IDs with new ones.
    To prevent "partial matching" (e.g., replacing '12' inside '123'), it sorts keys by length 
    descending and uses Regex Lookarounds to ensure the ID is specifically within a '/groups/' path.
.PARAMETER text
    The string or document content containing the paths to be updated.
.NOTES
    This function assumes a global or script-scope variable `$idMap` exists (a Hashtable 
    where keys are Old IDs and values are New IDs).
#>
    param([string]$text)
    $sortedKeys = $idMap.Keys | Sort-Object { $_.Length } -Descending
    foreach ($oldId in $sortedKeys) {
        $escaped = [regex]::Escape($oldId)
        $text = [regex]::Replace($text, "(?<=/groups/)$escaped(?=/|""|$)", $idMap[$oldId])
    }
    return $text
}

function Remove-Tags {
    <# Removes tags from a RawJson string, but KEEPS any tag whose scope|value
       or bare value is found in $inUseTags (actively used in group expressions).
       Emits a warning for every tag that is kept. #>
    param([string]$json, [string]$objectId)

    try {
        $obj  = $json | ConvertFrom-Json
        $tags = if ($obj.PSObject.Properties['tags']) { @($obj.tags) } else { @() }

        if ($tags.Count -eq 0) {
            # Nothing to remove — return json unchanged
            return $json
        }

        $keep    = [System.Collections.Generic.List[object]]::new()
        $removed = [System.Collections.Generic.List[string]]::new()

        foreach ($tag in $tags) {
            $scope = if ($tag.PSObject.Properties['scope']) { $tag.scope } else { '' }
            $value = if ($tag.PSObject.Properties['tag']  ) { $tag.tag   } else { '' }

            # NSX Tag condition values use "scope|value" when a scope is set,
            # or bare "value" when there is no scope qualifier
            $keyWithScope = if ($scope) { "$scope|$value" } else { $null }
            $keyBare      = $value

            $usedBy = @()
            if ($keyWithScope -and $inUseTags[$keyWithScope]) { $usedBy += $inUseTags[$keyWithScope] }
            if ($keyBare      -and $inUseTags[$keyBare]      ) { $usedBy += $inUseTags[$keyBare]      }
            $usedBy = $usedBy | Select-Object -Unique

            if ($usedBy.Count -gt 0) {
                $keep.Add($tag)
                Write-Host ("  [TagCheck] WARN: Keeping tag '$scope`:$value' on '$objectId' " +
                            "— referenced by group(s): $($usedBy -join ', ')") -ForegroundColor Yellow
            } else {
                $removed.Add("$scope`:$value")
            }
        }

        $obj.tags = $keep.ToArray()
        return ($obj | ConvertTo-Json -Depth 20 -Compress)

    } catch {
        # If JSON parsing fails, fall back to regex strip (original behaviour)
        Write-Host "  [TagCheck] Could not parse tags for '$objectId' — using regex fallback: $_" -ForegroundColor Yellow
        return [regex]::Replace($json, '"tags":\[.*?\]', '"tags":[]')
    }
}

# ---------------------------------------------------------------------------
# 5. Apply changes to every row
# ---------------------------------------------------------------------------
$mappingLog = [System.Collections.Generic.List[PSCustomObject]]::new()

foreach ($row in $rows) {
    $oldId = $row.Id.Trim()

    $row.RawJson = Decode-UnicodeEscapes -text $row.RawJson

    if ($idMap.ContainsKey($oldId)) {
        $newId      = $idMap[$oldId]
        $oldDisplay = $row.DisplayName.Trim()

        $row.Id          = $newId
        $row.DisplayName = $newId

        $json = Update-GroupPaths -text $row.RawJson

        $esc  = [regex]::Escape($oldId)
        $json = $json -replace """id"":""$esc""",            """id"":""$newId"""
        $json = $json -replace """relative_path"":""$esc""", """relative_path"":""$newId"""
        $escOldDisplay = [regex]::Escape($oldDisplay)
        $json = $json -replace """display_name"":""$escOldDisplay""", """display_name"":""$newId"""

        $json        = Remove-Tags -json $json -objectId $newId
        $row.RawJson = $json

        $mappingLog.Add([PSCustomObject]@{ OldId = $oldId; NewId = $newId })
    } else {
        $row.RawJson = Remove-Tags -json (Update-GroupPaths -text $row.RawJson) -objectId $oldId
    }

    # Rebuild the Tags CSV column from whatever tags survived the check
    try {
        $obj  = $row.RawJson | ConvertFrom-Json
        $tags = if ($obj.PSObject.Properties['tags']) { @($obj.tags) } else { @() }
        if ($tags.Count -gt 0) {
            $row.Tags = ($tags | ForEach-Object {
                $s = if ($_.PSObject.Properties['scope']) { $_.scope } else { '' }
                $v = if ($_.PSObject.Properties['tag']  ) { $_.tag   } else { '' }
                "$s`:$v"
            }) -join '; '
        } else {
            $row.Tags = ''
        }
    } catch {
        $row.Tags = ''
    }
}

# ---------------------------------------------------------------------------
# 6. Write the sanitized groups CSV
# ---------------------------------------------------------------------------
Write-Host "  [Groups] Writing: $OutputFile" -ForegroundColor Cyan
$rows | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8

# ---------------------------------------------------------------------------
# 7. Return the map or write it to CSV
# ---------------------------------------------------------------------------
if ($PassThruMap) {
    return $idMap
} else {
    Write-Host "  [Groups] Writing mapping log: $MappingFile" -ForegroundColor Cyan
    $mappingLog | Export-Csv -Path $MappingFile -NoTypeInformation -Encoding UTF8

    Write-Host ""
    Write-Host "Done! $($mappingLog.Count) group(s) renamed." -ForegroundColor Green
    #if ($mappingLog.Count -gt 0) { $mappingLog | Format-Table -AutoSize }
}