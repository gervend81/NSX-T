# =============================================================================
# Sanitize-NSXServices.ps1
#
# PURPOSE
# -------
# In NSX exports, a service's Id (internal identifier) can differ from its
# DisplayName (human-readable label). For example:
#
#   Id: application-228   DisplayName: HTTP-8080
#   Id: application-317   DisplayName: Custom-LDAP-TCP
#   Id: applicationgroup-45  DisplayName: Web-Services-Group
#
# This script renames every Service and ServiceGroup Id to match its
# DisplayName, and updates all service-to-service cross-references inside
# ServiceGroup members so paths remain consistent throughout the export.
#
# WHAT GETS CHANGED
# -----------------
# For each Service or ServiceGroup where Id != DisplayName:
#
#   CSV columns:
#     - Id          ->  set to sanitized DisplayName
#     - DisplayName ->  set to sanitized DisplayName
#     - Tags        ->  cleared (see tag removal below)
#
#   Inside RawJson:
#     - "id":"<oldId>"              ->  "id":"<newId>"
#     - "relative_path":"<oldId>"   ->  "relative_path":"<newId>"
#     - "display_name":"<oldName>"  ->  "display_name":"<newId>"
#     - Any /services/<oldId>/ or /services/<oldId>" path segment
#       (covers ServiceGroup member path references)
#     - "tags":[...]                ->  "tags":[]
#
# TAG REMOVAL
# -----------
# Services and ServiceGroups may carry tags that are migration artefacts from
# NSX-V. These are removed from both the CSV Tags column and the "tags" array
# in RawJson for all rows, regardless of whether the Id needed renaming.
#
# SERVICEGROUP MEMBER REFERENCES
# ---------------------------------
# ServiceGroup objects contain a "members" array in RawJson where each entry
# has a "path" field pointing to a service or service group by its NSX path:
#   /infra/services/<id>
#
# When a referenced service's Id is renamed, that path becomes stale. This
# script rewrites all such member paths using the same ID mapping table,
# similar to how Sanitize-NSXFirewallRules.ps1 rewrites /groups/ references.
#
# OUTPUTS
# -------
#   <InputFile>_sanitized.csv  — services/service groups CSV with corrected
#                                Ids and RawJson
#   <InputFile>_id_mapping.csv — audit log of every oldId -> newId rename
#                                (only written in standalone mode; the
#                                 orchestrator handles this itself)
#
# USAGE
# -----
#   # Standalone — processes services and writes both output files:
#   .\Sanitize-NSXServices.ps1 -InputFile "NSX_Services.csv"
#
#   # Also accepts the ServiceGroups CSV (same output structure, same endpoint):
#   .\Sanitize-NSXServices.ps1 -InputFile "NSX_ServiceGroups.csv"
#
#   # Called from the orchestrator — returns the idMap hashtable directly:
#   $serviceIdMap = .\Sanitize-NSXServices.ps1 -InputFile "NSX_Services.csv" -PassThruMap
#
# NOTES
# -----
#   - If you are sanitizing both NSX_Services.csv and NSX_ServiceGroups.csv,
#     process Services first so the ID map is complete before ServiceGroups
#     are processed. ServiceGroups reference Services by path and need the
#     full map available at rewrite time.
#   - This script follows the same conventions as Sanitize-NSXGroups.ps1.
#     See that script's header for a full explanation of the shared patterns
#     (duplicate handling, Unicode escape decoding, longest-key-first sort).
# =============================================================================

[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$InputFile,
    [string]$OutputFile  = ($InputFile -replace '\.csv$', '_sanitized.csv'),
    [string]$MappingFile = ($InputFile -replace '\.csv$', '_id_mapping.csv'),

    # When set, skips writing the mapping CSV and returns the hashtable to the
    # caller (used by an orchestrator so it can pass the map to downstream
    # scripts without an intermediate file).
    [switch]$PassThruMap,

    # Optionally accept an existing map from a prior sanitization pass
    # (e.g. if Services and ServiceGroups are in the same CSV file, pass the
    # map produced by the first pass into the second).
    [hashtable]$SeedMap = @{}
)

# ---------------------------------------------------------------------------
# 1. Load the services CSV
# ---------------------------------------------------------------------------
Write-Host "  [Services] Reading: $InputFile" -ForegroundColor Cyan
$rows = Import-Csv -Path $InputFile

if (-not $rows -or @($rows).Count -eq 0) {
    Write-Host "  [Services] No rows found in $InputFile — nothing to do." -ForegroundColor Yellow
    if ($PassThruMap) { return @{} } else { return }
}

# ---------------------------------------------------------------------------
# 2. Build the old-ID -> new-ID mapping table
#
# Same two-pass approach as Sanitize-NSXGroups.ps1:
#   Pass 1 — count how many times each sanitized DisplayName appears (to
#             detect collisions before we commit to any new IDs)
#   Pass 2 — assign final newIds, appending -N suffixes for duplicates
#
# We merge any incoming $SeedMap so that a caller passing IDs from a prior
# pass (e.g. plain Services) are available when processing ServiceGroups.
# ---------------------------------------------------------------------------

function Sanitize-Id {
    param([string]$value)
    # NSX IDs may only contain letters, digits, hyphens, and underscores.
    # Replace everything else with a dash.
    return [regex]::Replace($value.Trim(), '[^a-zA-Z0-9_-]', '-')
}

# Start with any IDs provided by the caller from a prior pass
$idMap = @{}
foreach ($key in $SeedMap.Keys) { $idMap[$key] = $SeedMap[$key] }

# Pass 1 — count occurrences of each sanitized DisplayName
$displayCount = @{}
foreach ($row in $rows) {
    $sanitized = Sanitize-Id $row.DisplayName
    $displayCount[$sanitized] = ($displayCount[$sanitized] -as [int]) + 1
}

# Pass 2 — assign newIds with deduplication suffixes where needed
$displayCounter = @{}
foreach ($row in $rows) {
    $oldId     = $row.Id.Trim()
    $sanitized = Sanitize-Id $row.DisplayName

    if ($displayCount[$sanitized] -gt 1) {
        if (-not $displayCounter.ContainsKey($sanitized)) {
            $displayCounter[$sanitized] = 1
        }
        $suffix = $displayCounter[$sanitized]
        $displayCounter[$sanitized]++
        $newId = "$sanitized-$suffix"
        Write-Warning "Duplicate DisplayName '$sanitized' — assigned '$newId' to Id '$oldId'."
    } else {
        $newId = $sanitized
    }

    if ($oldId -ne $newId) {
        if ($idMap.ContainsKey($oldId)) {
            Write-Warning "Duplicate old ID '$oldId' — skipping second occurrence."
        } else {
            $idMap[$oldId] = $newId
        }
    }
}

# Count only new mappings added by this pass (not from the seed)
$newMappings = $idMap.Count - $SeedMap.Count
Write-Host "  [Services] $newMappings ID(s) need renaming." -ForegroundColor Yellow

# ---------------------------------------------------------------------------
# 3. Helpers
# ---------------------------------------------------------------------------

function Decode-UnicodeEscapes {
    <# Decode all \uXXXX unicode escape sequences in a JSON string to their
       actual characters. NSX sometimes emits unicode escapes (e.g. \u0027
       for a single quote) in RawJson. Decoding before matching ensures all
       subsequent substitutions work on a single consistent representation. #>
    param([string]$text)
    return [regex]::Replace($text, '\\u([0-9a-fA-F]{4})', {
        param($m)
        [char][convert]::ToInt32($m.Groups[1].Value, 16)
    })
}

function Update-ServicePaths {
    <# Rewrite /services/<oldId> path segments in any string.
       NSX embeds service and service group IDs inside member paths:
         /infra/services/<id>
       Keys are sorted longest-first to prevent a shorter key from matching
       as a prefix inside a longer one at a path boundary. #>
    param([string]$text)
    $sortedKeys = $idMap.Keys | Sort-Object { $_.Length } -Descending
    foreach ($oldId in $sortedKeys) {
        $escaped = [regex]::Escape($oldId)
        # Lookbehind: must be preceded by /services/
        # Lookahead:  must be followed by /, ", or end-of-string
        $text = [regex]::Replace($text, "(?<=/services/)$escaped(?=/|""|$)", $idMap[$oldId])
    }
    return $text
}

function Remove-Tags {
    <# Remove all tags from a RawJson string.
       Tags in NSX RawJson are a top-level array, e.g.:
         "tags":[{"scope":"v_origin","tag":"application-228"}]
       These are migration artefacts and are replaced with an empty array. #>
    param([string]$json)
    return [regex]::Replace($json, '"tags":\[.*?\]', '"tags":[]')
}

# ---------------------------------------------------------------------------
# 4. Apply changes to every row
# ---------------------------------------------------------------------------
$mappingLog = [System.Collections.Generic.List[PSCustomObject]]::new()

foreach ($row in $rows) {
    $oldId = $row.Id.Trim()

    # Decode unicode escapes before any processing so all subsequent pattern
    # matches work on plain characters, not \uXXXX sequences.
    $row.RawJson = Decode-UnicodeEscapes -text $row.RawJson

    if ($idMap.ContainsKey($oldId)) {
        $newId      = $idMap[$oldId]
        $oldDisplay = $row.DisplayName.Trim()

        # Update the CSV Id and DisplayName columns
        $row.Id          = $newId
        $row.DisplayName = $newId

        # Update RawJson in three passes:

        # Pass A — fix /services/<oldId> path segments (member path references
        #           inside ServiceGroups, and self-referential path fields)
        $json = Update-ServicePaths -text $row.RawJson

        # Pass B — fix this object's own top-level "id", "display_name", and
        #          "relative_path" fields, which are plain JSON string values
        #          not inside a /services/ path.
        $esc        = [regex]::Escape($oldId)
        $escDisplay = [regex]::Escape($oldDisplay)
        $json = $json -replace """id"":""$esc""",                    """id"":""$newId"""
        $json = $json -replace """relative_path"":""$esc""",         """relative_path"":""$newId"""
        $json = $json -replace """display_name"":""$escDisplay""",   """display_name"":""$newId"""

        # Pass C — remove all tags (migration artefacts)
        $json = Remove-Tags -json $json
        $row.RawJson = $json

        # Log the rename (only log renames introduced by this pass,
        # not those inherited from $SeedMap)
        if (-not $SeedMap.ContainsKey($oldId)) {
            $mappingLog.Add([PSCustomObject]@{ OldId = $oldId; NewId = $newId })
        }
    } else {
        # No rename needed for this object's own Id.
        # Still run Update-ServicePaths so any member references to renamed
        # services are updated (relevant for ServiceGroup rows that reference
        # plain services whose IDs were changed in this or a prior pass).
        # Also run Remove-Tags to strip migration artefacts.
        $row.RawJson = Remove-Tags -json (Update-ServicePaths -text $row.RawJson)
    }

    # Clear the Tags CSV column for all rows
    if ($row.PSObject.Properties['Tags']) { $row.Tags = '' }
}

# ---------------------------------------------------------------------------
# 5. Write the sanitized services CSV
# ---------------------------------------------------------------------------
Write-Host "  [Services] Writing: $OutputFile" -ForegroundColor Cyan
$rows | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8

# ---------------------------------------------------------------------------
# 6. Return the map to the orchestrator, or write it to CSV for standalone use
# ---------------------------------------------------------------------------
if ($PassThruMap) {
    return $idMap
} else {
    Write-Host "  [Services] Writing mapping log: $MappingFile" -ForegroundColor Cyan
    if ($mappingLog.Count -gt 0) {
        $mappingLog | Export-Csv -Path $MappingFile -NoTypeInformation -Encoding UTF8
    } else {
        # Write an empty mapping file so the output is predictable
        [PSCustomObject]@{ OldId = ''; NewId = '' } |
            Export-Csv -Path $MappingFile -NoTypeInformation -Encoding UTF8
        # Remove the placeholder row — Export-Csv always writes the header
        $content = Get-Content $MappingFile
        $content[0] | Set-Content $MappingFile
    }

    Write-Host ""
    Write-Host "Done! $($mappingLog.Count) service(s) renamed." -ForegroundColor Green
    if ($mappingLog.Count -gt 0) { $mappingLog | Format-Table -AutoSize }
}