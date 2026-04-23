# =============================================================================
# Sanitize-NSXFirewallRules.ps1
# Version 1.3.5
#
# PURPOSE
# -------
# Firewall rules and policies reference NSX groups by their Id embedded in
# full NSX paths, for example:
#   /infra/domains/default/groups/securitygroup-223
#
# After Sanitize-NSXGroups.ps1 renames group Ids to match DisplayNames, those
# paths in both the rules and policies exports become stale. This script
# applies the same Id mapping to both exports so all references stay consistent.
#
# When -ServiceIdMap is provided (passed from the orchestrator after Step 2),
# service Id references in rule rows are also updated to match the renamed
# service Ids produced by Sanitize-NSXServices.ps1.
#
# WHAT GETS CHANGED — RULES (NSX_Rules.csv)
# ------------------------------------------
# Rule Ids are renamed to match their DisplayNames, following the same
# Sanitize-Id logic used by policies and Sanitize-NSXGroups.ps1 (spaces and
# invalid characters replaced with hyphens). Both the Id and DisplayName CSV
# columns are updated, as are the "id", "relative_path", "display_name", and
# the rule segment of "path" inside RawJson.
#
# For each rule row, group Id references are updated in:
#
#   CSV columns (contain full NSX group paths, or "ANY"):
#     - SourceGroups  — the source group(s) traffic must originate from
#     - DestGroups    — the destination group(s) traffic must be directed to
#     - AppliedTo     — the scope/applied-to group(s) for the rule
#     - Tags          — cleared entirely (see tag removal below)
#
#   Inside RawJson (same paths appear in JSON arrays):
#     - source_groups[]       — same semantics as SourceGroups column
#     - destination_groups[]  — same semantics as DestGroups column
#     - scope[]               — same semantics as AppliedTo column
#     - "tags":[...]          — replaced with "tags":[]
#
# When -ServiceIdMap is provided, service Id references are also updated in:
#
#   CSV columns:
#     - Services      — the service path(s) for the rule, or "ANY"
#
#   Inside RawJson:
#     - services[]    — same semantics as the Services column
#
# WHAT GETS CHANGED — POLICIES (NSX_Policies.csv)
# -------------------------------------------------
# Policy DisplayNames may contain the legacy suffix
# ":: NSX Service Composer - Firewall". This is stripped from the CSV
# DisplayName column only (step 3a). The RawJson "display_name" field is
# left untouched at this stage and is overwritten correctly in step 3c,
# where it is matched by the old Id rather than the old display name —
# making the substitution immune to suffix variations or encoding issues.
#
# Policy Ids are then renamed to match their (cleaned) DisplayNames, following
# the same Sanitize-Id logic used by Sanitize-NSXGroups.ps1. Duplicate
# DisplayNames receive a numeric suffix (-1, -2, …).
#
# For each policy row, the following are updated:
#
#   CSV columns:
#     - Id            — set to the sanitized DisplayName
#     - DisplayName   — set to the sanitized DisplayName (suffix stripped)
#     - Scope         — the applied-to group path(s) for the policy, or "ANY"
#     - Tags          — cleared entirely (see tag removal below)
#
#   Inside RawJson:
#     - "id":"<oldId>"                      ->  "id":"<newId>"
#     - "relative_path":"<oldId>"           ->  "relative_path":"<newId>"
#     - "display_name":"<oldDisplayName>"   ->  "display_name":"<newId>"
#     - scope[]       — group paths updated via the group Id map
#     - "tags":[...]  — replaced with "tags":[]
#
# Values of "ANY" and empty fields in group/service columns are left untouched.
#
# TAG REMOVAL
# -----------
# Rule and policy rows may carry tags that are migration artefacts from NSX-V.
# These are removed from both the CSV Tags column and the "tags" array in
# RawJson for all rows.
#
# WHAT DOES NOT GET CHANGED
# -------------------------
# All fields not explicitly listed above are left as-is.
#
# RULE ID MAPPING FILE FORMAT
# ----------------------------
# The rules mapping CSV contains three columns: PolicyId, OldId, NewId.
# PolicyId scopes each entry to the policy it belongs to, because the same
# rule Id can legally appear in multiple policies. The compare script uses
# this to build a per-policy lookup rather than a flat hashtable, avoiding
# collisions when duplicate rule Ids exist across different policies.
#
# USAGE
# -----
#   # Standalone — load the mapping from a CSV produced by Sanitize-NSXGroups.ps1:
#   .\Sanitize-NSXFirewallRules.ps1 -RulesFile   "rules.csv"    `
#                                   -PoliciesFile "policies.csv" `
#                                   -MappingFile  "groups_id_mapping.csv"
#
#   # Called from Sanitize-NSX.ps1 orchestrator — receives the live hashtables
#   # directly, no intermediate file needed:
#   .\Sanitize-NSXFirewallRules.ps1 -RulesFile    "rules.csv"    `
#                                   -PoliciesFile  "policies.csv" `
#                                   -IdMap         $groupIdMap    `
#                                   -ServiceIdMap  $serviceIdMap
#
#   # Rules only (policies file omitted — backward-compatible):
#   .\Sanitize-NSXFirewallRules.ps1 -RulesFile "rules.csv" -IdMap $idMap
#
# EXTENDING TO OTHER EXPORT TYPES
# --------------------------------
# If you need to sanitize another export type (e.g. segments),
# create a Sanitize-NSX<Type>.ps1 following the same pattern:
#   - Accept -IdMap <hashtable> and -MappingFile <path> parameters
#   - Use Update-GroupPaths to rewrite /groups/<oldId> segments
#   - Call it from Sanitize-NSX.ps1 as an additional step, passing -IdMap $idMap
# =============================================================================

[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$RulesFile,
    [string]$RulesOut = ($RulesFile -replace '\.csv$', '_sanitized.csv'),
    [string]$RulesIdMappingFile = ($RulesFile -replace '\.csv$', '_id_mapping.csv'),
    # Optional — policies CSV. When omitted, only rules are processed.
    [string]$PoliciesFile,
    [string]$PoliciesOut = '',   # auto-derived below if PoliciesFile is provided
    [string]$PoliciesIdMappingFile = ($PoliciesFile -replace '\.csv$', '_id_mapping.csv'),
    # Accepts either a live hashtable (passed from the orchestrator)...
    [hashtable]$IdMap,

    # ...or a path to the mapping CSV produced by Sanitize-NSXGroups.ps1
    # (for standalone use when running this script independently).
    [string]$MappingFile,

    # Optional — service ID mapping hashtable produced by Sanitize-NSXServices.ps1.
    # When provided, /services/<oldId> path segments in rule rows are rewritten
    # to match the renamed service Ids. Defaults to empty (no service rewriting).
    [hashtable]$ServiceIdMap = @{}
)

# Derive default PoliciesOut now that we know PoliciesFile
if ($PoliciesFile -and -not $PoliciesOut) {
    $PoliciesOut = $PoliciesFile -replace '\.csv$', '_sanitized.csv'
}

# ---------------------------------------------------------------------------
# 1. Resolve the group ID mapping table
#
# Prefer the live hashtable if provided — it avoids a file read and ensures
# we're working from exactly the same data the groups script produced.
# Fall back to loading from CSV for standalone / re-run scenarios.
# ---------------------------------------------------------------------------
if ($IdMap -and $IdMap.Count -gt 0) {
    $idMap = $IdMap
    Write-Host "  [Rules/Policies] Using provided ID map ($($idMap.Count) entries)." -ForegroundColor Cyan
}
elseif ($MappingFile) {
    Write-Host "  [Rules/Policies] Loading mapping from: $MappingFile" -ForegroundColor Cyan
    $idMap = @{}
    Import-Csv -Path $MappingFile | ForEach-Object {
        $idMap[$_.OldId] = $_.NewId
    }
    Write-Host "  [Rules/Policies] Loaded $($idMap.Count) mapping(s)." -ForegroundColor Yellow
}
else {
    Write-Error "Provide either -IdMap <hashtable> or -MappingFile <path>."
    exit 1
}

# ---------------------------------------------------------------------------
# 2. Helpers
# ---------------------------------------------------------------------------

# Decode all \uXXXX unicode escape sequences in a JSON string to their actual
# characters. NSX sometimes emits unicode escapes (e.g. \u0027 for a single
# quote) in RawJson. If an ID or DisplayName contains such a character, the
# encoded form would never match a plain-text regex pattern. Decoding upfront
# means all subsequent substitutions work on a single consistent representation.
function Decode-UnicodeEscapes {
    param([string]$text)
    return [regex]::Replace($text, '\\u([0-9a-fA-F]{4})', {
            param($m)
            [char][convert]::ToInt32($m.Groups[1].Value, 16)
        })
}

# Rewrite /groups/<oldId> path segments anywhere in a string.
# Used for both plain path values in CSV columns and JSON strings in RawJson.
#
# IMPORTANT: Keys are sorted longest-first before iterating. This prevents a
# shorter key from matching as a prefix inside a longer one. This is especially
# critical for IDs that contain a forward slash (e.g. IPNET_DATA-SER4/4A),
# where the regex would otherwise match the shorter prefix IPNET_DATA-SER4
# at the / boundary before getting a chance to match the full ID.
function Update-GroupPaths {
    param([string]$text)
    $sortedKeys = $idMap.Keys | Sort-Object { $_.Length } -Descending
    foreach ($oldId in $sortedKeys) {
        $escaped = [regex]::Escape($oldId)
        # Lookbehind ensures we're inside a /groups/ path.
        # Lookahead ensures we only replace the Id segment, not beyond it.
        # The $ alternative handles plain CSV column values where the path
        # ends at end-of-string rather than a / or " character.
        $text = [regex]::Replace($text, "(?<=/groups/)$escaped(?=/|""|$)", $idMap[$oldId])
    }
    return $text
}

# Update a single group-path column value.
# Columns like SourceGroups or Scope may contain multiple paths separated by
# semicolons, e.g.:
#   "/infra/.../groups/securitygroup-223; /infra/.../groups/ipset-286"
# Each part is updated individually and then rejoined.
function Update-GroupColumn {
    param([string]$value)

    # Skip empty values and the literal "ANY" sentinel — these are valid
    # values meaning "all groups" and should not be modified.
    if ([string]::IsNullOrWhiteSpace($value) -or $value -eq 'ANY') { return $value }

    $parts = $value -split ';' | ForEach-Object { $_.Trim() }
    $updated = $parts | ForEach-Object { Update-GroupPaths -text $_ }
    return $updated -join '; '
}

# Remove all tags from a RawJson string.
# Tags in NSX RawJson appear as a top-level array, e.g.:
#   "tags":[{"scope":"v_origin","tag":"SecurityGroup-securitygroup-70"}]
# These are migration artefacts with no value post-migration, so the entire
# array is replaced with an empty one.
function Remove-Tags {
    param([string]$json)
    # The lazy .*? stops at the first closing ] to avoid over-matching.
    return [regex]::Replace($json, '"tags":\[.*?\]', '"tags":[]')
}

# Rewrite /services/<oldId> path segments anywhere in a string.
# Mirrors Update-GroupPaths but targets /services/ instead of /groups/.
# Only runs when $ServiceIdMap is non-empty.
function Update-ServicePaths {
    param([string]$text)
    if ($ServiceIdMap.Count -eq 0) { return $text }
    $sortedKeys = $ServiceIdMap.Keys | Sort-Object { $_.Length } -Descending
    foreach ($oldId in $sortedKeys) {
        $escaped = [regex]::Escape($oldId)
        $text = [regex]::Replace($text, "(?<=/services/)$escaped(?=/|""|$)", $ServiceIdMap[$oldId])
    }
    return $text
}

# Update a single service-path column value (semicolon-separated paths, or "ANY").
function Update-ServiceColumn {
    param([string]$value)
    if ([string]::IsNullOrWhiteSpace($value) -or $value -eq 'ANY') { return $value }
    $parts = $value -split ';' | ForEach-Object { $_.Trim() }
    $updated = $parts | ForEach-Object { Update-ServicePaths -text $_ }
    return $updated -join '; '
}

# Replace characters that are invalid in NSX Ids with a hyphen.
# Mirrors the Sanitize-Id function in Sanitize-NSXGroups.ps1.
function Sanitize-Id {
    param([string]$value)
    return [regex]::Replace($value.Trim(), '[^a-zA-Z0-9_-]', '-')
}

# ---------------------------------------------------------------------------
# 3. Process policies CSV
# ---------------------------------------------------------------------------
if ($PoliciesFile) {
    if (-not (Test-Path $PoliciesFile)) {
        Write-Warning "  [Policies] File not found, skipping: $PoliciesFile"
    }
    else {
        Write-Host "  [Policies] Reading: $PoliciesFile" -ForegroundColor Cyan
        $policyRows = Import-Csv -Path $PoliciesFile

        # -------------------------------------------------------------------
        # 3a. Strip the legacy suffix from the DisplayName CSV column only.
        #     RawJson is intentionally not touched here — the "display_name"
        #     field will be overwritten correctly in step 3c when the full
        #     Id rename is applied (matched by old Id, not old display name).
        # -------------------------------------------------------------------
        $legacySuffix = ':: NSX Service Composer - Firewall'

        foreach ($row in $policyRows) {
            if ($row.DisplayName -like "*$legacySuffix*") {
                $row.DisplayName = $row.DisplayName.Replace($legacySuffix, '').Trim()
            }
        }

        # -------------------------------------------------------------------
        # 3b. Decode unicode escapes in RawJson, then build the policy Id map:
        #     OldId -> sanitized(DisplayName).
        #     DisplayName is already suffix-free from step 3a.
        #     Mirrors the two-pass deduplication logic in Sanitize-NSXGroups.ps1.
        # -------------------------------------------------------------------
        foreach ($row in $policyRows) {
            $row.RawJson = Decode-UnicodeEscapes -text $row.RawJson

            # Clear the Description CSV column
            $row.Description = ''
            # Clear "description":"..." inside RawJson
            $row.RawJson = [regex]::Replace($row.RawJson, '"description":"[^"]*"', '"description":""')
        }

        $policyIdMap = @{}

        # Pass 1 — count occurrences of each sanitized DisplayName
        $displayCount = @{}
        foreach ($row in $policyRows) {
            $sanitized = Sanitize-Id $row.DisplayName
            if ($displayCount.ContainsKey($sanitized)) { $displayCount[$sanitized]++ }
            else { $displayCount[$sanitized] = 1 }
        }

        # Pass 2 — assign newIds with deduplication suffixes where needed
        $displayCounter = @{}
        $mappingLog = [System.Collections.Generic.List[PSCustomObject]]::new()
        foreach ($row in $policyRows) {
            $oldId = $row.Id.Trim()
            $sanitized = Sanitize-Id $row.DisplayName

            if ($displayCount[$sanitized] -gt 1) {
                if (-not $displayCounter.ContainsKey($sanitized)) { $displayCounter[$sanitized] = 1 }
                $suffix = $displayCounter[$sanitized]
                $displayCounter[$sanitized]++
                $newId = "$sanitized-$suffix"
                Write-Warning "  [Policies] Duplicate DisplayName '$sanitized' — assigned '$newId' to Id '$oldId'."
            }
            else {
                $newId = $sanitized
            }

            if ($oldId -ne $newId) {
                if ($policyIdMap.ContainsKey($oldId)) { Write-Warning "  [Policies] Duplicate old Id '$oldId' — skipping." }
                else { $policyIdMap[$oldId] = $newId }
            }

            $mappingLog.Add([PSCustomObject]@{ OldId = $oldId; NewId = $newId })
        }

        Write-Host "  [Policies] $($policyIdMap.Count) policy Id(s) need renaming." -ForegroundColor Yellow

        # -------------------------------------------------------------------
        # 3c. Apply Id renames and group-path updates to each policy row
        # -------------------------------------------------------------------
        $policiesUpdated = 0

        foreach ($row in $policyRows) {
            $oldId = $row.Id.Trim()

            $before = $row | ConvertTo-Json -Compress

            if ($policyIdMap.ContainsKey($oldId)) {
                $newId = $policyIdMap[$oldId]

                # Update CSV columns
                $row.Id = $newId
                $row.DisplayName = $newId

                # Rewrite "id", "relative_path", "path", and "display_name" in RawJson.
                # "display_name" is matched by a wildcard pattern anchored to the old Id
                # on the same JSON object — the RawJson field may still contain the legacy
                # suffix at this point (it was never touched in 3a), so matching by display
                # name would be unreliable. Using a lookahead on the old Id is the safe anchor.
                $esc = [regex]::Escape($oldId)
                $json = $row.RawJson
                $json = $json -replace """id"":""$esc""", """id"":""$newId"""
                $json = $json -replace """relative_path"":""$esc""", """relative_path"":""$newId"""
                $json = [regex]::Replace($json, """display_name"":""[^""]*""(?=[^}]*""id"":""$esc"")", """display_name"":""$newId""")
                $json = $json -replace """path"":""/infra/domains/default/security-policies/$esc""", """path"":""/infra/domains/default/security-policies/$newId"""
                $row.RawJson = $json
            }

            # Update group paths in the Scope column and RawJson scope[] array
            $row.Scope = Update-GroupColumn -value $row.Scope
            $row.RawJson = Update-GroupPaths  -text  $row.RawJson

            # Remove tags from RawJson and clear the Tags CSV column.
            $row.RawJson = Remove-Tags -json $row.RawJson
            $row.Tags = ''

            $after = $row | ConvertTo-Json -Compress
            if ($before -ne $after) { $policiesUpdated++ }
        }

        Write-Host "  [Policies] Writing: $PoliciesOut" -ForegroundColor Cyan
        $policyRows | Export-Csv -Path $PoliciesOut -NoTypeInformation -Encoding UTF8
        Write-Host "  [Policies] $policiesUpdated policy row(s) updated." -ForegroundColor Yellow
    }
    Write-Host "  [Policies] Writing mapping log: $PoliciesIdMappingFile" -ForegroundColor Cyan
    $mappingLog | Export-Csv -Path $PoliciesIdMappingFile -NoTypeInformation -Encoding UTF8

    Write-Host ""
    Write-Host "Done! $($mappingLog.Count) policies renamed." -ForegroundColor Green
    #if ($mappingLog.Count -gt 0) { $mappingLog | Format-Table -AutoSize }

}

# ---------------------------------------------------------------------------
# 4. Process rules CSV
# ---------------------------------------------------------------------------
Write-Host "  [Rules] Reading: $RulesFile" -ForegroundColor Cyan
$ruleRows = Import-Csv -Path $RulesFile

$rulesUpdated = 0
$mappingLog = [System.Collections.Generic.List[PSCustomObject]]::new()
foreach ($row in $ruleRows) {
    
    # Decode unicode escapes in RawJson before any processing so that all
    # subsequent pattern matches work on plain characters, not \uXXXX sequences.
    $row.RawJson = Decode-UnicodeEscapes -text $row.RawJson

    $before = $row | ConvertTo-Json -Compress

    # --- NEW ID SANITIZATION LOGIC ---
    $oldRuleId = $row.Id.Trim()
    $oldDisplay = $row.DisplayName.Trim()
    $newRuleId = Sanitize-Id $oldDisplay

    if ($oldRuleId -ne $newRuleId) {
        # Update CSV columns
        $row.Id = $newRuleId
        $row.DisplayName = $newRuleId

        # Update "id", "relative_path", "display_name", and the rule segment of "path" in RawJson
        $escOldId = [regex]::Escape($oldRuleId)
        $escOldDisplay = [regex]::Escape($oldDisplay)
        $row.RawJson = $row.RawJson -replace """id"":""$escOldId""", """id"":""$newRuleId"""
        $row.RawJson = $row.RawJson -replace """relative_path"":""$escOldId""", """relative_path"":""$newRuleId"""
        $row.RawJson = $row.RawJson -replace """display_name"":""$escOldDisplay""", """display_name"":""$newRuleId"""

        # This regex ensures we only replace the rule ID at the end of the path string
        $row.RawJson = [regex]::Replace($row.RawJson, "(/rules/)$escOldId(?=""|$)", "/rules/$newRuleId")

        $mappingLog.Add([PSCustomObject]@{ PolicyId = $row.PolicyId; OldId = $oldRuleId; NewId = $newRuleId })
    }

    $row.SourceGroups = Update-GroupColumn   -value $row.SourceGroups
    $row.DestGroups = Update-GroupColumn   -value $row.DestGroups
    $row.AppliedTo = Update-GroupColumn   -value $row.AppliedTo
    $row.Services = Update-ServiceColumn -value $row.Services
    
    # Rewrite PolicyId and PolicyName CSV columns
    if ($policyIdMap.ContainsKey($row.PolicyId)) {
        $row.PolicyId = $policyIdMap[$row.PolicyId]
        $row.PolicyName = $row.PolicyId   # PolicyName mirrors the new Id
    }
    # RawJson contains the same group paths inside source_groups[],
    # destination_groups[], and scope[] — Update-GroupPaths handles all of them.
    # Update-ServicePaths rewrites /services/<oldId> segments in services[].
    $row.RawJson = Update-GroupPaths   -text $row.RawJson
    $row.RawJson = Update-ServicePaths -text $row.RawJson

    # Rewrite path and parent_path in RawJson
    foreach ($oldPolicyId in $policyIdMap.Keys) {
        $escPolicy = [regex]::Escape($oldPolicyId)
        $newPolicyId = $policyIdMap[$oldPolicyId]

        $row.RawJson = [regex]::Replace(
            $row.RawJson,
            "(?<=""path"":"")([^""]*/security-policies/)$escPolicy(?=/|"")",
            "`${1}$newPolicyId"
        )
        $row.RawJson = [regex]::Replace(
            $row.RawJson,
            "(?<=""parent_path"":"")([^""]*/security-policies/)$escPolicy(?=/|"")",
            "`${1}$newPolicyId"
        )
    }

    # Remove tags from RawJson and clear the Tags CSV column.
    $row.RawJson = Remove-Tags -json $row.RawJson
    $row.Tags = ''

    $after = $row | ConvertTo-Json -Compress
    if ($before -ne $after) { $rulesUpdated++ }
}

Write-Host "  [Rules] Writing: $RulesOut" -ForegroundColor Cyan
$ruleRows | Export-Csv -Path $RulesOut -NoTypeInformation -Encoding UTF8
Write-Host "  [Rules] $rulesUpdated rule row(s) had group/service references updated." -ForegroundColor Yellow

Write-Host "  [Rules] Writing mapping log: $RulesIdMappingFile" -ForegroundColor Cyan
$mappingLog | Export-Csv -Path $RulesIdMappingFile -NoTypeInformation -Encoding UTF8

Write-Host ""
Write-Host "Done! $($mappingLog.Count) rules renamed." -ForegroundColor Green
#if ($mappingLog.Count -gt 0) { $mappingLog | Format-Table -AutoSize }

# Print a closing summary only in standalone mode; the orchestrator prints
# its own summary covering all steps.
if (-not $IdMap) {
    Write-Host ""
    Write-Host "Done!" -ForegroundColor Green
}