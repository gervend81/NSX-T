# =============================================================================
# Sanitize-NSX.ps1  —  Orchestrator
# Version 1.4.0
#
# PURPOSE
# -------
# NSX exports can contain groups and services whose Id (the internal NSX
# identifier) differs from the DisplayName (the human-readable label).
# For example:
#
#   Id: securitygroup-223   DisplayName: Datacenter
#   Id: ipset-286           DisplayName: IPNET_1314-ETZ_Beheer_ICT
#   Id: application-228     DisplayName: HTTP-8080
#   Id: applicationgroup-45 DisplayName: Web-Services-Group
#
# This script coordinates three sanitization passes to bring every export into
# a consistent state where Id == DisplayName, and every cross-reference that
# previously used the old Id is updated to use the new one.
#
# PIPELINE (order matters)
# ------------------------
# Step 1 — Sanitize-NSXGroups.ps1
#   - Scans the groups CSV and collects every (oldId -> DisplayName) pair
#     where the two values differ. This becomes the groups ID mapping table.
#   - For each group that needs renaming:
#       * Updates the Id column in the CSV to match DisplayName.
#       * Inside RawJson, updates the group's own "id" and "relative_path"
#         JSON fields to reflect the new Id.
#   - For ALL groups (renamed or not), rewrites any /groups/<oldId> path
#     segments that appear in RawJson — these are inter-group references where
#     one group's PathExpression points to another group by its old Id.
#   - Returns the ID mapping table as a live hashtable so Step 3 can reuse it
#     without re-reading the CSV.
#   - Also saves the mapping table to a CSV file for auditing.
#
# Step 2 — Sanitize-NSXServices.ps1
#   - Scans the services CSV (which contains both Services and ServiceGroups)
#     and collects every (oldId -> DisplayName) pair where the two values
#     differ. This becomes the services ID mapping table.
#   - For each service/service group that needs renaming:
#       * Updates the Id and DisplayName columns in the CSV.
#       * Inside RawJson, updates "id", "relative_path", and "display_name".
#       * Rewrites any /services/<oldId> path segments (ServiceGroup member
#         references) using the same mapping table.
#   - Removes migration-artefact tags from all rows.
#   - Returns the ID mapping table as a live hashtable for auditing.
#   - Also saves the mapping table to a CSV file for auditing.
#
# Step 3 — Sanitize-NSXFirewallRules.ps1
#   - Receives the groups ID mapping table from Step 1 and the service ID
#     mapping table from Step 2 (empty hashtable when no services file given).
#   - Processes both the rules CSV and the policies CSV:
#
#     Rules — group references appear in three dedicated CSV columns:
#       * SourceGroups  — the source group(s) for the rule
#       * DestGroups    — the destination group(s)
#       * AppliedTo     — the scope/applied-to group(s)
#     The old group Id in each path is replaced with the new one, and the
#     same substitution is applied inside RawJson (source_groups[],
#     destination_groups[], scope[]).
#
#     Rules — service references appear in one dedicated CSV column:
#       * Services      — the service(s) for the rule
#     The old service Id in each path is replaced with the new one, and the
#     same substitution is applied inside RawJson (services[]).
#
#     Policies — group references appear in one CSV column:
#       * Scope         — the applied-to group path(s) for the policy
#     The old group Id in each path is replaced with the new one, and the
#     same substitution is applied inside the RawJson scope[] array.
#
#   - Values of "ANY" and empty fields are left untouched in both files.
#
# Step 4 — Inline profiles sanitization (no separate script needed)
#   - When -ProfilesFile is provided, reads the Context Profiles CSV and
#     removes migration-artefact tags from both the Tags CSV column and the
#     "tags" array inside RawJson. No ID remapping is performed — profile
#     Ids are already clean human-readable names.
#   - Writes <ProfilesFile>_sanitized.csv.
#
# OUTPUTS
# -------
#   <GroupsFile>_sanitized.csv    — groups with corrected Ids and RawJson
#   <ServicesFile>_sanitized.csv  — services/service groups with corrected Ids
#   <RulesFile>_sanitized.csv     — rules with updated group/service path references
#   <PoliciesFile>_sanitized.csv  — policies with updated group path references
#   <ProfilesFile>_sanitized.csv  — profiles with tags removed
#   <GroupsFile>_id_mapping.csv   — audit log of every group oldId -> newId rename
#   <ServicesFile>_id_mapping.csv — audit log of every service oldId -> newId rename
#
# USAGE
# -----
#   # Typical usage — all output paths are auto-derived:
#   .\Sanitize-NSX.ps1 -GroupsFile "groups.csv" -ServicesFile "services.csv" `
#                      -RulesFile  "rules.csv"   -PoliciesFile "policies.csv" `
#                      -ProfilesFile "profiles.csv"
#
#   # With explicit output paths:
#   .\Sanitize-NSX.ps1 -GroupsFile    "groups.csv"    -ServicesFile    "services.csv"  `
#                      -RulesFile     "rules.csv"      -PoliciesFile    "policies.csv"  `
#                      -ProfilesFile  "profiles.csv"                                    `
#                      -GroupsOut     "groups_clean.csv"                                `
#                      -ServicesOut   "services_clean.csv"                              `
#                      -RulesOut      "rules_clean.csv"                                 `
#                      -PoliciesOut   "policies_clean.csv"                              `
#                      -ProfilesOut   "profiles_clean.csv"                              `
#                      -GroupMappingOut   "groups_rename_log.csv"                       `
#                      -ServiceMappingOut "services_rename_log.csv"
#
#   # Without a policies file (backward-compatible — rules only):
#   .\Sanitize-NSX.ps1 -GroupsFile "groups.csv" -ServicesFile "services.csv" `
#                      -RulesFile  "rules.csv"
#
#   # Without a services file (backward-compatible — groups and rules only):
#   .\Sanitize-NSX.ps1 -GroupsFile "groups.csv" -RulesFile "rules.csv"
#
# NOTES
# -----
#   - All four scripts (this file, Sanitize-NSXGroups.ps1,
#     Sanitize-NSXServices.ps1, and Sanitize-NSXFirewallRules.ps1) must be in
#     the same directory.
#   - If you add more export types in future (e.g. segments), create a
#     Sanitize-NSX<Type>.ps1 following the same pattern and call it here as
#     an additional step, passing -IdMap $idMap.
# =============================================================================

[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$GroupsFile,
    [Parameter(Mandatory)][string]$RulesFile,

    # Optional — when provided, services and service groups are sanitized in Step 2
    [string]$ServicesFile,

    # Optional — when provided, the policies CSV is sanitized in Step 3
    # alongside the rules CSV using the same group ID mapping.
    [string]$PoliciesFile,

    # Optional — when provided, the profiles CSV is sanitized in Step 4
    # (tags are removed; no ID remapping is needed for profiles).
    [string]$ProfilesFile,

    [string]$GroupsOut   = ($GroupsFile -replace '\.csv$', '_sanitized.csv'),
    [string]$ServicesOut = '',   # auto-derived below if ServicesFile is provided
    [string]$RulesOut    = ($RulesFile  -replace '\.csv$', '_sanitized.csv'),
    [string]$PoliciesOut = '',   # auto-derived below if PoliciesFile is provided
    [string]$ProfilesOut = '',   # auto-derived below if ProfilesFile is provided

    # Separate mapping output paths for groups and services
    [string]$GroupMappingOut   = ($GroupsFile -replace '\.csv$', '_id_mapping.csv'),
    [string]$ServiceMappingOut = '',   # auto-derived below if ServicesFile is provided

    # Legacy parameter — if caller passes -MappingOut it is treated as the
    # groups mapping output for backward compatibility.
    [string]$MappingOut  = ''
)

# Derive default output paths now that we know the optional file parameters
if ($ServicesFile -and -not $ServicesOut) {
    $ServicesOut = $ServicesFile -replace '\.csv$', '_sanitized.csv'
}
if ($ServicesFile -and -not $ServiceMappingOut) {
    $ServiceMappingOut = $ServicesFile -replace '\.csv$', '_id_mapping.csv'
}
if ($PoliciesFile -and -not $PoliciesOut) {
    $PoliciesOut = $PoliciesFile -replace '\.csv$', '_sanitized.csv'
}
if ($ProfilesFile -and -not $ProfilesOut) {
    $ProfilesOut = $ProfilesFile -replace '\.csv$', '_sanitized.csv'
}

# Honor legacy -MappingOut override for backward compatibility
if ($MappingOut) { $GroupMappingOut = $MappingOut }

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

# ---------------------------------------------------------------------------
# Validate that input files and sibling scripts all exist before starting
# ---------------------------------------------------------------------------
foreach ($f in @($GroupsFile, $RulesFile)) {
    if (-not (Test-Path $f)) {
        Write-Error "Input file not found: $f"
        exit 1
    }
}

if ($ServicesFile -and -not (Test-Path $ServicesFile)) {
    Write-Error "Input file not found: $ServicesFile"
    exit 1
}

if ($PoliciesFile -and -not (Test-Path $PoliciesFile)) {
    Write-Error "Input file not found: $PoliciesFile"
    exit 1
}

if ($ProfilesFile -and -not (Test-Path $ProfilesFile)) {
    Write-Error "Input file not found: $ProfilesFile"
    exit 1
}

$requiredScripts = @('Sanitize-NSXGroups.ps1', 'Sanitize-NSXFirewallRules.ps1')
if ($ServicesFile) { $requiredScripts += 'Sanitize-NSXServices.ps1' }

foreach ($s in $requiredScripts) {
    if (-not (Test-Path (Join-Path $scriptDir $s))) {
        Write-Error "Required script not found: $s (must be in the same folder as this script)"
        exit 1
    }
}

# ---------------------------------------------------------------------------
# Step 1 — Sanitize groups
#
# -PassThruMap tells the script to return the idMap hashtable directly to
# this caller instead of writing it to CSV. We persist it to CSV ourselves
# below so we control the output path.
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "Step 1/$(if ($ServicesFile) { 3 } else { 2 }) — Sanitizing groups..." -ForegroundColor Magenta

$groupIdMap = & "$scriptDir\Sanitize-NSXGroups.ps1" `
    -InputFile   $GroupsFile `
    -OutputFile  $GroupsOut `
    -PassThruMap

# Persist the groups mapping table to CSV for auditing / future reference.
Write-Host "  [Groups] Writing mapping log: $GroupMappingOut" -ForegroundColor Cyan
$groupIdMap.GetEnumerator() |
    Select-Object @{N='OldId';E={$_.Key}}, @{N='NewId';E={$_.Value}} |
    Sort-Object OldId |
    Export-Csv -Path $GroupMappingOut -NoTypeInformation -Encoding UTF8

Write-Host "  [Groups] $($groupIdMap.Count) group ID(s) in mapping." -ForegroundColor Yellow

# ---------------------------------------------------------------------------
# Step 2 — Sanitize services and service groups (optional)
# ---------------------------------------------------------------------------
$serviceIdMap = @{}

if ($ServicesFile) {
    Write-Host ""
    Write-Host "Step 2/3 — Sanitizing services and service groups..." -ForegroundColor Magenta

    $serviceIdMap = & "$scriptDir\Sanitize-NSXServices.ps1" `
        -InputFile   $ServicesFile `
        -OutputFile  $ServicesOut `
        -PassThruMap

    # Persist the services mapping table to CSV for auditing.
    Write-Host "  [Services] Writing mapping log: $ServiceMappingOut" -ForegroundColor Cyan
    $serviceIdMap.GetEnumerator() |
        Select-Object @{N='OldId';E={$_.Key}}, @{N='NewId';E={$_.Value}} |
        Sort-Object OldId |
        Export-Csv -Path $ServiceMappingOut -NoTypeInformation -Encoding UTF8

    Write-Host "  [Services] $($serviceIdMap.Count) service ID(s) in mapping." -ForegroundColor Yellow
}

# ---------------------------------------------------------------------------
# Step 3 (or Step 2 when no services file) — Update firewall rules and policies
#
# We pass the live $groupIdMap hashtable rather than the CSV so this step
# doesn't need to re-read from disk. PoliciesFile is passed when provided;
# the rules/policies script silently skips it when omitted.
# ---------------------------------------------------------------------------
$ruleStepNumber = if ($ServicesFile) { 3 } else { 2 }
$totalSteps     = $ruleStepNumber + $(if ($ProfilesFile) { 1 } else { 0 })

Write-Host ""
Write-Host "Step $ruleStepNumber/$totalSteps — Sanitizing firewall rules and policies..." -ForegroundColor Magenta

$step3Params = @{
    RulesFile    = $RulesFile
    RulesOut     = $RulesOut
    IdMap        = $groupIdMap
    ServiceIdMap = $serviceIdMap
}

if ($PoliciesFile) {
    $step3Params['PoliciesFile'] = $PoliciesFile
    $step3Params['PoliciesOut']  = $PoliciesOut
}

& "$scriptDir\Sanitize-NSXFirewallRules.ps1" @step3Params

# ---------------------------------------------------------------------------
# Step 4 — Sanitize Context Profiles (optional)
#
# Profile IDs are already clean — no renaming needed. We only strip tags,
# which are migration artefacts with no meaning in the destination environment.
# ---------------------------------------------------------------------------
if ($ProfilesFile) {
    $profileStepNumber = $ruleStepNumber + 1
    Write-Host ""
    Write-Host "Step $profileStepNumber/$totalSteps — Sanitizing Context Profiles..." -ForegroundColor Magenta
    Write-Host "  [Profiles] Reading: $ProfilesFile" -ForegroundColor Cyan

    $profileRows    = Import-Csv -Path $ProfilesFile
    $profilesUpdated = 0

    foreach ($row in $profileRows) {
        $before      = $row.RawJson
        # Strip the "tags" array from RawJson — same regex used throughout the toolkit.
        $row.RawJson = [regex]::Replace($row.RawJson, '"tags":\[.*?\]', '"tags":[]')
        $row.Tags    = ''
        if ($row.RawJson -ne $before) { $profilesUpdated++ }
    }

    Write-Host "  [Profiles] Writing: $ProfilesOut" -ForegroundColor Cyan
    $profileRows | Export-Csv -Path $ProfilesOut -NoTypeInformation -Encoding UTF8
    Write-Host "  [Profiles] $profilesUpdated profile row(s) had tags removed." -ForegroundColor Yellow
}

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "=====================================================" -ForegroundColor Green
Write-Host " Sanitization complete!" -ForegroundColor Green
Write-Host "=====================================================" -ForegroundColor Green
Write-Host "  Groups (sanitized)   : $GroupsOut"
Write-Host "  Groups ID mapping    : $GroupMappingOut"
if ($ServicesFile) {
    Write-Host "  Services (sanitized) : $ServicesOut"
    Write-Host "  Services ID mapping  : $ServiceMappingOut"
}
Write-Host "  Rules  (sanitized)   : $RulesOut"
if ($PoliciesFile) {
    Write-Host "  Policies (sanitized) : $PoliciesOut"
}
if ($ProfilesFile) {
    Write-Host "  Profiles (sanitized) : $ProfilesOut"
}
Write-Host ""

if ($groupIdMap.Count -gt 0) {
    Write-Host "Renamed group IDs:" -ForegroundColor Yellow
    $groupIdMap.GetEnumerator() |
        Sort-Object Key |
        Format-Table @{N='Old ID'; E={$_.Key}}, @{N='New ID'; E={$_.Value}} -AutoSize
}

if ($serviceIdMap.Count -gt 0) {
    Write-Host "Renamed service IDs:" -ForegroundColor Yellow
    $serviceIdMap.GetEnumerator() |
        Sort-Object Key |
        Format-Table @{N='Old ID'; E={$_.Key}}, @{N='New ID'; E={$_.Value}} -AutoSize
}