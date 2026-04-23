#Requires -Version 5.1
<#
.SYNOPSIS
    Validates an NSX DFW migration by comparing custom objects between source and destination.

.DESCRIPTION
    Connects to both the source and destination NSX Managers and performs a side-by-side
    comparison of all custom (non-system-owned) DFW objects:

      - IP Sets
      - Services
      - Service Groups
      - Security Groups
      - DFW Policies
      - DFW Rules

    System-owned objects are intentionally excluded from all comparisons.

    MAPPING FILE SUPPORT
    --------------------
    The sanitization pipeline (Sanitize-NSX.ps1) renames object IDs so they
    match their DisplayName. For example:
        securitygroup-223  →  Datacenter
        application-228    →  HTTP-8080

    The destination NSX Manager received objects with these new IDs, so a
    direct source-ID lookup will always fail without the mapping. Supply the
    mapping CSV files produced by Sanitize-NSX.ps1 to allow the comparison to
    translate source IDs to their renamed counterparts before looking them up:

        -GroupMappingFile   "NSX_Groups_id_mapping.csv"
        -ServiceMappingFile "NSX_Services_id_mapping.csv"

    Each mapping CSV must contain columns OldId and NewId (the format written
    by Sanitize-NSX.ps1). When a mapping file is not provided, comparisons for
    that object type assume IDs were not changed.

    For each object type the script reports:
      ✔ MATCH        - object exists on both sides and key fields agree
      ⚠️  MISMATCH     - object exists on both sides but key fields differ
      ✖ MISSING_DST  - object exists on source but is absent from destination
      ✖ MISSING_SRC  - object exists on destination but absent from source (extra/unexpected)

    A full HTML report and a CSV findings file are written to the output folder so you can
    present the results to your customer.

.PARAMETER SourceNSX
    FQDN or IP of the source NSX Manager (e.g. NSX 4).

.PARAMETER DestNSX
    FQDN or IP of the destination NSX Manager (e.g. NSX 9).

.PARAMETER DomainId
    NSX Policy domain. Default: "default"

.PARAMETER OutputFolder
    Folder where the report and CSV are written. Created if it does not exist.
    Default: .\NSX_Validation_<timestamp>

.PARAMETER LogFile
    Path for the transcript log file. Defaults to a file inside OutputFolder.

.PARAMETER LogTarget
    Controls where log output is written.
      Screen : colored output to the console only (default)
      File   : write to -LogFile only, no console output
      Both   : colored console output AND written to -LogFile

.PARAMETER CompareIPSets
    Validate IP Sets. Default: $false

.PARAMETER CompareProfiles
    Validate Context Profiles. Default: $true

.PARAMETER CompareServices
    Validate Services and Service Groups. Default: $true

.PARAMETER CompareGroups
    Validate Security Groups. Default: $true

.PARAMETER ComparePolicies
    Validate DFW Policies and Rules. Default: $true

.PARAMETER GroupReviewList
    Path to a plain-text file containing one source group ID per line whose
    MISMATCH result should be downgraded to REVIEW in the report. Use for
    groups that are logically equivalent but structurally different in a way
    the script cannot resolve (e.g. same conditions split across different
    criteria blocks). REVIEW rows are visible in the report but do not count
    as mismatches and do not affect the overall PASSED/ISSUES FOUND status.
    Lines starting with # and blank lines are ignored.

.PARAMETER GroupMappingFile
    Path to the groups ID mapping CSV produced by Sanitize-NSX.ps1
    (typically named NSX_Groups_id_mapping.csv). Must contain OldId and NewId
    columns. When provided, source group IDs are translated to their renamed
    counterparts before being looked up on the destination.

.PARAMETER ServiceMappingFile
    Path to the services ID mapping CSV produced by Sanitize-NSX.ps1
    (typically named NSX_Services_id_mapping.csv). Must contain OldId and NewId
    columns. When provided, source service IDs are translated to their renamed
    counterparts before being looked up on the destination.

.PARAMETER PolicyMappingFile
    Path to the policies ID mapping CSV produced by Sanitize-NSX.ps1
    (typically named NSX_Policies_id_mapping.csv). Must contain OldId and NewId
    columns. When provided, source policy IDs are translated to their renamed
    counterparts before being looked up on the destination.

.PARAMETER RuleMappingFile
    Path to the rules ID mapping CSV produced by Sanitize-NSX.ps1
    (typically named NSX_Rules_id_mapping.csv). Must contain OldId and NewId
    columns. When provided, source service IDs are translated to their renamed
    counterparts before being looked up on the destination.

.EXAMPLE
    .\Compare-NSX-Migration.ps1 -SourceNSX nsx4.corp.local -DestNSX nsx9.corp.local

.EXAMPLE
    # With sanitization mapping files so renamed IDs are matched correctly
    .\Compare-NSX-Migration.ps1 -SourceNSX nsx4.corp.local -DestNSX nsx9.corp.local `
        -GroupMappingFile .\NSX_DFW_Export\NSX_Groups_id_mapping.csv `
        -ServiceMappingFile .\NSX_DFW_Export\NSX_Services_id_mapping.csv `
        -PolicyMappingFile .\NSX_DFW_Export\NSX_Policies_id_mapping.csv `
        -RuleMappingFile .\NSX_DFW_Export\NSX_Rules_id_mapping.csv

.EXAMPLE
    .\Compare-NSX-Migration.ps1 -SourceNSX nsx4.corp.local -DestNSX nsx9.corp.local `
        -GroupMappingFile   .\NSX_DFW_Export\NSX_Groups_id_mapping.csv `
        -ServiceMappingFile .\NSX_DFW_Export\NSX_Services_id_mapping.csv `
        -OutputFolder C:\Reports\Migration -LogTarget Both

.NOTES
    Version : 1.5.1
    Changelog:
      1.0.0  Initial release.
      1.0.1  Fixed Build-Map: replaced $_ with $obj inside foreach loop ($_ is
             not set in a foreach, only in ForEach-Object / Where-Object pipelines).
             Also fixed inverted filter logic - system-owned objects were being
             kept and custom objects skipped, causing all comparisons to return
             empty results and the $_ access to throw under Set-StrictMode.
      1.1.0  Added -GroupMappingFile and -ServiceMappingFile parameters.
             The sanitization pipeline renames object IDs (e.g. securitygroup-223
             → Datacenter). Without the mapping files, every renamed object was
             reported as MISSING_DST because its old source ID was not found on
             the destination. The mapping CSVs produced by Sanitize-NSX.ps1 are
             now loaded into $GroupIdMap and $ServiceIdMap hashtables and used in
             Compare-ObjectSets to translate source IDs before destination lookup.
      1.2.0  Fixed false MISMATCH on services whose destination_ports or
             source_ports arrive in a different order than the source. Service
             entries are now sorted by a canonical key (resource_type + protocol
             + sorted ports) before index-by-index comparison, making the check
             fully order-insensitive for both entries and individual port lists.
             Also added source_ports to the per-field comparison (previously
             omitted).
      1.2.1  Fixed 'property Count cannot be found' error in service comparison.
             Sort-Object unwraps single-item arrays to a scalar under
             Set-StrictMode. Wrapped $srcSorted and $dstSorted in @() to
             guarantee array type regardless of entry count.
      1.2.2  Fixed false display_name MISMATCH on services and service groups
             when a service mapping file is provided. The sanitization pipeline
             renames display_name to match the new ID, so the name is expected
             to differ when an ID mapping exists. Compare-ObjectSets now passes
             the resolved $dstId to the compare function, and $svcCompare /
             $sgCompare skip the display_name check when the ID was remapped.
      1.2.3  Fixed same false display_name MISMATCH for security groups when a
             group mapping file is provided. The groups compareFunc now also
             accepts $dstId and skips the display_name check when the ID was
             remapped by the sanitization pipeline.
      1.2.4  Fixed false MISMATCH on group PathExpression paths when a group
             mapping file is provided. Source paths embed the old object ID in
             the final path segment (e.g. /groups/securitygroup-223) while the
             destination uses the renamed ID (e.g. /groups/Datacenter). Source
             paths are now translated via $GroupIdMap before comparison.
      1.2.5  Disabled IP Sets comparison by default (-CompareIPSets now defaults
             to $false). Fixed false MISMATCH on group expression count caused
             by ConjunctionOperator entries that NSX auto-generates as glue
             between real expressions. These are now filtered out before the
             count and field-level comparison so they no longer cause spurious
             mismatches.
      1.3.0  Added -CompareProfiles parameter and Compare-Profiles function.
             Compares custom Context Profiles between source and destination,
             checking display_name (skipped when ID was remapped) and attributes
             (order-insensitive key=value comparison). Profiles are included in
             the HTML/CSV report, console summary table, and overall totals.
      1.3.1  Fixed false MISMATCH on groups where membership criteria are split
             across a different number of PathExpression or Condition entries
             on source vs destination. Replaced the index-by-index expression
             comparison with a flattened set-based approach: all paths from all
             PathExpression entries are collected into one set (with ID mapping
             applied) and all Conditions into another, then compared as sets.
             The number or structure of expression entries no longer matters.
      1.3.2  Fixed false MISMATCH on groups where conditions are wrapped inside
             NestedExpression blocks on one side but not the other. Added a
             recursive Get-LeafExpressions helper that unpacks NestedExpression
             blocks at any depth before collecting Conditions and PathExpression
             paths, so the structural grouping of expressions is fully ignored.
      1.3.3  Fixed Get-LeafExpressions silently not executing - PowerShell does
             not support function definitions inside scriptblocks. Replaced with
             an iterative stack-based approach directly inside the scriptblock
             that unpacks NestedExpression entries without calling any function.
             Also replaced Get-SafeProp calls inside the scriptblock with direct
             PSObject.Properties checks to avoid scope resolution issues.
      1.3.4  Fixed $GroupIdMap being $null inside the groups compareFunc scriptblock.
             When a scriptblock is invoked with & from a different function scope,
             it does not inherit the caller's variables. Fixed by calling
             .GetNewClosure() on the scriptblock before passing it to
             Compare-ObjectSets, which captures $GroupIdMap from the defining
             scope at the time Compare-Groups runs.
      1.3.5  Fixed 'Get-SafeProp is not recognized' error inside the groups
             compareFunc. .GetNewClosure() captures variables but not functions.
             Replaced the remaining two Get-SafeProp calls (seeding the src/dst
             expression stacks) with inline PSObject.Properties checks.
      1.3.6  Fixed 'Get-SafeProp is not recognized' in ALL compare scriptblocks.
             .GetNewClosure() captures variables but not script-level functions,
             so every compareFunc had the same latent bug. Added a $SafeProp
             scriptblock variable (identical logic to Get-SafeProp) that IS
             captured by .GetNewClosure(). Replaced all Get-SafeProp calls
             inside every compare scriptblock with '& $SafeProp'. Applied
             .GetNewClosure() to all six Compare-ObjectSets call sites.
      1.3.7  Fixed 'expression after & produced an object that was not valid'.
             '$(if ($x.PSObject.Properties[$y]) { $x.$($y) }) | pipeline' is invalid - PowerShell cannot use
             & as a pipeline source element. Wrapped all such calls in @() so
             they become '@($(if ($x.PSObject.Properties[$y]) { $x.$($y) })) | pipeline'.
      1.4.0  Changed -GroupReviewList from a comma-separated string to a path to
             a plain-text file containing one group ID per line. Lines starting
             with # and blank lines are ignored. This makes it practical to manage
             larger review lists without hitting command-line length limits.
             Moved Write-Log function definition before its first call site so the
             function is always defined before it is used regardless of execution
             order. Added the review list groups as a dedicated section in both
             the console validation summary and the HTML report summary table, so
             reviewers can see which groups were deliberately downgraded to REVIEW.
      1.5.0  Removed IP Sets and Service Groups from both the console summary
             table and the HTML summary table - these object types are not
             compared by this script. Added Context Profiles to both summary
             tables. Adjusted totals calculations accordingly.
      1.5.1  Added mapping files for Policies and Rules. These files are created by
             Sanitize-NSXFirewallRules.ps1 version 1.3.2 and higher.
      1.5.2  Fixed false display_name MISMATCH on DFW policies when a policy
             mapping file is provided. Source policies may still carry the legacy
             suffix ":: NSX Service Composer - Firewall" in their display_name,
             while the destination has the sanitized name without it. The policy
             compareFunc now accepts $dstId and skips the display_name check when
             the ID was remapped, consistent with the same fix applied to services,
             groups, and profiles in earlier versions.
      1.5.3  Fixed MISSING_DST + MISSING_SRC false pair for rules when the same
             rule ID exists in multiple source policies. Rule IDs are only unique
             within a policy; a flat RuleIdMap hashtable caused later entries to
             overwrite earlier ones for duplicate IDs, so Resolve-Id returned the
             wrong NewId. The rule mapping file now includes a PolicyId column
             (written by Sanitize-NSXFirewallRules.ps1 v1.3.4+). Load-RuleMappingFile
             builds a nested hashtable (policyId -> oldRuleId -> newRuleId) and
             Compare-Policies passes the correct per-policy sub-map to
             Compare-ObjectSets for each rules fetch.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$SourceNSX,
    [Parameter(Mandatory)][string]$DestNSX,
    [string]$DomainId = 'default',
    [string]$OutputFolder = ".\NSX_Validation_$(Get-Date -Format 'yyyyMMdd_HHmmss')",
    [string]$LogFile = '',
    [ValidateSet('Screen', 'File', 'Both')]
    [string]$LogTarget = 'Screen',
    [bool]$CompareIPSets = $false,
    [bool]$CompareServices = $true,
    [bool]$CompareGroups = $true,
    [bool]$ComparePolicies = $true,
    [bool]$CompareProfiles = $true,
    [string]$GroupMappingFile = '',
    [string]$ServiceMappingFile = '',
    [string]$PolicyMappingFile = '',
    [string]$RuleMappingFile = '',
    [string]$GroupReviewList = ''
)

$ScriptVersion = '1.5.3'

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# --------------------------------------------------------------
# BOOTSTRAP OUTPUT FOLDER & LOG FILE
# --------------------------------------------------------------
if (-not (Test-Path $OutputFolder)) {
    New-Item -ItemType Directory -Path $OutputFolder -Force | Out-Null
}
$OutputFolder = (Resolve-Path $OutputFolder).Path

if (-not $LogFile) {
    $LogFile = Join-Path $OutputFolder "Compare-NSX-Migration_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
}

# --------------------------------------------------------------
# LOGGING
# --------------------------------------------------------------
function Write-Log {
    param(
        [string]$Message,
        [ValidateSet('INFO', 'WARN', 'ERROR', 'SUCCESS')][string]$Level = 'INFO'
    )
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $line = "[$ts][$Level] $Message"
    $color = switch ($Level) {
        'WARN' { 'Yellow' }
        'ERROR' { 'Red' }
        'SUCCESS' { 'Green' }
        default { 'Cyan' }
    }

    if ($LogTarget -eq 'Screen' -or $LogTarget -eq 'Both') {
        Write-Host $line -ForegroundColor $color
    }

    if (($LogTarget -eq 'File' -or $LogTarget -eq 'Both') -and $LogFile) {
        try {
            Add-Content -Path $LogFile -Value $line -Encoding UTF8
        }
        catch {
            Write-Host "[WARN] Could not write to log file: $_" -ForegroundColor Yellow
            Write-Host $line -ForegroundColor $color
        }
    }
}

# --------------------------------------------------------------
# Groups known to be system-managed but not flagged as _system_owned.
# These are provisioned by NSX Threat Intelligence, IDS/IPS, and related services.
# --------------------------------------------------------------
$pseudoSystemIds = @(
    'DefaultMaliciousIpGroup',
    'DefaultUDAGroup'
)

# --------------------------------------------------------------
# ID MAPPING TABLES
#
# Loaded from the _id_mapping.csv files produced by Sanitize-NSX.ps1.
# These translate source old IDs (e.g. securitygroup-223) to the renamed
# IDs that were imported into the destination (e.g. Datacenter).
# Both hashtables default to empty - comparisons then assume no renaming.
# -------------------------------------------------------------
$GroupIdMap = @{} # oldId -> newId for security groups
$ServiceIdMap = @{} # oldId -> newId for services
$PolicyIdMap = @{}  # oldId -> newId for policies
$RuleIdMap = @{}    # oldId -> newId for rules

function Load-MappingFile {
    param([string]$FilePath, [string]$Label)
    $map = @{}
    if (-not $FilePath) { return $map }
    if (-not (Test-Path $FilePath)) {
        Write-Warning "[$Label] Mapping file not found: $FilePath - ID translation disabled for this type."
        return $map
    }
    $rows = Import-Csv -Path $FilePath -Encoding UTF8
    foreach ($row in $rows) {
        if ($row.PSObject.Properties['OldId'] -and $row.PSObject.Properties['NewId'] -and $row.OldId -and $row.NewId) {
            $map[$row.OldId] = $row.NewId
        }
    }
    Write-Log "  [$Label] Loaded $($map.Count) ID mapping(s) from $(Split-Path $FilePath -Leaf)" INFO
    return $map
}

# Load a rule mapping file whose rows contain PolicyId, OldId, and NewId columns.
# Rule IDs are only unique within a policy, so the same OldId can legitimately
# appear in multiple policies with different NewIds. A flat hashtable would lose
# entries on collision; this function builds a nested hashtable instead:
#   policyId -> @{ oldRuleId -> newRuleId }
# The compare script passes the per-policy sub-map to Compare-ObjectSets so that
# Resolve-Id operates in the correct scope for each policy's rules.
function Load-RuleMappingFile {
    param([string]$FilePath, [string]$Label)
    $map = @{}   # policyId -> @{ oldRuleId -> newRuleId }
    if (-not $FilePath) { return $map }
    if (-not (Test-Path $FilePath)) {
        Write-Warning "[$Label] Mapping file not found: $FilePath - ID translation disabled for rules."
        return $map
    }
    $rows = Import-Csv -Path $FilePath -Encoding UTF8
    $total = 0
    foreach ($row in $rows) {
        if ($row.PSObject.Properties['PolicyId'] -and $row.PSObject.Properties['OldId'] -and $row.PSObject.Properties['NewId'] `
                -and $row.PolicyId -and $row.OldId -and $row.NewId) {
            if (-not $map.ContainsKey($row.PolicyId)) { $map[$row.PolicyId] = @{} }
            $map[$row.PolicyId][$row.OldId] = $row.NewId
            $total++
        }
    }
    Write-Log "  [$Label] Loaded $total rule ID mapping(s) across $($map.Count) policy/policies from $(Split-Path $FilePath -Leaf)" INFO
    return $map
}

if ($GroupMappingFile) { $GroupIdMap = Load-MappingFile -FilePath $GroupMappingFile   -Label 'Groups' }
if ($ServiceMappingFile) { $ServiceIdMap = Load-MappingFile -FilePath $ServiceMappingFile -Label 'Services' }
if ($PolicyMappingFile) { $PolicyIdMap = Load-MappingFile -FilePath $PolicyMappingFile -Label 'Policies' }
if ($RuleMappingFile) { $RuleIdMap = Load-RuleMappingFile -FilePath $RuleMappingFile -Label 'Rules' }

# --------------------------------------------------------------
# GROUP REVIEW SET
#
# Loaded from a plain-text file - one source group ID per line.
# Lines starting with # and blank lines are ignored.
# Groups in this set have their MISMATCH result downgraded to REVIEW.
# --------------------------------------------------------------
$GroupReviewSet = @{}
if ($GroupReviewList) {
    if (-not (Test-Path $GroupReviewList)) {
        Write-Log "Group review list file not found: $GroupReviewList - review list disabled." WARN
    }
    else {
        $lines = Get-Content -Path $GroupReviewList -Encoding UTF8
        foreach ($line in $lines) {
            $trimmed = $line.Trim()
            if ($trimmed -and -not $trimmed.StartsWith('#')) {
                $GroupReviewSet[$trimmed] = $true
            }
        }
        Write-Log "  [ReviewList] Loaded $($GroupReviewSet.Count) group(s) from $(Split-Path $GroupReviewList -Leaf) - these will be downgraded from MISMATCH to REVIEW" INFO
    }
}

# Translates a source object ID to its (potentially renamed) destination ID.
# Returns the mapped ID if one exists, otherwise returns the original.
function Resolve-Id {
    param([string]$Id, [hashtable]$IdMap)
    if ($IdMap.ContainsKey($Id)) { return $IdMap[$Id] }
    return $Id
}

# --------------------------------------------------------------
# IGNORE SELF-SIGNED CERTIFICATES
# --------------------------------------------------------------
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
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12

# --------------------------------------------------------------
# CREDENTIALS
# --------------------------------------------------------------
Write-Log "Compare-NSX-Migration.ps1 v$ScriptVersion" INFO
Write-Log "Enter credentials for SOURCE NSX Manager: $SourceNSX" INFO
$SrcCred = Get-Credential -Message "SOURCE NSX ($SourceNSX) credentials"
$SrcPair = "$($SrcCred.UserName):$($SrcCred.GetNetworkCredential().Password)"
$SrcBytes = [System.Text.Encoding]::ASCII.GetBytes($SrcPair)
$SrcHeaders = @{
    Authorization  = "Basic $([Convert]::ToBase64String($SrcBytes))"
    'Content-Type' = 'application/json'
}

Write-Log "Enter credentials for DESTINATION NSX Manager: $DestNSX" INFO
$DstCred = Get-Credential -Message "DESTINATION NSX ($DestNSX) credentials"
$DstPair = "$($DstCred.UserName):$($DstCred.GetNetworkCredential().Password)"
$DstBytes = [System.Text.Encoding]::ASCII.GetBytes($DstPair)
$DstHeaders = @{
    Authorization  = "Basic $([Convert]::ToBase64String($DstBytes))"
    'Content-Type' = 'application/json'
}

# --------------------------------------------------------------
# REST HELPERS
# --------------------------------------------------------------
function Invoke-NSXGet {
    param([string]$Manager, [hashtable]$Headers, [string]$Path)
    $uri = "https://$Manager$Path"
    try {
        return Invoke-RestMethod -Uri $uri -Method GET -Headers $Headers
    }
    catch {
        Write-Log "GET $uri failed: $_" ERROR
        return $null
    }
}

function Get-AllPages {
    param([string]$Manager, [hashtable]$Headers, [string]$Path)
    $allResults = @()
    $cursor = $null
    do {
        $url = if ($cursor) { "${Path}?cursor=$cursor&page_size=1000" } else { "${Path}?page_size=1000" }
        $resp = Invoke-NSXGet -Manager $Manager -Headers $Headers -Path $url
        if ($null -eq $resp) { break }
        if ($resp.PSObject.Properties['results'] -and $resp.results) {
            $allResults += $resp.results
        }
        $cursor = if ($resp.PSObject.Properties['cursor']) { $resp.cursor } else { $null }
    } while ($cursor)
    return $allResults
}

function Get-SafeProp {
    param([object]$Obj, [string]$Name)
    if ($null -eq $Obj) { return $null }
    if ($Obj.PSObject.Properties[$Name]) { return $Obj.$Name }
    return $null
}

function Format-Tags {
    param([object]$Obj)
    $tags = Get-SafeProp $Obj 'tags'
    if (-not $tags) { return '' }
    return ($tags | ForEach-Object { "$($_.scope):$($_.tag)" }) -join '; '
}

# --------------------------------------------------------------
# CONNECTIVITY CHECK
# --------------------------------------------------------------
function Test-Connectivity {
    param([string]$Manager, [hashtable]$Headers, [string]$Label)
    Write-Log "Checking connectivity to $Label ($Manager)..." INFO
    $info = Invoke-NSXGet -Manager $Manager -Headers $Headers -Path '/api/v1/node'
    if ($info) {
        Write-Log "  Connected - NSX version: $($info.product_version)" SUCCESS
        return $true
    }
    else {
        Write-Log "  FAILED to connect to $Label ($Manager)" ERROR
        return $false
    }
}

# --------------------------------------------------------------
# STATISTICS & FINDINGS COLLECTION
# --------------------------------------------------------------
$Stats = @{
    IPSets_Match = 0; IPSets_Mismatch = 0; IPSets_MissingDst = 0; IPSets_MissingSrc = 0
    Services_Match = 0; Services_Mismatch = 0; Services_MissingDst = 0; Services_MissingSrc = 0
    SvcGroups_Match = 0; SvcGroups_Mismatch = 0; SvcGroups_MissingDst = 0; SvcGroups_MissingSrc = 0
    Groups_Match = 0; Groups_Mismatch = 0; Groups_MissingDst = 0; Groups_MissingSrc = 0; Groups_Review = 0
    Policies_Match = 0; Policies_Mismatch = 0; Policies_MissingDst = 0; Policies_MissingSrc = 0
    Rules_Match = 0; Rules_Mismatch = 0; Rules_MissingDst = 0; Rules_MissingSrc = 0
    Profiles_Match = 0; Profiles_Mismatch = 0; Profiles_MissingDst = 0; Profiles_MissingSrc = 0
    TotalMatch = 0; TotalMismatch = 0; TotalMissingDst = 0; TotalMissingSrc = 0
    Errors = 0
}

# All individual finding rows go here for CSV + HTML export
$Findings = [System.Collections.Generic.List[PSCustomObject]]::new()

function Add-Finding {
    param(
        [string]$ObjectType,
        [string]$ObjectId,
        [string]$DisplayName,
        [ValidateSet('MATCH', 'MISMATCH', 'MISSING_DST', 'MISSING_SRC', 'REVIEW')][string]$Result,
        [string]$Detail = ''
    )
    $Findings.Add([PSCustomObject]@{
            ObjectType  = $ObjectType
            ObjectId    = $ObjectId
            DisplayName = $DisplayName
            Result      = $Result
            Detail      = $Detail
        })
}

# --------------------------------------------------------------
# GENERIC COMPARE HELPER
# Compares two hashtables (Id -> object) for a given object type.
# Calls $CompareFunc($srcObj, $dstObj) to check field-level equality.
# Returns a summary hashtable with Match/Mismatch/MissingDst/MissingSrc counts.
# --------------------------------------------------------------
function Compare-ObjectSets {
    param(
        [string]    $TypeLabel,
        [hashtable] $SrcMap,       # id -> object
        [hashtable] $DstMap,       # id -> object
        [scriptblock]$CompareFunc, # ($src,$dst) -> @{Equal=$bool; Detail='...'}
        [hashtable] $IdMap = @{},  # source oldId -> destination newId (from mapping file)
        [hashtable] $ReviewSet = @{} # source IDs whose MISMATCH should be downgraded to REVIEW
    )

    $counts = @{ Match = 0; Mismatch = 0; MissingDst = 0; MissingSrc = 0; Review = 0 }

    # Objects present in source - check if they reached the destination
    foreach ($id in $SrcMap.Keys) {
        $src = $SrcMap[$id]
        $name = if ((Get-SafeProp $src 'display_name')) { $src.display_name } else { $id }
        $dstId = Resolve-Id -Id $id -IdMap $IdMap   # translate to renamed ID if applicable
        $idNote = if ($dstId -ne $id) { " (renamed to '$dstId' on destination)" } else { '' }

        if ($DstMap.ContainsKey($dstId)) {
            $dst = $DstMap[$dstId]
            $result = & $CompareFunc $src $dst $dstId $IdMap
            if ($result.Equal) {
                Write-Log "  MATCH        [$TypeLabel] $id ($name)$idNote" SUCCESS
                Add-Finding -ObjectType $TypeLabel -ObjectId $id -DisplayName $name -Result 'MATCH' -Detail $idNote.Trim()
                $counts.Match++
            }
            elseif ($ReviewSet.ContainsKey($id)) {
                Write-Log "  REVIEW       [$TypeLabel] $id ($name)$idNote - $($result.Detail)" WARN
                Add-Finding -ObjectType $TypeLabel -ObjectId $id -DisplayName $name -Result 'REVIEW' -Detail ('Manually reviewed - ' + $idNote.Trim() + $(if ($idNote) { ' | ' } else { '' }) + $result.Detail)
                $counts.Review++
            }
            else {
                Write-Log "  MISMATCH     [$TypeLabel] $id ($name)$idNote - $($result.Detail)" WARN
                Add-Finding -ObjectType $TypeLabel -ObjectId $id -DisplayName $name -Result 'MISMATCH' -Detail ($idNote.Trim() + $(if ($idNote) { ' | ' } else { '' }) + $result.Detail)
                $counts.Mismatch++
            }
        }
        else {
            Write-Log "  MISSING_DST  [$TypeLabel] $id ($name)$idNote - not found on destination" ERROR
            Add-Finding -ObjectType $TypeLabel -ObjectId $id -DisplayName $name -Result 'MISSING_DST' -Detail "Object not found on destination NSX Manager$idNote"
            $counts.MissingDst++
        }
    }

    # Objects present on destination but not traceable back to any source ID
    # Build the set of all destination IDs that were claimed by a source object
    $claimedDstIds = @{}
    foreach ($id in $SrcMap.Keys) {
        $claimedDstIds[(Resolve-Id -Id $id -IdMap $IdMap)] = $true
    }

    foreach ($id in $DstMap.Keys) {
        if (-not $claimedDstIds.ContainsKey($id)) {
            $dst = $DstMap[$id]
            $name = if ((Get-SafeProp $dst 'display_name')) { $dst.display_name } else { $id }
            Write-Log "  MISSING_SRC  [$TypeLabel] $id ($name) - exists on destination but not on source" WARN
            Add-Finding -ObjectType $TypeLabel -ObjectId $id -DisplayName $name -Result 'MISSING_SRC' -Detail 'Object exists on destination but has no counterpart on source'
            $counts.MissingSrc++
        }
    }

    return $counts
}


# Helper: build an id-keyed hashtable from an array, filtering out system-owned objects
function Build-Map {
    param([object[]]$Objects)
    $map = @{}
    foreach ($obj in $Objects) {
        if ((Get-SafeProp $obj '_system_owned') -eq $true -or (Get-SafeProp $obj '_create_user') -eq 'system' -or $obj.id -in $pseudoSystemIds) { continue }
        $id = Get-SafeProp $obj 'id'
        if ($id) { $map[$id] = $obj }
    }
    return $map
}

# -------------------------------------------------------------
# 1. COMPARE IP SETS
# -------------------------------------------------------------
function Compare-IPSets {
    Write-Log "" INFO
    Write-Log "------------------------------------------------------------------" INFO
    Write-Log "  COMPARING IP SETS" INFO
    Write-Log "------------------------------------------------------------------" INFO

    Write-Log "  Fetching IP Sets from source ($SourceNSX)..." INFO
    $srcObjs = Get-AllPages -Manager $SourceNSX -Headers $SrcHeaders -Path '/api/v1/ip-sets'
    Write-Log "  Fetching IP Sets from destination ($DestNSX)..." INFO
    $dstObjs = Get-AllPages -Manager $DestNSX   -Headers $DstHeaders -Path '/api/v1/ip-sets'

    $srcMap = Build-Map $srcObjs
    $dstMap = Build-Map $dstObjs
    Write-Log "  Source: $($srcMap.Count) custom IP Sets  |  Destination: $($dstMap.Count) custom IP Sets" INFO

    $compareFunc = {
        param($src, $dst)
        $diffs = @()

        # Display name
        if ($src.display_name -ne $dst.display_name) {
            $diffs += "display_name: '$($src.display_name)' → '$($dst.display_name)'"
        }

        # IP addresses (order-insensitive)
        $srcIPList = if ($src.PSObject.Properties['ip_addresses'] -and $null -ne $src.ip_addresses) { @($src.ip_addresses) } else { @() }
        $srcIPs = @($srcIPList | Where-Object { $null -ne $_ } | Sort-Object)
        $dstIPList = if ($dst.PSObject.Properties['ip_addresses'] -and $null -ne $dst.ip_addresses) { @($dst.ip_addresses) } else { @() }
        $dstIPs = @($dstIPList | Where-Object { $null -ne $_ } | Sort-Object)
        $added = $dstIPs | Where-Object { $_ -notin $srcIPs }
        $removed = $srcIPs | Where-Object { $_ -notin $dstIPs }
        if ($added) { $diffs += "addresses added on dst: $($added -join ', ')" }
        if ($removed) { $diffs += "addresses missing on dst: $($removed -join ', ')" }

        if ($diffs.Count -eq 0) { return @{ Equal = $true; Detail = '' } }
        return @{ Equal = $false; Detail = ($diffs -join ' | ') }
    }

    $c = Compare-ObjectSets -TypeLabel 'IPSet' -SrcMap $srcMap -DstMap $dstMap -CompareFunc $compareFunc.GetNewClosure()
    $Stats.IPSets_Match += $c.Match
    $Stats.IPSets_Mismatch += $c.Mismatch
    $Stats.IPSets_MissingDst += $c.MissingDst
    $Stats.IPSets_MissingSrc += $c.MissingSrc
    Write-Log "  IP Sets result: $($c.Match) match | $($c.Mismatch) mismatch | $($c.MissingDst) missing on dst | $($c.MissingSrc) extra on dst" INFO
}

# -------------------------------------------------------------
# 2. COMPARE SERVICES & SERVICE GROUPS
# -------------------------------------------------------------
function Compare-Services {
    Write-Log "" INFO
    Write-Log "------------------------------------------------------------------" INFO
    Write-Log "  COMPARING SERVICES" INFO
    Write-Log "------------------------------------------------------------------" INFO

    Write-Log "  Fetching Services from source ($SourceNSX)..." INFO
    $srcAll = Get-AllPages -Manager $SourceNSX -Headers $SrcHeaders -Path '/policy/api/v1/infra/services'
    Write-Log "  Fetching Services from destination ($DestNSX)..." INFO
    $dstAll = Get-AllPages -Manager $DestNSX   -Headers $DstHeaders -Path '/policy/api/v1/infra/services'

    # Split into services vs service groups by resource_type
    $srcSvcs = Build-Map ($srcAll | Where-Object { (Get-SafeProp $_ 'resource_type') -ne 'PolicyServiceGroup' })
    $dstSvcs = Build-Map ($dstAll | Where-Object { (Get-SafeProp $_ 'resource_type') -ne 'PolicyServiceGroup' })
    $srcSGs = Build-Map ($srcAll | Where-Object { (Get-SafeProp $_ 'resource_type') -eq 'PolicyServiceGroup' })
    $dstSGs = Build-Map ($dstAll | Where-Object { (Get-SafeProp $_ 'resource_type') -eq 'PolicyServiceGroup' })

    Write-Log "  Services  - Source: $($srcSvcs.Count)  |  Destination: $($dstSvcs.Count)" INFO
    Write-Log "  Svc Groups - Source: $($srcSGs.Count)   |  Destination: $($dstSGs.Count)" INFO

    # Service compare: check display_name + service_entries count + protocol summary
    $svcCompare = {
        param($src, $dst, $dstId)
        $diffs = @()

        # Skip display_name check when the ID was remapped by sanitization - the
        # destination display_name is expected to differ (it was renamed to match the new ID).
        if (-not $dstId -or $src.id -eq $dstId) {
            if ($src.display_name -ne $dst.display_name) {
                $diffs += "display_name: '$($src.display_name)' → '$($dst.display_name)'"
            }
        }

        $srcEntries = if ($src.PSObject.Properties['service_entries'] -and $null -ne $src.service_entries) { @($src.service_entries) } else { @() }
        $dstEntries = if ($dst.PSObject.Properties['service_entries'] -and $null -ne $dst.service_entries) { @($dst.service_entries) } else { @() }
        if ($srcEntries.Count -ne $dstEntries.Count) {
            $diffs += "service_entries count: $($srcEntries.Count) → $($dstEntries.Count)"
        }
        else {
            # Sort both entry lists by a canonical key so entry order differences
            # between source and destination do not cause false mismatches.
            $srcSorted = @($srcEntries | Sort-Object {
                    $rt = if ($_.PSObject.Properties['resource_type']) { $_.resource_type } else { '' }
                    $proto = if ($_.PSObject.Properties['l4_protocol']) { $_.l4_protocol } else { '' }
                    $dportRaw = if ($_.PSObject.Properties['destination_ports'] -and $null -ne $_.destination_ports) { $_.destination_ports } else { $null }
                    $dport = if ($dportRaw -is [array]) { ($dportRaw | Sort-Object) -join ',' } else { "$dportRaw" }
                    $sportRaw = if ($_.PSObject.Properties['source_ports'] -and $null -ne $_.source_ports) { $_.source_ports } else { $null }
                    $sport = if ($sportRaw -is [array]) { ($sportRaw | Sort-Object) -join ',' } else { "$sportRaw" }
                    $icmp = if ($_.PSObject.Properties['icmp_type']) { $_.icmp_type } else { '' }
                    $pnum = if ($_.PSObject.Properties['protocol_number']) { $_.protocol_number } else { '' }
                    "$rt|$proto|$dport|$sport|$icmp|$pnum"
                })
            $dstSorted = @($dstEntries | Sort-Object {
                    $rt = if ($_.PSObject.Properties['resource_type']) { $_.resource_type } else { '' }
                    $proto = if ($_.PSObject.Properties['l4_protocol']) { $_.l4_protocol } else { '' }
                    $dportRaw = if ($_.PSObject.Properties['destination_ports'] -and $null -ne $_.destination_ports) { $_.destination_ports } else { $null }
                    $dport = if ($dportRaw -is [array]) { ($dportRaw | Sort-Object) -join ',' } else { "$dportRaw" }
                    $sportRaw = if ($_.PSObject.Properties['source_ports'] -and $null -ne $_.source_ports) { $_.source_ports } else { $null }
                    $sport = if ($sportRaw -is [array]) { ($sportRaw | Sort-Object) -join ',' } else { "$sportRaw" }
                    $icmp = if ($_.PSObject.Properties['icmp_type']) { $_.icmp_type } else { '' }
                    $pnum = if ($_.PSObject.Properties['protocol_number']) { $_.protocol_number } else { '' }
                    "$rt|$proto|$dport|$sport|$icmp|$pnum"
                })

            for ($i = 0; $i -lt $srcSorted.Count; $i++) {
                $se = $srcSorted[$i]; $de = $dstSorted[$i]
                if ($se.resource_type -ne $de.resource_type) {
                    $diffs += "entry[$i] resource_type: $($se.resource_type) → $($de.resource_type)"
                }
                foreach ($f in @('l4_protocol', 'destination_ports', 'source_ports', 'icmp_type', 'protocol_number')) {
                    $sv = if ($se.PSObject.Properties[$f]) { $se.$f } else { $null }; $dv = if ($de.PSObject.Properties[$f]) { $de.$f } else { $null }
                    $svStr = if ($sv -is [array]) { ($sv | Sort-Object) -join ',' } else { "$sv" }
                    $dvStr = if ($dv -is [array]) { ($dv | Sort-Object) -join ',' } else { "$dv" }
                    if ($svStr -ne $dvStr) {
                        $diffs += "entry[$i].${f}: '$svStr' → '$dvStr'"
                    }
                }
            }
        }

        if ($diffs.Count -eq 0) { return @{ Equal = $true; Detail = '' } }
        return @{ Equal = $false; Detail = ($diffs -join ' | ') }
    }

    # Service group compare: check display_name + member paths (order-insensitive)
    $sgCompare = {
        param($src, $dst, $dstId)
        $diffs = @()

        # Skip display_name check when the ID was remapped by sanitization - the
        # destination display_name is expected to differ (it was renamed to match the new ID).
        if (-not $dstId -or $src.id -eq $dstId) {
            if ($src.display_name -ne $dst.display_name) {
                $diffs += "display_name: '$($src.display_name)' → '$($dst.display_name)'"
            }
        }

        $srcMemberList = if ($src.PSObject.Properties['members'] -and $null -ne $src.members) { @($src.members) } else { @() }
        $srcMembers = @($srcMemberList | Where-Object { $null -ne $_ } | ForEach-Object { $_.path } | Sort-Object)
        $dstMemberList = if ($dst.PSObject.Properties['members'] -and $null -ne $dst.members) { @($dst.members) } else { @() }
        $dstMembers = @($dstMemberList | Where-Object { $null -ne $_ } | ForEach-Object { $_.path } | Sort-Object)
        $added = $dstMembers | Where-Object { $_ -notin $srcMembers }
        $removed = $srcMembers | Where-Object { $_ -notin $dstMembers }
        if ($added) { $diffs += "members added on dst: $($added -join ', ')" }
        if ($removed) { $diffs += "members missing on dst: $($removed -join ', ')" }

        if ($diffs.Count -eq 0) { return @{ Equal = $true; Detail = '' } }
        return @{ Equal = $false; Detail = ($diffs -join ' | ') }
    }

    Write-Log "  --- Services ---" INFO
    $c1 = Compare-ObjectSets -TypeLabel 'Service' -SrcMap $srcSvcs -DstMap $dstSvcs -CompareFunc $svcCompare.GetNewClosure() -IdMap $ServiceIdMap
    $Stats.Services_Match += $c1.Match
    $Stats.Services_Mismatch += $c1.Mismatch
    $Stats.Services_MissingDst += $c1.MissingDst
    $Stats.Services_MissingSrc += $c1.MissingSrc
    Write-Log "  Services result: $($c1.Match) match | $($c1.Mismatch) mismatch | $($c1.MissingDst) missing on dst | $($c1.MissingSrc) extra on dst" INFO

    Write-Log "  --- Service Groups ---" INFO
    $c2 = Compare-ObjectSets -TypeLabel 'ServiceGroup' -SrcMap $srcSGs -DstMap $dstSGs -CompareFunc $sgCompare.GetNewClosure() -IdMap $ServiceIdMap
    $Stats.SvcGroups_Match += $c2.Match
    $Stats.SvcGroups_Mismatch += $c2.Mismatch
    $Stats.SvcGroups_MissingDst += $c2.MissingDst
    $Stats.SvcGroups_MissingSrc += $c2.MissingSrc
    Write-Log "  Service Groups result: $($c2.Match) match | $($c2.Mismatch) mismatch | $($c2.MissingDst) missing on dst | $($c2.MissingSrc) extra on dst" INFO
}

# -------------------------------------------------------------
# 3. COMPARE SECURITY GROUPS
# -------------------------------------------------------------
function Compare-Groups {
    Write-Log "" INFO
    Write-Log "------------------------------------------------------------------" INFO
    Write-Log "  COMPARING SECURITY GROUPS" INFO
    Write-Log "------------------------------------------------------------------" INFO

    Write-Log "  Fetching Security Groups from source ($SourceNSX)..." INFO
    $srcObjs = Get-AllPages -Manager $SourceNSX -Headers $SrcHeaders -Path "/policy/api/v1/infra/domains/$DomainId/groups"
    Write-Log "  Fetching Security Groups from destination ($DestNSX)..." INFO
    $dstObjs = Get-AllPages -Manager $DestNSX   -Headers $DstHeaders -Path "/policy/api/v1/infra/domains/$DomainId/groups"

    $srcMap = Build-Map $srcObjs
    $dstMap = Build-Map $dstObjs
    Write-Log "  Source: $($srcMap.Count) custom Groups  |  Destination: $($dstMap.Count) custom Groups" INFO

    $compareFunc = {
        param($src, $dst, $dstId, $idMap)
        $diffs = @()

        # Skip display_name check when the ID was remapped by sanitization - the
        # destination display_name is expected to differ (it was renamed to match the new ID).
        if (-not $dstId -or $src.id -eq $dstId) {
            if ($src.display_name -ne $dst.display_name) {
                $diffs += "display_name: '$($src.display_name)' → '$($dst.display_name)'"
            }
        }

        # Flatten all leaf expressions from a group's expression tree using an
        # iterative stack - no nested functions (unsupported in scriptblocks).
        # ConjunctionOperator entries are skipped; NestedExpression blocks are
        # unpacked by pushing their inner expressions onto the stack.
        # This means conditions/paths split across any structure compare equally.
        # Flatten leaf expressions using a plain array as a queue (no .NET generics).
        # Process each expression: skip nulls/ConjunctionOperators, unpack NestedExpressions,
        # collect everything else as a leaf.
        $srcLeaves = @()
        $srcQueue = if ($src.PSObject.Properties['expression'] -and $null -ne $src.expression) { @($src.expression | Where-Object { $null -ne $_ }) } else { @() }
        for ($qi = 0; $qi -lt $srcQueue.Count; $qi++) {
            $e = $srcQueue[$qi]
            if ($null -eq $e) { continue }
            $rt = if ($e.PSObject.Properties['resource_type']) { $e.resource_type } else { '' }
            if ($rt -eq 'ConjunctionOperator') { continue }
            if ($rt -eq 'NestedExpression') {
                if ($e.PSObject.Properties['expressions'] -and $null -ne $e.expressions) {
                    $srcQueue += @($e.expressions | Where-Object { $null -ne $_ })
				}
            }
            else { $srcLeaves += $e }
        }

        $dstLeaves = @()
        $dstQueue = if ($dst.PSObject.Properties['expression'] -and $null -ne $dst.expression) { @($dst.expression | Where-Object { $null -ne $_ }) } else { @() }
        for ($qi = 0; $qi -lt $dstQueue.Count; $qi++) {
            $e = $dstQueue[$qi]
            if ($null -eq $e) { continue }
            $rt = if ($e.PSObject.Properties['resource_type']) { $e.resource_type } else { '' }
            if ($rt -eq 'ConjunctionOperator') { continue }
            if ($rt -eq 'NestedExpression') {
                if ($e.PSObject.Properties['expressions'] -and $null -ne $e.expressions) {
                    $dstQueue += @($e.expressions | Where-Object { $null -ne $_ })
				}
            }
            else { $dstLeaves += $e }
        }

        # --- Flatten all PathExpression paths from source (with ID translation) ---
        $srcAllPaths = @($srcLeaves | Where-Object { $null -ne $_ -and $_.PSObject.Properties['resource_type'] -and $_.resource_type -eq 'PathExpression' } | ForEach-Object {
                if ($_.PSObject.Properties['paths']) { $_.paths }
            } | ForEach-Object {
                if ($_ -match '^(.*/)([^/]+)$') {
                    $mappedId = if ($idMap -and $idMap.ContainsKey($Matches[2])) { $idMap[$Matches[2]] } else { $Matches[2] }
                    "$($Matches[1])$mappedId"
                }
                else { $_ }
            } | Sort-Object)

        $dstAllPaths = @($dstLeaves | Where-Object { $null -ne $_ -and $_.PSObject.Properties['resource_type'] -and $_.resource_type -eq 'PathExpression' } | ForEach-Object {
                if ($_.PSObject.Properties['paths']) { $_.paths }
            } | Sort-Object)

        $addedPaths = $dstAllPaths | Where-Object { $_ -notin $srcAllPaths }
        $removedPaths = $srcAllPaths | Where-Object { $_ -notin $dstAllPaths }
        if ($addedPaths) { $diffs += "paths added on dst: $($addedPaths -join ', ')" }
        if ($removedPaths) { $diffs += "paths missing on dst: $($removedPaths -join ', ')" }

        # --- Flatten all Conditions from source and destination ---
        $srcConditions = @($srcLeaves | Where-Object { $null -ne $_ -and $_.PSObject.Properties['resource_type'] -and $_.resource_type -eq 'Condition' } | ForEach-Object {
                $mt = if ($_.PSObject.Properties['member_type']) { $_.member_type.ToUpper() } else { '' }
                $k = if ($_.PSObject.Properties['key']) { $_.key.ToUpper() } else { '' }
                $op = if ($_.PSObject.Properties['operator']) { $_.operator.ToUpper() } else { '' }
                $v = if ($_.PSObject.Properties['value']) { $_.value } else { '' }
                "$mt|$k|$op|$v"
            } | Sort-Object)

        $dstConditions = @($dstLeaves | Where-Object { $null -ne $_ -and $_.PSObject.Properties['resource_type'] -and $_.resource_type -eq 'Condition' } | ForEach-Object {
                $mt = if ($_.PSObject.Properties['member_type']) { $_.member_type.ToUpper() } else { '' }
                $k = if ($_.PSObject.Properties['key']) { $_.key.ToUpper() } else { '' }
                $op = if ($_.PSObject.Properties['operator']) { $_.operator.ToUpper() } else { '' }
                $v = if ($_.PSObject.Properties['value']) { $_.value } else { '' }
                "$mt|$k|$op|$v"
            } | Sort-Object)

        $addedCond = $dstConditions | Where-Object { $_ -notin $srcConditions }
        $removedCond = $srcConditions | Where-Object { $_ -notin $dstConditions }
        if ($addedCond) { $diffs += "conditions added on dst: $($addedCond -join '; ')" }
        if ($removedCond) { $diffs += "conditions missing on dst: $($removedCond -join '; ')" }

        if ($diffs.Count -eq 0) { return @{ Equal = $true; Detail = '' } }
        return @{ Equal = $false; Detail = ($diffs -join ' | ') }
    }

    $c = Compare-ObjectSets -TypeLabel 'Group' -SrcMap $srcMap -DstMap $dstMap -CompareFunc $compareFunc.GetNewClosure() -IdMap $GroupIdMap -ReviewSet $GroupReviewSet
    $Stats.Groups_Match += $c.Match
    $Stats.Groups_Mismatch += $c.Mismatch
    $Stats.Groups_MissingDst += $c.MissingDst
    $Stats.Groups_MissingSrc += $c.MissingSrc
    $Stats.Groups_Review += $c.Review
    Write-Log "  Security Groups result: $($c.Match) match | $($c.Mismatch) mismatch | $($c.MissingDst) missing on dst | $($c.MissingSrc) extra on dst | $($c.Review) review" INFO
}

# -------------------------------------------------------------
# 4. COMPARE DFW POLICIES & RULES
# -------------------------------------------------------------
function Compare-Policies {
    Write-Log "" INFO
    Write-Log "------------------------------------------------------------------" INFO
    Write-Log "  COMPARING DFW POLICIES & RULES" INFO
    Write-Log "------------------------------------------------------------------" INFO

    Write-Log "  Fetching DFW Policies from source ($SourceNSX)..." INFO
    $srcPolicies = Get-AllPages -Manager $SourceNSX -Headers $SrcHeaders -Path "/policy/api/v1/infra/domains/$DomainId/security-policies"
    Write-Log "  Fetching DFW Policies from destination ($DestNSX)..." INFO
    $dstPolicies = Get-AllPages -Manager $DestNSX   -Headers $DstHeaders -Path "/policy/api/v1/infra/domains/$DomainId/security-policies"

    $srcPolMap = Build-Map $srcPolicies
    $dstPolMap = Build-Map $dstPolicies
    Write-Log "  Source: $($srcPolMap.Count) custom Policies  |  Destination: $($dstPolMap.Count) custom Policies" INFO

    $polCompare = {
        param($src, $dst, $dstId)
        $diffs = @()
        # Skip display_name check when the ID was remapped by sanitization — the
        # destination display_name is expected to differ (suffix stripped + sanitized).
        if (-not $dstId -or $src.id -eq $dstId) {
            if ($src.display_name -ne $dst.display_name) { $diffs += "display_name: '$($src.display_name)' → '$($dst.display_name)'" }
        }
        foreach ($f in @('category', 'sequence_number')) {
            $sv = if ($src.PSObject.Properties[$f]) { $src.$f } else { $null }; $dv = if ($dst.PSObject.Properties[$f]) { $dst.$f } else { $null }
            if ("$sv" -ne "$dv") { $diffs += "${f}: '$sv' → '$dv'" }
        }
        if ($diffs.Count -eq 0) { return @{ Equal = $true; Detail = '' } }
        return @{ Equal = $false; Detail = ($diffs -join ' | ') }
    }

    $pc = Compare-ObjectSets -TypeLabel 'Policy' -SrcMap $srcPolMap -DstMap $dstPolMap -CompareFunc $polCompare.GetNewClosure() -IdMap $PolicyIdMap
    $Stats.Policies_Match += $pc.Match
    $Stats.Policies_Mismatch += $pc.Mismatch
    $Stats.Policies_MissingDst += $pc.MissingDst
    $Stats.Policies_MissingSrc += $pc.MissingSrc
    Write-Log "  Policies result: $($pc.Match) match | $($pc.Mismatch) mismatch | $($pc.MissingDst) missing on dst | $($pc.MissingSrc) extra on dst" INFO

    # Rules - per policy
    $ruleCompare = {
        #param($src, $dst)
        param($src, $dst, $dstId)
		$diffs = @()
        #if ($src.display_name -ne $dst.display_name) { $diffs += "display_name: '$($src.display_name)' → '$($dst.display_name)'" }
        # Skip display_name check when ID was remapped by sanitization
		if (-not $dstId -or $src.id -eq $dstId) {
			if ($src.display_name -ne $dst.display_name) { 
				$diffs += "display_name: '$($src.display_name)' → '$($dst.display_name)'" 
			}
		}
		foreach ($f in @('action', 'direction', 'ip_protocol', 'disabled', 'logged', 'sequence_number')) {
            $sv = if ($src.PSObject.Properties[$f]) { $src.$f } else { $null }; $dv = if ($dst.PSObject.Properties[$f]) { $dst.$f } else { $null }
            if ("$sv" -ne "$dv") { $diffs += "${f}: '$sv' → '$dv'" }
        }
        foreach ($listField in @('sources_excluded', 'destinations_excluded')) {
            $sv = if ($src.PSObject.Properties[$listField]) { $src.$listField } else { $null }; $dv = if ($dst.PSObject.Properties[$listField]) { $dst.$listField } else { $null }
            if ("$sv" -ne "$dv") { $diffs += "${listField}: '$sv' → '$dv'" }
        }
        if ($diffs.Count -eq 0) { return @{ Equal = $true; Detail = '' } }
        return @{ Equal = $false; Detail = ($diffs -join ' | ') }
    }

    foreach ($polId in $srcPolMap.Keys) {
        $polName = $srcPolMap[$polId].display_name
		
		# Resolve the policy ID to its destination counterpart
		$dstPolId = Resolve-Id -Id $polId -IdMap $PolicyIdMap
		
		Write-Log "    Fetching rules for policy: $polId → $dstPolId" INFO

        $srcRules = Get-AllPages -Manager $SourceNSX -Headers $SrcHeaders -Path "/policy/api/v1/infra/domains/$DomainId/security-policies/$polId/rules"
        $dstRules = Get-AllPages -Manager $DestNSX   -Headers $DstHeaders -Path "/policy/api/v1/infra/domains/$DomainId/security-policies/$dstPolId/rules"

        $srcRuleMap = @{}
        foreach ($r in $srcRules) { if (Get-SafeProp $r 'id') { $srcRuleMap[$r.id] = $r } }
        $dstRuleMap = @{}
        foreach ($r in $dstRules) { if (Get-SafeProp $r 'id') { $dstRuleMap[$r.id] = $r } }

        Write-Log "    Rules - Source: $($srcRuleMap.Count)  |  Destination: $($dstRuleMap.Count)" INFO

        # Look up the per-policy rule ID sub-map. Rule IDs are only unique within
        # a policy, so $RuleIdMap is keyed by source policy ID. If no sub-map exists
        # for this policy (no rules were renamed), pass an empty hashtable so
        # Compare-ObjectSets treats all rule IDs as unchanged.
        $ruleIdSubMap = if ($RuleIdMap.ContainsKey($polId)) { $RuleIdMap[$polId] } else { @{} }

        $rc = Compare-ObjectSets -TypeLabel "Rule[$polName]" -SrcMap $srcRuleMap -DstMap $dstRuleMap -CompareFunc $ruleCompare.GetNewClosure() -IdMap $ruleIdSubMap
        $Stats.Rules_Match += $rc.Match
        $Stats.Rules_Mismatch += $rc.Mismatch
        $Stats.Rules_MissingDst += $rc.MissingDst
        $Stats.Rules_MissingSrc += $rc.MissingSrc
    }
    Write-Log "  Rules result: $($Stats.Rules_Match) match | $($Stats.Rules_Mismatch) mismatch | $($Stats.Rules_MissingDst) missing on dst | $($Stats.Rules_MissingSrc) extra on dst" INFO
}

# -------------------------------------------------------------
# 5. COMPARE CONTEXT PROFILES
# -------------------------------------------------------------
function Compare-Profiles {
    Write-Log "" INFO
    Write-Log "------------------------------------------------------------------" INFO
    Write-Log "  COMPARING CONTEXT PROFILES" INFO
    Write-Log "------------------------------------------------------------------" INFO

    Write-Log "  Fetching Context Profiles from source ($SourceNSX)..." INFO
    $srcObjs = Get-AllPages -Manager $SourceNSX -Headers $SrcHeaders -Path '/policy/api/v1/infra/context-profiles'
    Write-Log "  Fetching Context Profiles from destination ($DestNSX)..." INFO
    $dstObjs = Get-AllPages -Manager $DestNSX   -Headers $DstHeaders -Path '/policy/api/v1/infra/context-profiles'
	
	# Exclude APP_POP2 profile from comparison
	$srcObjs = $srcObjs | Where-Object { $_.display_name -ne "APP_POP2" }
	$dstObjs = $dstObjs | Where-Object { $_.display_name -ne "APP_POP2" }

    $srcMap = Build-Map $srcObjs
    $dstMap = Build-Map $dstObjs
    Write-Log "  Source: $($srcMap.Count) custom Profiles  |  Destination: $($dstMap.Count) custom Profiles" INFO

    $profileCompare = {
        param($src, $dst, $dstId)
        $diffs = @()

        # Skip display_name check when ID was remapped by sanitization
        if (-not $dstId -or $src.id -eq $dstId) {
            if ($src.display_name -ne $dst.display_name) {
                $diffs += "display_name: '$($src.display_name)' → '$($dst.display_name)'"
            }
        }

        # Compare attributes (order-insensitive).
        # Each attribute has a 'key' and a 'value' array. Build canonical key=value strings and compare as sets.
        $srcAttrs = if ($src.PSObject.Properties['attributes'] -and $null -ne $src.attributes) { @($src.attributes) } else { @() }
        $dstAttrs = if ($dst.PSObject.Properties['attributes'] -and $null -ne $dst.attributes) { @($dst.attributes) } else { @() }

        $srcAttrKeys = @($srcAttrs | ForEach-Object {
                $k = if ($_.PSObject.Properties['key']) { $_.key } else { '' }
                $vList = if ($_.PSObject.Properties['value'] -and $null -ne $_.value) { @($_.value) } else { @() }
                $v = ($vList | Sort-Object) -join ','
                "$k=$v"
            } | Sort-Object)

        $dstAttrKeys = @($dstAttrs | ForEach-Object {
                $k = if ($_.PSObject.Properties['key']) { $_.key } else { '' }
                $vList = if ($_.PSObject.Properties['value'] -and $null -ne $_.value) { @($_.value) } else { @() }
                $v = ($vList | Sort-Object) -join ','
                "$k=$v"
            } | Sort-Object)

        $added = $dstAttrKeys | Where-Object { $_ -notin $srcAttrKeys }
        $removed = $srcAttrKeys | Where-Object { $_ -notin $dstAttrKeys }
        if ($added) { $diffs += "attributes added on dst: $($added -join '; ')" }
        if ($removed) { $diffs += "attributes missing on dst: $($removed -join '; ')" }

        if ($diffs.Count -eq 0) { return @{ Equal = $true; Detail = '' } }
        return @{ Equal = $false; Detail = ($diffs -join ' | ') }
    }

    $c = Compare-ObjectSets -TypeLabel 'Profile' -SrcMap $srcMap -DstMap $dstMap -CompareFunc $profileCompare.GetNewClosure()
    $Stats.Profiles_Match += $c.Match
    $Stats.Profiles_Mismatch += $c.Mismatch
    $Stats.Profiles_MissingDst += $c.MissingDst
    $Stats.Profiles_MissingSrc += $c.MissingSrc
    Write-Log "  Profiles result: $($c.Match) match | $($c.Mismatch) mismatch | $($c.MissingDst) missing on dst | $($c.MissingSrc) extra on dst" INFO
}


# --------------------------------------------------------------
# REPORT GENERATION
# --------------------------------------------------------------
function Export-CsvReport {
    $csvPath = Join-Path $OutputFolder "NSX_Migration_Validation_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    $Findings | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
    Write-Log "  CSV report written to: $csvPath" SUCCESS
    return $csvPath
}

function Get-ResultBadge {
    param([string]$Result)
    switch ($Result) {
        'MATCH' { return '<span class="badge match">✔ MATCH</span>' }
        'MISMATCH' { return '<span class="badge mismatch">⚠️ MISMATCH</span>' }
        'MISSING_DST' { return '<span class="badge missing-dst">✖ MISSING ON DST</span>' }
        'MISSING_SRC' { return '<span class="badge missing-src">✖ EXTRA ON DST</span>' }
        'REVIEW' { return '<span class="badge review">~ REVIEW</span>' }
        default { return "<span class='badge'>$Result</span>" }
    }
}

function Export-HtmlReport {
    param([string]$CsvPath)

    $totalMatch = ($Stats.IPSets_Match + $Stats.Services_Match + $Stats.SvcGroups_Match + $Stats.Groups_Match + $Stats.Profiles_Match + $Stats.Policies_Match + $Stats.Rules_Match)
    $totalMismatch = ($Stats.IPSets_Mismatch + $Stats.Services_Mismatch + $Stats.SvcGroups_Mismatch + $Stats.Groups_Mismatch + $Stats.Profiles_Mismatch + $Stats.Policies_Mismatch + $Stats.Rules_Mismatch)
    $totalMissingDst = ($Stats.IPSets_MissingDst + $Stats.Services_MissingDst + $Stats.SvcGroups_MissingDst + $Stats.Groups_MissingDst + $Stats.Profiles_MissingDst + $Stats.Policies_MissingDst + $Stats.Rules_MissingDst)
    $totalMissingSrc = ($Stats.IPSets_MissingSrc + $Stats.Services_MissingSrc + $Stats.SvcGroups_MissingSrc + $Stats.Groups_MissingSrc + $Stats.Profiles_MissingSrc + $Stats.Policies_MissingSrc + $Stats.Rules_MissingSrc)
    $totalObjects = $totalMatch + $totalMismatch + $totalMissingDst + $totalMissingSrc
    $overallStatus = if ($totalMismatch -eq 0 -and $totalMissingDst -eq 0) { 'PASSED' } else { 'ISSUES FOUND' }
    $statusColor = if ($overallStatus -eq 'PASSED') { '#16a34a' } else { '#dc2626' }
    $reportDate = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'

    # Build findings table rows
    $tableRows = foreach ($finding in $Findings) {
        $badge = Get-ResultBadge -Result $finding.Result
        $rowClass = switch ($finding.Result) {
            'MATCH' { 'row-match' }
            'MISMATCH' { 'row-mismatch' }
            'MISSING_DST' { 'row-missing-dst' }
            'MISSING_SRC' { 'row-missing-src' }
            'REVIEW' { 'row-review' }
        }
        $detail = [System.Web.HttpUtility]::HtmlEncode($finding.Detail)
        "<tr class='$rowClass'><td>$([System.Web.HttpUtility]::HtmlEncode($finding.ObjectType))</td><td><code>$([System.Web.HttpUtility]::HtmlEncode($finding.ObjectId))</code></td><td>$([System.Web.HttpUtility]::HtmlEncode($finding.DisplayName))</td><td>$badge</td><td class='detail'>$detail</td></tr>"
    }

    # Summary rows
    $summaryData = @(
        @{ Type = 'Services'; Match = $Stats.Services_Match; Mismatch = $Stats.Services_Mismatch; MissingDst = $Stats.Services_MissingDst; MissingSrc = $Stats.Services_MissingSrc }
        @{ Type = 'Security Groups'; Match = $Stats.Groups_Match; Mismatch = $Stats.Groups_Mismatch; MissingDst = $Stats.Groups_MissingDst; MissingSrc = $Stats.Groups_MissingSrc }
        @{ Type = 'Context Profiles'; Match = $Stats.Profiles_Match; Mismatch = $Stats.Profiles_Mismatch; MissingDst = $Stats.Profiles_MissingDst; MissingSrc = $Stats.Profiles_MissingSrc }
        @{ Type = 'DFW Policies'; Match = $Stats.Policies_Match; Mismatch = $Stats.Policies_Mismatch; MissingDst = $Stats.Policies_MissingDst; MissingSrc = $Stats.Policies_MissingSrc }
        @{ Type = 'DFW Rules'; Match = $Stats.Rules_Match; Mismatch = $Stats.Rules_Mismatch; MissingDst = $Stats.Rules_MissingDst; MissingSrc = $Stats.Rules_MissingSrc }
    )
    $summaryRows = foreach ($row in $summaryData) {
        $rowOk = ($row.Mismatch -eq 0 -and $row.MissingDst -eq 0)
        $icon = if ($rowOk) { '✔' } else { '⚠️' }
        $cls = if ($rowOk) { 'sum-ok' } else { 'sum-warn' }
        "<tr class='$cls'><td>$icon $($row.Type)</td><td class='num'>$($row.Match)</td><td class='num warn-cell'>$($row.Mismatch)</td><td class='num err-cell'>$($row.MissingDst)</td><td class='num info-cell'>$($row.MissingSrc)</td></tr>"
    }

    # Review list section - only rendered when at least one group is in the review set
    $reviewListHtml = ''
    if ($GroupReviewSet.Count -gt 0) {
        $reviewListFile = if ($GroupReviewList) { [System.IO.Path]::GetFileName($GroupReviewList) } else { '' }
        $reviewRows = ($GroupReviewSet.Keys | Sort-Object) | ForEach-Object {
            "<tr><td><code>$([System.Web.HttpUtility]::HtmlEncode($_))</code></td></tr>"
        }
        $reviewListHtml = @"

<section>
  <h2>Groups in Review List <span style="font-size:.8rem;font-weight:400;color:var(--gray)">($reviewListFile - $($GroupReviewSet.Count) group(s) downgraded from MISMATCH to REVIEW)</span></h2>
  <table>
    <thead><tr><th>Group ID</th></tr></thead>
    <tbody>$($reviewRows -join "`n")</tbody>
  </table>
</section>
"@
    }

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width,initial-scale=1" />
<title>NSX Migration Validation Report</title>
<style>
  :root{--green:#16a34a;--red:#dc2626;--amber:#d97706;--blue:#2563eb;--gray:#6b7280;--bg:#f9fafb;--card:#fff;--border:#e5e7eb}
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:'Segoe UI',system-ui,sans-serif;background:var(--bg);color:#111;padding:2rem}
  h1{font-size:1.6rem;font-weight:700;margin-bottom:.25rem}
  .subtitle{color:var(--gray);font-size:.9rem;margin-bottom:2rem}
  .header-meta{display:flex;gap:2rem;flex-wrap:wrap;margin-bottom:2rem;padding:1rem 1.25rem;background:var(--card);border:1px solid var(--border);border-radius:.5rem}
  .meta-item label{font-size:.75rem;text-transform:uppercase;letter-spacing:.05em;color:var(--gray);display:block}
  .meta-item span{font-size:.95rem;font-weight:600}
  .overall{display:inline-block;padding:.35rem 1rem;border-radius:9999px;color:#fff;font-weight:700;font-size:1rem;background:$statusColor}
  .kpi-row{display:flex;gap:1rem;flex-wrap:wrap;margin-bottom:2rem}
  .kpi{flex:1 1 140px;background:var(--card);border:1px solid var(--border);border-radius:.5rem;padding:1rem 1.25rem;text-align:center}
  .kpi .num{font-size:2rem;font-weight:800}
  .kpi .lbl{font-size:.8rem;color:var(--gray);margin-top:.25rem}
  .kpi.green .num{color:var(--green)} .kpi.amber .num{color:var(--amber)} .kpi.red .num{color:var(--red)} .kpi.blue .num{color:var(--blue)}
  section{margin-bottom:2.5rem}
  h2{font-size:1.1rem;font-weight:700;margin-bottom:.75rem;border-bottom:2px solid var(--border);padding-bottom:.4rem}
  table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--border);border-radius:.5rem;overflow:hidden;font-size:.875rem}
  th{background:#f3f4f6;text-align:left;padding:.6rem .9rem;font-size:.75rem;text-transform:uppercase;letter-spacing:.04em;color:var(--gray);border-bottom:1px solid var(--border)}
  td{padding:.55rem .9rem;border-bottom:1px solid var(--border);vertical-align:top}
  tr:last-child td{border-bottom:none}
  .num{text-align:center}
  .warn-cell{color:var(--amber);font-weight:600}
  .err-cell{color:var(--red);font-weight:600}
  .info-cell{color:var(--blue)}
  .sum-ok td:first-child{color:var(--green)}
  .sum-warn td:first-child{color:var(--amber);font-weight:600}
  .badge{display:inline-block;padding:.2rem .6rem;border-radius:9999px;font-size:.75rem;font-weight:700;white-space:nowrap}
  .badge.match{background:#dcfce7;color:#166534}
  .badge.mismatch{background:#fef3c7;color:#92400e}
  .badge.missing-dst{background:#fee2e2;color:#991b1b}
  .badge.missing-src{background:#dbeafe;color:#1e40af}
  .row-mismatch td{background:#fffbeb}
  .row-missing-dst td{background:#fff5f5}
  .row-missing-src td{background:#eff6ff}
  .detail{color:#374151;font-size:.8rem;word-break:break-all}
  code{font-family:monospace;font-size:.8rem;background:#f3f4f6;padding:.1rem .3rem;border-radius:.2rem}
  .filter-bar{margin-bottom:.75rem;display:flex;gap:.5rem;flex-wrap:wrap}
  .filter-btn{padding:.35rem .85rem;border:1px solid var(--border);border-radius:9999px;background:var(--card);cursor:pointer;font-size:.8rem;font-weight:500}
  .filter-btn:hover,.filter-btn.active{background:#111;color:#fff;border-color:#111}
  footer{margin-top:3rem;font-size:.75rem;color:var(--gray);text-align:center}
</style>
</head>
<body>
<h1>NSX DFW Migration Validation Report</h1>
<p class="subtitle">Custom object comparison - system-owned objects excluded</p>

<div class="header-meta">
  <div class="meta-item"><label>Report Date</label><span>$reportDate</span></div>
  <div class="meta-item"><label>Source NSX Manager</label><span>$SourceNSX</span></div>
  <div class="meta-item"><label>Destination NSX Manager</label><span>$DestNSX</span></div>
  <div class="meta-item"><label>Domain</label><span>$DomainId</span></div>
  <div class="meta-item"><label>Overall Status</label><span class="overall">$overallStatus</span></div>
</div>

<div class="kpi-row">
  <div class="kpi green"><div class="num">$totalMatch</div><div class="lbl">Matched</div></div>
  <div class="kpi amber"><div class="num">$totalMismatch</div><div class="lbl">Mismatched</div></div>
  <div class="kpi red"><div class="num">$totalMissingDst</div><div class="lbl">Missing on Dst</div></div>
  <div class="kpi blue"><div class="num">$totalMissingSrc</div><div class="lbl">Extra on Dst</div></div>
  <div class="kpi"><div class="num">$totalObjects</div><div class="lbl">Total Compared</div></div>
</div>

<section>
  <h2>Summary by Object Type</h2>
  <table>
    <thead><tr><th>Object Type</th><th class="num">Match</th><th class="num">Mismatch</th><th class="num">Missing on Dst</th><th class="num">Extra on Dst</th></tr></thead>
    <tbody>$($summaryRows -join "`n")</tbody>
    <tfoot><tr style="font-weight:700;background:#f3f4f6"><td>TOTAL</td><td class="num">$totalMatch</td><td class="num warn-cell">$totalMismatch</td><td class="num err-cell">$totalMissingDst</td><td class="num info-cell">$totalMissingSrc</td></tr></tfoot>
  </table>
</section>

$reviewListHtml
<section>
  <h2>Detailed Findings</h2>
  <div class="filter-bar">
    <button class="filter-btn active" onclick="filterTable('ALL',this)">All</button>
    <button class="filter-btn" onclick="filterTable('MATCH',this)">✔ Match</button>
    <button class="filter-btn" onclick="filterTable('MISMATCH',this)">⚠️ Mismatch</button>
    <button class="filter-btn" onclick="filterTable('MISSING_DST',this)">✖ Missing on Dst</button>
    <button class="filter-btn" onclick="filterTable('MISSING_SRC',this)">✖ Extra on Dst</button>
    <button class="filter-btn" onclick="filterTable('REVIEW',this)">~ Review</button>
  </div>
  <table id="findingsTable">
    <thead><tr><th>Type</th><th>ID</th><th>Display Name</th><th>Result</th><th>Detail</th></tr></thead>
    <tbody>$($tableRows -join "`n")</tbody>
  </table>
</section>

<footer>Generated by Compare-NSX-Migration.ps1 v$ScriptVersion &nbsp;|&nbsp; $reportDate</footer>

<script>
function filterTable(filter, btn) {
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  const rows = document.querySelectorAll('#findingsTable tbody tr');
  rows.forEach(row => {
    const badge = row.querySelector('.badge');
    if (!badge) { row.style.display = filter === 'ALL' ? '' : 'none'; return; }
    const cls = badge.className;
    const show =
      (filter === 'ALL') ||
      (filter === 'MATCH'       && cls.includes('match') && !cls.includes('mis')) ||
      (filter === 'MISMATCH'    && cls.includes('mismatch')) ||
      (filter === 'MISSING_DST' && cls.includes('missing-dst')) ||
      (filter === 'MISSING_SRC' && cls.includes('missing-src')) ||
      (filter === 'REVIEW'      && cls.includes('review'));
    row.style.display = show ? '' : 'none';
  });
}
</script>
</body>
</html>
"@

    # Need System.Web for HtmlEncode - use a simple fallback if unavailable
    # (already used above; if the assembly isn't loaded the above will have thrown)
    $htmlPath = Join-Path $OutputFolder "NSX_Migration_Validation_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
    [System.IO.File]::WriteAllText($htmlPath, $html, [System.Text.Encoding]::UTF8)
    Write-Log "  HTML report written to: $htmlPath" SUCCESS
    return $htmlPath
}

# --------------------------------------------------------------
# MAIN
# --------------------------------------------------------------

# Load System.Web for HtmlEncode (used in HTML report)
try { Add-Type -AssemblyName System.Web -ErrorAction SilentlyContinue } catch {}

Write-Log "--------------------------------------------------------------------" INFO
Write-Log " NSX DFW MIGRATION VALIDATION" INFO
Write-Log " Script version  : $ScriptVersion" INFO
Write-Log " Source NSX      : $SourceNSX" INFO
Write-Log " Destination NSX : $DestNSX" INFO
Write-Log " Domain          : $DomainId" INFO
Write-Log " Output folder   : $OutputFolder" INFO
Write-Log " Log file        : $LogFile" INFO
Write-Log " Group mapping   : $(if ($GroupMappingFile)   { $GroupMappingFile   } else { '(none - IDs assumed unchanged)' })" INFO
Write-Log " Service mapping : $(if ($ServiceMappingFile) { $ServiceMappingFile } else { '(none - IDs assumed unchanged)' })" INFO
Write-Log " Review list     : $(if ($GroupReviewList) { "$(Split-Path $GroupReviewList -Leaf) - $($GroupReviewSet.Count) group(s)" } else { '(none)' })" INFO
Write-Log "--------------------------------------------------------------------" INFO
Write-Log " NOTE: System-owned objects are EXCLUDED from all comparisons." INFO
Write-Log "--------------------------------------------------------------------" INFO

try {
    # Connectivity checks
    $srcOk = Test-Connectivity -Manager $SourceNSX -Headers $SrcHeaders -Label 'SOURCE'
    $dstOk = Test-Connectivity -Manager $DestNSX   -Headers $DstHeaders -Label 'DESTINATION'
    if (-not $srcOk -or -not $dstOk) {
        Write-Log "Connectivity check failed. Aborting." ERROR
        exit 1
    }

    if ($CompareIPSets) { Compare-IPSets }
    if ($CompareServices) { Compare-Services }
    if ($CompareGroups) { Compare-Groups }
    if ($CompareProfiles) { Compare-Profiles }
    if ($ComparePolicies) { Compare-Policies }

    Write-Log "" INFO
    Write-Log "--------------------------------------------------------------------" INFO
    Write-Log " GENERATING REPORTS" INFO
    Write-Log "--------------------------------------------------------------------" INFO

    $csvPath = Export-CsvReport
    $htmlPath = Export-HtmlReport -CsvPath $csvPath

}
catch {
    Write-Log "FATAL ERROR: $_" ERROR
    $Stats.Errors++
    exit 1
}
finally {
    # Totals
    $totalMatch = ($Stats.Services_Match + $Stats.Groups_Match + $Stats.Profiles_Match + $Stats.Policies_Match + $Stats.Rules_Match)
    $totalMismatch = ($Stats.Services_Mismatch + $Stats.Groups_Mismatch + $Stats.Profiles_Mismatch + $Stats.Policies_Mismatch + $Stats.Rules_Mismatch)
    $totalMissingDst = ($Stats.Services_MissingDst + $Stats.Groups_MissingDst + $Stats.Profiles_MissingDst + $Stats.Policies_MissingDst + $Stats.Rules_MissingDst)
    $totalMissingSrc = ($Stats.Services_MissingSrc + $Stats.Groups_MissingSrc + $Stats.Profiles_MissingSrc + $Stats.Policies_MissingSrc + $Stats.Rules_MissingSrc)
    $overallStatus = if ($totalMismatch -eq 0 -and $totalMissingDst -eq 0) { if ($Stats.Groups_Review -gt 0) { 'PASSED WITH REVIEWS ✔' } else { 'PASSED ✔' } } else { 'ISSUES FOUND ⚠️ ' }

    Write-Log "" INFO
    Write-Log "--------------------------------------------------------------------" INFO
    Write-Log " VALIDATION SUMMARY" INFO
    Write-Log "---------------------------------------------------------------------" INFO
    Write-Log ("  {0,-20} {1,8} {2,10} {3,12} {4,10} {5,8}" -f 'Object Type', 'Match', 'Mismatch', 'Missing Dst', 'Extra Dst', 'Review') INFO
    Write-Log "  ------------------------------------------------------------------" INFO
    Write-Log ("  {0,-20} {1,8} {2,10} {3,12} {4,10} {5,8}" -f 'Services', $Stats.Services_Match, $Stats.Services_Mismatch, $Stats.Services_MissingDst, $Stats.Services_MissingSrc, 0) INFO
    Write-Log ("  {0,-20} {1,8} {2,10} {3,12} {4,10} {5,8}" -f 'Security Groups', $Stats.Groups_Match, $Stats.Groups_Mismatch, $Stats.Groups_MissingDst, $Stats.Groups_MissingSrc, $Stats.Groups_Review) INFO
    Write-Log ("  {0,-20} {1,8} {2,10} {3,12} {4,10} {5,8}" -f 'Context Profiles', $Stats.Profiles_Match, $Stats.Profiles_Mismatch, $Stats.Profiles_MissingDst, $Stats.Profiles_MissingSrc, 0) INFO
    Write-Log ("  {0,-20} {1,8} {2,10} {3,12} {4,10} {5,8}" -f 'DFW Policies', $Stats.Policies_Match, $Stats.Policies_Mismatch, $Stats.Policies_MissingDst, $Stats.Policies_MissingSrc, 0) INFO
    Write-Log ("  {0,-20} {1,8} {2,10} {3,12} {4,10} {5,8}" -f 'DFW Rules', $Stats.Rules_Match, $Stats.Rules_Mismatch, $Stats.Rules_MissingDst, $Stats.Rules_MissingSrc, 0) INFO
    Write-Log "  ------------------------------------------------------------------" INFO
    Write-Log ("  {0,-20} {1,8} {2,10} {3,12} {4,10} {5,8}" -f 'TOTAL', $totalMatch, $totalMismatch, $totalMissingDst, $totalMissingSrc, $Stats.Groups_Review) INFO
    Write-Log "--------------------------------------------------------------------" INFO
    Write-Log " Overall status : $overallStatus" INFO
    if ($GroupReviewSet.Count -gt 0) {
        Write-Log "---------------------------------------------------------------------" INFO
        Write-Log " GROUPS IN REVIEW LIST ($($GroupReviewSet.Count))" INFO
        Write-Log "---------------------------------------------------------------------" INFO
        foreach ($groupId in ($GroupReviewSet.Keys | Sort-Object)) {
            Write-Log "  ~ $groupId" WARN
        }
    }
    Write-Log "--------------------------------------------------------------------" INFO
}