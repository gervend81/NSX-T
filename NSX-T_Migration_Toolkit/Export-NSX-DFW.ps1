# Version 1.1.0
<#
.SYNOPSIS
    STEP 1 of 2 — Exports NSX 4 Distributed Firewall objects to CSV files.

.DESCRIPTION
    Connects to an NSX 4 Manager and exports the following DFW objects to CSV:
      - IP Sets / Address Groups       → NSX_IPSets.csv
      - Services                       → NSX_Services.csv
      - Service Groups                 → NSX_ServiceGroups.csv
      - Security Groups                → NSX_Groups.csv
      - Context Profiles               → NSX_Profiles.csv
      - DFW Policies                   → NSX_Policies.csv
      - DFW Rules                      → NSX_Rules.csv

    Each CSV row contains key readable columns PLUS a RawJson column with the
    full object payload. The import script reads RawJson to reconstruct objects,
    so do not remove that column. All other columns are for review purposes only.

    After export, review the CSVs, remove any rows you do NOT want to import,
    then run Import-NSX-DFW.ps1 against your NSX 9 Manager.

.PARAMETER NSXManager
    FQDN or IP of the source NSX 4 Manager.

.PARAMETER OutputFolder
    Folder where CSV files will be written. Created if it doesn't exist.
    Default: .\NSX_DFW_Export_<timestamp>

.PARAMETER DomainId
    NSX Policy domain. Default: "default"

.PARAMETER ExportIPSets
    Export IP Sets. Default: $true

.PARAMETER ExportServices
    Export Services and Service Groups. Default: $true

.PARAMETER ExportGroups
    Export Security Groups. Default: $true

.PARAMETER ExportProfiles
    Export custom Context Profiles (NSX_Profiles.csv). Default: $false
    Only custom (non-system-owned) profiles are exported. System profiles
    such as those bundled with NSX (e.g. SSL, HTTP) are present on every
    NSX instance and do not need to be migrated.

.PARAMETER ExportPolicies
    Export DFW Policies and Rules. Default: $true

.PARAMETER ExportTags
    Export VM tags from the fabric inventory. Default: $true

.PARAMETER LogFile
    Path to a log file. Required when -LogTarget is 'File' or 'Both'.

.PARAMETER LogTarget
    Controls where log output is written.
      Screen : colored output to the console only (default)
      File   : write to -LogFile only, no console output
      Both   : colored console output AND written to -LogFile

.EXAMPLE
    .\Export-NSX-DFW.ps1 -NSXManager nsx4.corp.local

.EXAMPLE
    .\Export-NSX-DFW.ps1 -NSXManager nsx4.corp.local -OutputFolder C:\NSX\Export
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$NSXManager,
    [string]$OutputFolder  = ".\NSX_DFW_Export_$(Get-Date -Format 'yyyyMMdd_HHmmss')",
    [string]$DomainId      = 'default',
    [bool]$ExportIPSets    = $false,
    [bool]$ExportServices  = $false,
    [bool]$ExportGroups    = $false,
    [bool]$ExportProfiles  = $false,
    [bool]$ExportPolicies  = $false,
    [bool]$ExportTags      = $false,
    [string]$LogFile   = (Join-Path $OutputFolder "Export-NSX-DFW_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"),
    [ValidateSet('Screen','File','Both')]
    [string]$LogTarget = 'Screen'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ─────────────────────────────────────────────────────────────
# Groups known to be system-managed but not flagged as _system_owned.
# These are provisioned by NSX Threat Intelligence, IDS/IPS, and related services.
# ─────────────────────────────────────────────────────────────
$pseudoSystemGroupIds = @(
    'DefaultMaliciousIpGroup',
    'DefaultUDAGroup'
)

# ─────────────────────────────────────────────────────────────
# Policies known to be system-managed but not flagged as _system_owned.
# NSX will reject DELETE requests for these with a 400/403 error.
# ─────────────────────────────────────────────────────────────
$pseudoSystemPolicyIds = @(
    'default-layer3-section',
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
$Cred    = Get-Credential -Message "NSX 4 ($NSXManager) credentials"
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

# ─────────────────────────────────────────────────────────────
# OBJECT HELPERS
# ─────────────────────────────────────────────────────────────
function Remove-ReadOnlyFields {
    param([object]$Obj)
    $clone = $Obj | ConvertTo-Json -Depth 20 | ConvertFrom-Json
    foreach ($field in @('_create_time','_last_modified_time','_system_owned','_revision',
                         '_create_user','_last_modified_user','_protection')) {
        if ($clone.PSObject.Properties[$field]) {
            $clone.PSObject.Properties.Remove($field)
        }
    }
    return $clone
}

function Get-SafeProp {
    # Safely reads an optional property - returns $null if absent.
    # Prevents Set-StrictMode from throwing on missing properties.
    param([object]$Obj, [string]$Name)
    if ($Obj.PSObject.Properties[$Name]) { return $Obj.$Name }
    return $null
}

function Format-Tags {
    # Returns a semicolon-separated scope:tag string, or empty string if no tags.
    param([object]$Obj)
    $tags = Get-SafeProp $Obj 'tags'
    if ($tags) { return ($tags | ForEach-Object { "$($_.scope):$($_.tag)" }) -join '; ' }
    return ''
}

function Format-PropList {
    # Joins an optional array property as semicolon-separated, or returns $Fallback.
    param([object]$Obj, [string]$Name, [string]$Fallback = '')
    $val = Get-SafeProp $Obj $Name
    if ($val) { return $val -join '; ' }
    return $Fallback
}

# ─────────────────────────────────────────────────────────────
# OUTPUT FOLDER
# ─────────────────────────────────────────────────────────────
if (-not (Test-Path $OutputFolder)) {
    New-Item -ItemType Directory -Path $OutputFolder | Out-Null
    Write-Log "Created output folder: $OutputFolder" INFO
}
$OutputFolder = (Resolve-Path $OutputFolder).Path

# ─────────────────────────────────────────────────────────────
# STATISTICS
# ─────────────────────────────────────────────────────────────
$Stats = @{ IPSets=0; Services=0; ServiceGroups=0; Groups=0; Profiles=0; Policies=0; Rules=0; Tags=0 }

# ═════════════════════════════════════════════════════════════
# 1. EXPORT IP SETS
# ═════════════════════════════════════════════════════════════
function Export-IPSets {
    Write-Log "━━━ Exporting IP Sets ━━━" INFO
    $objects = Get-AllPages -Path "/api/v1/ip-sets"
    if (-not $objects) { Write-Log "No IP Sets found." WARN; return }

    $rows = foreach ($obj in $objects) {
        $clean = Remove-ReadOnlyFields $obj
        [PSCustomObject]@{
            ObjectType  = 'IPSet'
            Id          = $obj.id
            DisplayName = $obj.display_name
            Description = (Get-SafeProp $obj 'description')
            IPAddresses = (Format-PropList $obj 'ip_addresses')
            Tags        = (Format-Tags $obj)
            RawJson     = ($clean | ConvertTo-Json -Depth 20 -Compress)
        }
    }

    $csvPath = Join-Path $OutputFolder 'NSX_IPSets.csv'
    $rows | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
    $Stats.IPSets = @($rows).Count
    Write-Log "  Exported $($Stats.IPSets) IP Sets → $csvPath" SUCCESS
}

# ═════════════════════════════════════════════════════════════
# 2. EXPORT SERVICES & SERVICE GROUPS
# ═════════════════════════════════════════════════════════════
function Export-Services {
    Write-Log "━━━ Exporting Services ━━━" INFO
    $objects = Get-AllPages -Path "/policy/api/v1/infra/services"
    $custom  = $objects | Where-Object { (Get-SafeProp $_ '_system_owned') -ne $true }

    if (-not $custom) { Write-Log "No custom Services found." WARN }
    else {
        $rows = foreach ($svc in $custom) {
            $clean   = Remove-ReadOnlyFields $svc
            $entries = Get-SafeProp $svc 'service_entries'
            $entrySummary = ''
            if ($entries) {
                $entrySummary = ($entries | ForEach-Object {
                    $type = $_.resource_type
                    switch -Wildcard ($type) {
                        '*L4Port*'     { "$(Get-SafeProp $_ 'l4_protocol'):$(((Get-SafeProp $_ 'destination_ports') -join ','))" }
                        '*ICMPType*'   { "ICMP:$(Get-SafeProp $_ 'icmp_type')" }
                        '*IPProtocol*' { "IPProto:$(Get-SafeProp $_ 'protocol_number')" }
                        default        { $type }
                    }
                }) -join '; '
            }
            [PSCustomObject]@{
                ObjectType     = 'Service'
                Id             = $svc.id
                DisplayName    = $svc.display_name
                Description    = (Get-SafeProp $svc 'description')
                ServiceEntries = $entrySummary
                Tags           = (Format-Tags $svc)
                RawJson        = ($clean | ConvertTo-Json -Depth 20 -Compress)
            }
        }
        $csvPath = Join-Path $OutputFolder 'NSX_Services.csv'
        $rows | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
        $Stats.Services = @($rows).Count
        Write-Log "  Exported $($Stats.Services) Services → $csvPath" SUCCESS
    }

    Write-Log "━━━ Exporting Service Groups ━━━" INFO

    # Service groups share the /infra/services endpoint - filter by resource_type
    $sgObjects = Get-AllPages -Path "/policy/api/v1/infra/services"
    $customSGs = $sgObjects | Where-Object {
        (Get-SafeProp $_ 'resource_type') -eq 'PolicyServiceGroup' -and
        (Get-SafeProp $_ '_system_owned') -ne $true
    }

    if (-not $customSGs) { Write-Log "No custom Service Groups found." WARN; return }

    $rows = foreach ($sg in $customSGs) {
        $clean   = Remove-ReadOnlyFields $sg
        $members = Get-SafeProp $sg 'members'
        [PSCustomObject]@{
            ObjectType  = 'ServiceGroup'
            Id          = $sg.id
            DisplayName = $sg.display_name
            Description = (Get-SafeProp $sg 'description')
            Members     = if ($members) { ($members | ForEach-Object { $_.path }) -join '; ' } else { '' }
            Tags        = (Format-Tags $sg)
            RawJson     = ($clean | ConvertTo-Json -Depth 20 -Compress)
        }
    }
    $csvPath = Join-Path $OutputFolder 'NSX_ServiceGroups.csv'
    $rows | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
    $Stats.ServiceGroups = @($rows).Count
    Write-Log "  Exported $($Stats.ServiceGroups) Service Groups → $csvPath" SUCCESS
}

# ═════════════════════════════════════════════════════════════
# 3. EXPORT SECURITY GROUPS
# ═════════════════════════════════════════════════════════════
function Export-Groups {
    Write-Log "━━━ Exporting Security Groups ━━━" INFO
    $objects = Get-AllPages -Path "/policy/api/v1/infra/domains/$DomainId/groups"
    $custom = $objects | Where-Object {
      (Get-SafeProp $_ '_system_owned') -ne $true -and
      (Get-SafeProp $_ '_create_user')  -ne 'system' -and
      $_.id -notin $pseudoSystemGroupIds
    }

    if (-not $custom) { Write-Log "No custom Security Groups found." WARN; return }

    $rows = foreach ($grp in $custom) {
        $clean      = Remove-ReadOnlyFields $grp
        $expression = Get-SafeProp $grp 'expression'
        $exprSummary = if ($expression) {
            ($expression | ForEach-Object { $_.resource_type }) -join '; '
        } else { 'Static' }

        [PSCustomObject]@{
            ObjectType      = 'Group'
            Id              = $grp.id
            DisplayName     = $grp.display_name
            Description     = (Get-SafeProp $grp 'description')
            ExpressionTypes = $exprSummary
            Tags            = (Format-Tags $grp)
            RawJson         = ($clean | ConvertTo-Json -Depth 20 -Compress)
        }
    }

    $csvPath = Join-Path $OutputFolder 'NSX_Groups.csv'
    $rows | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
    $Stats.Groups = @($rows).Count
    Write-Log "  Exported $($Stats.Groups) Security Groups → $csvPath" SUCCESS
}

# ═════════════════════════════════════════════════════════════
# 4. EXPORT CONTEXT PROFILES
# ═════════════════════════════════════════════════════════════
function Export-Profiles {
    Write-Log "━━━ Exporting Context Profiles ━━━" INFO
    $objects = Get-AllPages -Path "/policy/api/v1/infra/context-profiles"
    $custom  = $objects | Where-Object { (Get-SafeProp $_ '_system_owned') -ne $true }

    if (-not $custom) { Write-Log "No custom Context Profiles found." WARN; return }

    $rows = foreach ($prof in $custom) {
        $clean      = Remove-ReadOnlyFields $prof
        $attributes = Get-SafeProp $prof 'attributes'
        $attrSummary = if ($attributes) {
            ($attributes | ForEach-Object {
                $key   = Get-SafeProp $_ 'key'
                $vals  = Get-SafeProp $_ 'value'
                $vStr  = if ($vals) { $vals -join ',' } else { '' }
                "$key=$vStr"
            }) -join '; '
        } else { '' }

        [PSCustomObject]@{
            ObjectType   = 'ContextProfile'
            Id           = $prof.id
            DisplayName  = $prof.display_name
            Description  = (Get-SafeProp $prof 'description')
            Attributes   = $attrSummary
            Tags         = (Format-Tags $prof)
            RawJson      = ($clean | ConvertTo-Json -Depth 20 -Compress)
        }
    }

    $csvPath = Join-Path $OutputFolder 'NSX_Profiles.csv'
    $rows | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
    $Stats.Profiles = @($rows).Count
    Write-Log "  Exported $($Stats.Profiles) Context Profiles → $csvPath" SUCCESS
}

# ═════════════════════════════════════════════════════════════
# 5. EXPORT DFW POLICIES & RULES
# ═════════════════════════════════════════════════════════════
function Export-Policies {
    Write-Log "━━━ Exporting DFW Policies ━━━" INFO
    $policies = Get-AllPages -Path "/policy/api/v1/infra/domains/$DomainId/security-policies"
    $custom   = $policies | Where-Object { 
      (Get-SafeProp $_ '_system_owned') -ne $true -and 
      $_.Id -notin $pseudoSystemPolicyIds 
    } | Sort-Object -Property sequence_number

    if (-not $custom) { Write-Log "No custom DFW Policies found." WARN; return }

    $policyRows = @()
    $ruleRows   = @()

    foreach ($pol in $custom) {
        $cleanPol = Remove-ReadOnlyFields $pol
        $scope    = Get-SafeProp $pol 'scope'

        $policyRows += [PSCustomObject]@{
            ObjectType     = 'Policy'
            Id             = $pol.id
            DisplayName    = $pol.display_name
            Description    = (Get-SafeProp $pol 'description')
            SequenceNumber = $pol.sequence_number
            Category       = (Get-SafeProp $pol 'category')
            Stateful       = (Get-SafeProp $pol 'stateful')
            TCPStrict      = (Get-SafeProp $pol 'tcp_strict')
            Scope          = if ($scope) { $scope -join '; ' } else { 'ANY' }
            Tags           = (Format-Tags $pol)
            RawJson        = ($cleanPol | ConvertTo-Json -Depth 20 -Compress)
        }
        $Stats.Policies++

        $rules = Get-AllPages -Path "/policy/api/v1/infra/domains/$DomainId/security-policies/$($pol.id)/rules"
        if ($rules) {
            $rules = $rules | Sort-Object -Property sequence_number
            foreach ($rule in $rules) {
                $cleanRule = Remove-ReadOnlyFields $rule
                $ruleRows += [PSCustomObject]@{
                    ObjectType     = 'Rule'
                    PolicyId       = $pol.id
                    PolicyName     = $pol.display_name
                    Id             = $rule.id
                    DisplayName    = $rule.display_name
                    Description    = (Get-SafeProp $rule 'description')
                    SequenceNumber = $rule.sequence_number
                    Action         = $rule.action
                    Direction      = (Get-SafeProp $rule 'direction')
                    IPProtocol     = (Get-SafeProp $rule 'ip_protocol')
                    Disabled       = (Get-SafeProp $rule 'disabled')
                    Logged         = (Get-SafeProp $rule 'logged')
                    SourceGroups   = (Format-PropList $rule 'source_groups'      'ANY')
                    DestGroups     = (Format-PropList $rule 'destination_groups' 'ANY')
                    Services       = (Format-PropList $rule 'services'           'ANY')
                    AppliedTo      = (Format-PropList $rule 'scope'              'ANY')
                    Tags           = (Format-Tags $rule)
                    RawJson        = ($cleanRule | ConvertTo-Json -Depth 20 -Compress)
                }
                $Stats.Rules++
            }
        }
    }

    $polCsv  = Join-Path $OutputFolder 'NSX_Policies.csv'
    $ruleCsv = Join-Path $OutputFolder 'NSX_Rules.csv'
    $policyRows | Export-Csv -Path $polCsv  -NoTypeInformation -Encoding UTF8
    $ruleRows   | Export-Csv -Path $ruleCsv -NoTypeInformation -Encoding UTF8
    Write-Log "  Exported $($Stats.Policies) Policies → $polCsv" SUCCESS
    Write-Log "  Exported $($Stats.Rules) Rules → $ruleCsv" SUCCESS
}


# ═════════════════════════════════════════════════════════════
# 6. EXPORT VM TAGS
# ═════════════════════════════════════════════════════════════
function Export-Tags {
    Write-Log "━━━ Exporting VM Tags ━━━" INFO
    # Retrieve all VMs from the fabric inventory including their tags
    $vms = Get-AllPages -Path "/api/v1/fabric/virtual-machines?included_fields=display_name,external_id,tags"

    if (-not $vms) { Write-Log "No VMs found in fabric inventory." WARN; return }

    # Only export VMs that actually have tags assigned
    $taggedVMs = $vms | Where-Object { Get-SafeProp $_ 'tags' }

    if (-not $taggedVMs) { Write-Log "No VMs with tags found." WARN; return }

    $rows = foreach ($vm in $taggedVMs) {
        $tags = Get-SafeProp $vm 'tags'
        foreach ($tag in $tags) {
            [PSCustomObject]@{
                VMDisplayName = $vm.display_name
                ExternalId    = $vm.external_id   # vCenter UUID — required for import
                TagScope      = (Get-SafeProp $tag 'scope')
                TagValue      = (Get-SafeProp $tag 'tag')
            }
        }
        $Stats.Tags++
    }

    $csvPath = Join-Path $OutputFolder 'NSX_VMTags.csv'
    $rows | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
    Write-Log "  Exported tags for $($Stats.Tags) VMs → $csvPath" SUCCESS
    Write-Log "  NOTE: Tags are applied per VM using the ExternalId (vCenter UUID)." WARN
    Write-Log "        VMs must exist in the destination NSX/vCenter inventory before importing." WARN
}

# ═════════════════════════════════════════════════════════════
# MAIN
# ═════════════════════════════════════════════════════════════
Write-Log "════════════════════════════════════════════" INFO
Write-Log " NSX DFW EXPORT" INFO
Write-Log " Source  : $NSXManager" INFO
Write-Log " Output  : $OutputFolder" INFO
Write-Log " Domain  : $DomainId" INFO
Write-Log "════════════════════════════════════════════" INFO

try {
    Write-Log "Verifying connectivity to $NSXManager..." INFO
    $info = Invoke-NSXGet -Path "/api/v1/node"
    if ($info) { Write-Log "  Connected: NSX $($info.product_version)" SUCCESS }
    else        { throw "Cannot connect to NSX Manager $NSXManager." }

    if ($ExportIPSets)   { Export-IPSets   }
    if ($ExportServices) { Export-Services }
    if ($ExportGroups)   { Export-Groups   }
    if ($ExportProfiles) { Export-Profiles }
    if ($ExportPolicies) { Export-Policies }
    if ($ExportTags)     { Export-Tags     }

} catch {
    Write-Log "FATAL: $_" ERROR
    exit 1
} finally {
    Write-Log "════════════════════════════════════════════" INFO
    Write-Log " EXPORT SUMMARY" INFO
    Write-Log "────────────────────────────────────────────" INFO
    Write-Log "  IP Sets       : $($Stats.IPSets)"        INFO
    Write-Log "  Services      : $($Stats.Services)"      INFO
    Write-Log "  Svc Groups    : $($Stats.ServiceGroups)" INFO
    Write-Log "  Groups        : $($Stats.Groups)"        INFO
    Write-Log "  Profiles      : $($Stats.Profiles)"      INFO
    Write-Log "  Policies      : $($Stats.Policies)"      INFO
    Write-Log "  Rules         : $($Stats.Rules)"         INFO
    Write-Log "  VMs with Tags : $($Stats.Tags)"          INFO
    Write-Log "────────────────────────────────────────────" INFO
    Write-Log "  Output folder : $OutputFolder" INFO
    Write-Log "════════════════════════════════════════════" INFO
    Write-Log "Review the CSV files, remove any rows you do NOT want to import," INFO
    Write-Log "then run: .\Import-NSX-DFW.ps1 -NSXManager <nsx9> -InputFolder '$OutputFolder'" INFO


}