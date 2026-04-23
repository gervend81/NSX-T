# Version 1.0.0
<#
.SYNOPSIS
    Exports MIG-IP_ Security Groups and removes MIG-IP_ path references from
    groups that reference them, preparing both for clean re-import.

.DESCRIPTION
    This script targets two categories of NSX Security Groups and processes them
    in two stages:

    Condition A — Groups whose display_name starts with "MIG-IP_":
        Exported as-is. These are the standalone IP-address groups created during
        the VM-to-IP migration preparation.

    Condition B — Groups that reference a MIG-IP_ group via a PathExpression:
        Exported and then transformed. The MIG-IP_ path (and its adjacent
        ConjunctionOperator) is stripped from the expression array, producing
        a clean UpdatedRawJson ready for re-import without the MIG-IP_ dependency.

    The workflow executes the following stages:

    1. DISCOVERY: Fetches all groups from the NSX Manager and filters for
       Condition A and Condition B groups.
       (Output: NSX_MIGIP_Groups.csv)

    2. TRANSFORMATION: For each Condition B group, removes MIG-IP_ paths from
       PathExpressions and cleans up orphaned ConjunctionOperators. Condition A
       groups are passed through unchanged with an empty UpdatedRawJson.
       (Output: NSX_MIGIP_Groups_Final.csv)

    The resulting NSX_MIGIP_Groups_Final.csv contains the UpdatedRawJson column
    required for the import script. Both CSVs are retained for auditing purposes.

.PARAMETER NSXManager
    FQDN or IP address of the source NSX Manager.

.PARAMETER OutputFolder
    Folder where CSV files and logs will be written. Created if it does not exist.
    Default: .\NSX_MIG_Prep_<timestamp>

.PARAMETER DomainId
    NSX Policy domain identifier. Default: "default"

.PARAMETER ExportMIGIPGroups
    Set to $true to trigger the discovery and transformation workflow.
    Default: $false

.PARAMETER LogFile
    Path to the log file. Auto-generated inside OutputFolder if not specified.

.PARAMETER LogTarget
    Controls where log output is written:
      Screen : Colored output to the console only.
      File   : Writes to -LogFile only, no console output.
      Both   : Colored console output and appends to -LogFile (default).

.EXAMPLE
    .\Export-NSX-MIGIPGroups.ps1 -NSXManager nsx01.corp.local -ExportMIGIPGroups $true
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$NSXManager,
    [string]$OutputFolder  = ".\NSX_MIG_Prep_$(Get-Date -Format 'yyyyMMdd_HHmmss')",
    [string]$DomainId      = 'default',
    [bool]$ExportMIGIPGroups  = $false,
    [string]$LogFile   = (Join-Path $OutputFolder "Export-NSX-MIGIPGroups_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"),
    [ValidateSet('Screen','File','Both')]
    [string]$LogTarget = 'Both'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ─────────────────────────────────────────────────────────────
# Groups known to be system-managed but not flagged as _system_owned.
# These are provisioned by NSX Threat Intelligence, IDS/IPS, and related services.
# ─────────────────────────────────────────────────────────────
$pseudoSystemIds = @(
    'DefaultMaliciousIpGroup',
    'DefaultUDAGroup'
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
# OUTPUT FOLDER
# ─────────────────────────────────────────────────────────────
if (-not (Test-Path $OutputFolder)) {
    New-Item -ItemType Directory -Path $OutputFolder | Out-Null
    Write-Log "Created output folder: $OutputFolder" INFO
}
$OutputFolder = (Resolve-Path $OutputFolder).Path

# ─────────────────────────────────────────────────────────────
# IGNORE SELF-SIGNED CERTIFICATES
# ─────────────────────────────────────────────────────────────
# Uncomment the block below if your NSX Manager uses a self-signed or
# internally-signed certificate that is not trusted by this machine.
#
# IMPORTANT: This uses the legacy ICertificatePolicy API which is supported
# on Windows PowerShell 5.1 only. It will not work on PowerShell 7+.
#
# For PowerShell 7+, add -SkipCertificateCheck to each Invoke-RestMethod
# call in the Invoke-NSXGet function instead:
#
#   Invoke-RestMethod -Uri $uri -Method GET -Headers $Headers -SkipCertificateCheck
#
# WARNING: Disabling certificate validation removes a layer of security.
# Only use this in trusted lab or migration environments, never in production.
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
        $url = if ($cursor) {
			$sep = if ($Path -match '\?') { '&' } else { '?' }
			"${Path}${sep}cursor=$cursor"
		} else { $Path }
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
    
    # Handle Arrays: recurse into each element
    if ($Obj -is [System.Collections.IEnumerable] -and $Obj -isnot [string]) {
        foreach ($item in $Obj) {
            Remove-ReadOnlyFields -Obj $item
        }
    }
    # Handle Objects: remove keys and recurse into properties
    elseif ($Obj -is [PSCustomObject]) {
        $fieldsToRemove = @('_create_time','_last_modified_time','_system_owned','_revision',
                            '_create_user','_last_modified_user','_protection','marked_for_delete','overridden','reference','path','parent_path','relative_path','remote_path','owner_id','realization_id','unique_id')
        
        foreach ($field in $fieldsToRemove) {
            if ($Obj.PSObject.Properties[$field]) {
                $Obj.PSObject.Properties.Remove($field)
            }
        }

        # Recurse into remaining properties (like 'expression' or 'expressions')
        foreach ($prop in $Obj.PSObject.Properties) {
            Remove-ReadOnlyFields -Obj $prop.Value
        }
    }
    # We return the object, but since it's a reference type, 
    # the changes affect the original object passed in.
    return $Obj
}

function Get-SafeProp {
    param($Obj, [string]$Name)
    
    if ($null -eq $Obj) { return $null }

    # Using the PSObject.Properties collection is often safer and 
    # faster than try/catch when checking for existence in Strict Mode.
    if ($Obj.PSObject.Properties[$Name]) {
        return $Obj.$Name
    }

    return $null
}

# ─────────────────────────────────────────────────────────────
# STATISTICS
# ─────────────────────────────────────────────────────────────
$Stats = @{ MIGIP_Groups=0; MIGIP_Groups_Transformed=0  }

# ═════════════════════════════════════════════════════════════
# 1. EXPORT MIG-IP_ VM SECURITY GROUPS
# ═════════════════════════════════════════════════════════════
function Export-MIGIPGroups {
    Write-Log "━━━ Exporting MIG-IP Groups and Groups Referencing Them ━━━" INFO
    
    # 1. Fetch all groups from the NSX Manager
    $objects = Get-AllPages -Path "/policy/api/v1/infra/domains/$DomainId/groups"
    
    # 2. Filter: groups with display_name starting with "MIG-IP_"
    #           OR groups with a PathExpression containing a path to a "MIG-IP_" group
    $custom = $objects | Where-Object {
        $grp = $_
        
        # System/Internal Filters (using Get-SafeProp for safety)
        if ((Get-SafeProp $grp '_system_owned') -eq $true -or 
            (Get-SafeProp $grp '_create_user')  -eq 'system' -or 
            (Get-SafeProp $grp 'id') -in $pseudoSystemIds) { return $false }

        $displayName = Get-SafeProp $grp 'display_name'
        $expression  = Get-SafeProp $grp 'expression'

        # Condition A: display_name starts with "MIG-IP_"
        $isMigIpGroup = $displayName -like 'MIG-IP_*'

        # Condition B: has a PathExpression whose paths contain a MIG-IP_ group path
        $hasMigIpPath = $false
        if ($expression) {
            $pathExpressions = @($expression | Where-Object {
                (Get-SafeProp $_ 'resource_type') -eq 'PathExpression'
            })
            foreach ($pe in $pathExpressions) {
                $paths = Get-SafeProp $pe 'paths'
                if ($paths) {
                    $match = @($paths | Where-Object { $_ -match '/groups/MIG-IP_' })
                    if ($match.Count -gt 0) {
                        $hasMigIpPath = $true
                        break
                    }
                }
            }
        }

        return ($isMigIpGroup -or $hasMigIpPath)
    }

    if (-not $custom) { Write-Log "No MIG-IP groups or referencing groups found." WARN; return }

    # 3. Process the filtered groups into CSV rows
    $rows = foreach ($grp in $custom) {
        $null = Remove-ReadOnlyFields -Obj $grp
        $expression = Get-SafeProp $grp 'expression'

        $exprSummary = if ($expression) {
            (@($expression | ForEach-Object { Get-SafeProp $_ 'resource_type' }) | Where-Object { $_ }) -join '; '
        } else {
            'Static'
        }

        $nestedSummary = if ($expression) {
			(@($expression |
				ForEach-Object { Get-SafeProp $_ 'expressions' } |
				Where-Object   { $_ } |                             # filter nulls before flattening
				ForEach-Object { Get-SafeProp $_ 'resource_type' } |
				Where-Object   { $_ }
			)) -join '; '
		} else {
			'N/A'
		}

        # Collect all MIG-IP_ paths referenced in PathExpressions
        $referencedMigPath = if ($expression) {
            @($expression | Where-Object {
                (Get-SafeProp $_ 'resource_type') -eq 'PathExpression'
            } | ForEach-Object {
                $paths = Get-SafeProp $_ 'paths'
                if ($paths) { $paths | Where-Object { $_ -match '/groups/MIG-IP_' } }
            }) -join '; '
        } else { '' }

        [PSCustomObject]@{
            ObjectType          = 'Group'
            Id                  = (Get-SafeProp $grp 'id')
            DisplayName         = (Get-SafeProp $grp 'display_name')
            ExpressionTypes     = $exprSummary
            NestedTypes         = if ($nestedSummary) { $nestedSummary } else { 'None' }
            ReferencedMigPath  = if ($referencedMigPath) { $referencedMigPath } else { '' }
            RawJson             = ($grp | ConvertTo-Json -Depth 20 -Compress)
        }
    }

    # 4. Export to CSV
    $csvPath = Join-Path $OutputFolder 'NSX_MIGIP_Groups.csv'
    $rows | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
    
    # 5. Update Global Stats and Log Success
    $Stats.MIGIP_Groups = @($rows).Count
    Write-Log "  Exported $($Stats.MIGIP_Groups) MIGIP Security Groups → $csvPath" SUCCESS
}

function Remove-MigIpPaths {
    param(
        [Parameter(Mandatory)]
        [string]$InputCsvPath,
        [Parameter(Mandatory)]
        [string]$OutputCsvPath
    )

    Write-Log "━━━ Transforming MIG-IP Paths in Condition B Groups ━━━" INFO

    # 1. Read the CSV produced by Export-MIGIPGroups
    if (-not (Test-Path $InputCsvPath)) {
        Write-Log "Input CSV not found: $InputCsvPath" ERROR
        return 0
    }
    $rows = Import-Csv -Path $InputCsvPath -Encoding UTF8

    # 2. Transform each row
    $transformed = @(foreach ($row in $rows) {

        # Skip transformation if no MIG-IP_ paths are referenced (Condition A groups
        # and any row where ReferencedMigPaths is empty, null, or 'N/A')
        $hasRef = $row.ReferencedMigPath -and
                  $row.ReferencedMigPath -ne ''

        if (-not $hasRef) {
            $row | Select-Object *, @{ Name = 'UpdatedRawJson'; Expression = { '' } }
            continue
        }

        # Parse RawJson
        $grp             = $row.RawJson | ConvertFrom-Json
        $expressionArray = @($grp.expression)
        $newExpression   = [System.Collections.Generic.List[object]]::new()

        for ($i = 0; $i -lt $expressionArray.Count; $i++) {
            $item = $expressionArray[$i]

            if ($item.resource_type -ne 'PathExpression') {
                $newExpression.Add($item)
                continue
            }

            $migPaths    = @($item.paths | Where-Object { $_ -match '/groups/MIG-IP_' })
            $nonMigPaths = @($item.paths | Where-Object { $_ -notmatch '/groups/MIG-IP_' })

            if ($nonMigPaths.Count -gt 0) {
				# PathExpression kept — strip only MIG-IP_ paths, leave conjunction untouched
				$item.paths = $nonMigPaths
				$newExpression.Add($item)
			} else {
				# PathExpression dropped — remove adjacent ConjunctionOperator
				# Check trailing first (most common: OR was appended before PathExpression)
				$lastIndex = $newExpression.Count - 1
				if ($lastIndex -ge 0 -and $newExpression[$lastIndex].resource_type -eq 'ConjunctionOperator') {
					$newExpression.RemoveAt($lastIndex)
				}
				# Check leading (PathExpression was first, ConjunctionOperator follows it in the original)
				elseif ($i + 1 -lt $expressionArray.Count -and $expressionArray[$i + 1].resource_type -eq 'ConjunctionOperator') {
					$i++  # skip the following ConjunctionOperator in the loop
				}
				# PathExpression is simply not added
			}
        }

        $grp.expression = $newExpression.ToArray()
        $updatedRawJson = $grp | ConvertTo-Json -Depth 20 -Compress

        $row | Select-Object *, @{ Name = 'UpdatedRawJson'; Expression = { $updatedRawJson } }
    })

    # 3. Export to new CSV
    $transformed | Export-Csv -Path $OutputCsvPath -NoTypeInformation -Encoding UTF8

    $condBCount = @($transformed | Where-Object { $_.UpdatedRawJson -ne '' }).Count
    Write-Log "  Transformed $condBCount Condition B group(s) → $OutputCsvPath" SUCCESS
	return $condBCount
}

# ═════════════════════════════════════════════════════════════
# MAIN
# ═════════════════════════════════════════════════════════════
Write-Log "════════════════════════════════════════════" INFO
Write-Log " NSX VM-TO-IP GROUP EXPORT" INFO
Write-Log " Source  : $NSXManager" INFO
Write-Log " Output  : $OutputFolder" INFO
Write-Log " Domain  : $DomainId" INFO
Write-Log "════════════════════════════════════════════" INFO

try {
    Write-Log "Verifying connectivity to $NSXManager..." INFO
    $info = Invoke-NSXGet -Path "/api/v1/node"
    if ($info) { Write-Log "  Connected: NSX $($info.product_version)" SUCCESS }
    else        { throw "Cannot connect to NSX Manager $NSXManager." }

    if ($ExportMIGIPGroups) { 
    # 1. Discover Groups (Creates NSX_MIGIP_Groups.csv)
    Export-MIGIPGroups

    $groupCsv = Join-Path $OutputFolder 'NSX_MIGIP_Groups.csv'
	
	# 2. Transform Condition B groups → NSX_MIGIP_Groups_Final.csv
    $transformedCsv = Join-Path $OutputFolder 'NSX_MIGIP_Groups_Final.csv'
    
    $Stats.MIGIP_Groups_Transformed = Remove-MigIpPaths -InputCsvPath $groupCsv -OutputCsvPath $transformedCsv
    		
    } else {
        Write-Log "Skipping processing: ExportMIGIPGroups flag not set." WARN
    }
}

 catch {
    Write-Log "FATAL: $_" ERROR
    exit 1
} finally {
    Write-Log "════════════════════════════════════════════" INFO
    Write-Log " EXPORT SUMMARY" INFO
    Write-Log "────────────────────────────────────────────" INFO
    Write-Log "  MIGIPGroups             : $($Stats.MIGIP_Groups)"        INFO
	Write-Log "  MIGIPGroups Transformed : $($Stats.MIGIP_Groups_Transformed)" INFO
    Write-Log "────────────────────────────────────────────" INFO
    Write-Log "  Output folder : $OutputFolder" INFO
    Write-Log "════════════════════════════════════════════" INFO
    Write-Log "Review the CSV files, remove any rows you do NOT want to import," INFO
    Write-Log "then run: .\Delete-NSX-MIG-IP_-Groups.ps1 -NSXManager <nsx9> -InputFolder '$OutputFolder' [-Action]" INFO


}