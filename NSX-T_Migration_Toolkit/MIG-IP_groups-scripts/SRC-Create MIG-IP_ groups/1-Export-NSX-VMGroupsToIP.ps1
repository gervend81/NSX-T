# Version 1.0.0
<#
.SYNOPSIS
    STEP 1 of 2 — Exports and transforms NSX Security Groups for IP-based migration.

.DESCRIPTION
    This script identifies VM-based Security Groups in a source NSX Manager and performs 
    a multi-stage transformation to prepare them for migration to a new environment.
    
    The workflow executes the following stages:
    
    1. DISCOVERY: Identifies custom Security Groups containing "VirtualMachine" members.
       (Output: NSX_VM_Groups.csv)
       
    2. RESOLUTION: Fetches the effective IPv4 addresses for these groups, filtering 
       out CIDRs, Ranges, and IPv6 addresses.
       (Output: NSX_Group_IPv4_Raw.csv)
       
    3. TRANSFORMATION: Generates a new "MIG-IP_" naming convention and creates a 
       standalone "IPAddressExpression" JSON payload for each group.
       (Output: NSX_Groups_Transformed.csv)
       
    4. PATCHING: Merges the original group logic with the new IP-based logic. 
       It appends an 'OR' ConjunctionOperator and a PathExpression to the original 
       group's RawJson so that the final group members include BOTH the original 
       VM-based criteria AND the specific IPv4 addresses found during discovery.
       (Output: NSX_VM_Groups-Final.csv)

    The resulting 'NSX_VM_Groups-Final.csv' contains the 'UpdatedRawJson' column 
    required for the migration import script. All intermediate CSVs are retained 
    for auditing purposes.

.PARAMETER NSXManager
    FQDN or IP of the source NSX Manager.

.PARAMETER OutputFolder
    Folder where CSV files and logs will be written. Created if it doesn't exist.
    Default: .\NSX_MIG_Prep_<timestamp>

.PARAMETER DomainId
    NSX Policy domain. Default: "default"

.PARAMETER ExportVMGroups
    Enables the discovery, IP extraction, and JSON patching workflow for 
    VM-based Security Groups. Must be $true to trigger the transformation.
    Default: $false

.PARAMETER LogFile
    Path to the log file. Automatically generated within the OutputFolder if not specified.

.PARAMETER LogTarget
    Controls log output destination:
      Screen : Colored output to console only.
      File   : Write to -LogFile only.
      Both   : Console and -LogFile (default).

.EXAMPLE
    .\Export-NSX-VMGroupsToIP.ps1 -NSXManager nsx01.corp.local -ExportVMGroups $true
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$NSXManager,
    [string]$OutputFolder  = ".\NSX_MIG_Prep_$(Get-Date -Format 'yyyyMMdd_HHmmss')",
    [string]$DomainId      = 'default',
    [bool]$ExportVMGroups  = $false,
    [string]$LogFile   = (Join-Path $OutputFolder "Export-NSX-VMGroupsToIP_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"),
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
Write-Log "Enter credentials for Source NSX Manager: $NSXManager"
$Cred    = Get-Credential -Message "Source NSX ($NSXManager) credentials"
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
# STATISTICS
# ─────────────────────────────────────────────────────────────
$Stats = @{ VMGroups=0 }

# ═════════════════════════════════════════════════════════════
#  RESOLVE ExternalIDExpression VM Display Names
# ═════════════════════════════════════════════════════════════
function Resolve-ExternalIdVMNames {
    <#
    .SYNOPSIS
        For any group containing an ExternalIDExpression, resolves each external_id
        to a VM display_name by fetching the group's virtual-machine members.
    .OUTPUTS
        Returns a [hashtable] keyed by ExternalId → display_name.
        Returns an empty hashtable if the group has no ExternalIDExpression or no members.
    #>
    param(
        [Parameter(Mandatory)][string]$GroupId,
        [Parameter(Mandatory)][object]$GroupExpression   # The parsed 'expression' array
    )

    $result = @{}   # ExternalId → display_name

    # 1. Collect all external_ids declared across all ExternalIDExpression blocks
    $externalIds = @(
        $GroupExpression |
            Where-Object { (Get-SafeProp $_ 'resource_type') -eq 'ExternalIDExpression' } |
            ForEach-Object { Get-SafeProp $_ 'external_ids' } |
            Where-Object { $_ } |
			ForEach-Object { $_ }   # flattens nested arrays
    )

    if ($externalIds.Count -eq 0) {
        return $result   # Nothing to resolve
    }

    Write-Log "  Resolving $($externalIds.Count) ExternalID(s) for group: $GroupId" INFO

    # 2. Fetch the realised virtual-machine members for this group
    $vmMembers = Get-AllPages -Path "/policy/api/v1/infra/domains/$DomainId/groups/$GroupId/members/virtual-machines"

    if (-not $vmMembers) {
        Write-Log "  No VM members returned for group: $GroupId" WARN
        return $result
    }

    # 3. Build a lookup: VM id → display_name
    #    The API returns RealizedVirtualMachine objects whose 'id' equals the instanceUuid / externalId
    $vmLookup = @{}
    foreach ($vm in $vmMembers) {
        $vmId   = Get-SafeProp $vm 'id'
        $vmName = Get-SafeProp $vm 'display_name'
        if ($vmId -and $vmName) {
            $vmLookup[$vmId] = $vmName
        }
    }

    # 4. Match each declared external_id against the lookup
    foreach ($extId in $externalIds) {
        if ($vmLookup.ContainsKey($extId)) {
            $result[$extId] = $vmLookup[$extId]
            Write-Log "    Resolved: $extId → $($vmLookup[$extId])" SUCCESS
        } else {
            # VM may be powered off / not realised — record it explicitly
            $result[$extId] = 'UNRESOLVED'
            Write-Log "    Could not resolve ExternalId: $extId" WARN
        }
    }

    return $result
}

# ═════════════════════════════════════════════════════════════
# 1. EXPORT VM SECURITY GROUPS
# ═════════════════════════════════════════════════════════════
function Export-VMGroups {
    Write-Log "━━━ Exporting VM-Based Security Groups ━━━" INFO
    
    # 1. Fetch all groups from the NSX Manager
    $objects = Get-AllPages -Path "/policy/api/v1/infra/domains/$DomainId/groups"
    
    # 2. Filter: Only custom groups containing VirtualMachine members
    $custom = $objects | Where-Object {
        $grp = $_
        
        # System/Internal Filters (using Get-SafeProp for safety)
        if ((Get-SafeProp $grp '_system_owned') -eq $true -or 
            (Get-SafeProp $grp '_create_user')  -eq 'system' -or 
            (Get-SafeProp $grp 'id') -in $pseudoSystemIds) { return $false }

        # Get the expression array
        $expression = Get-SafeProp $grp 'expression'
        if ($null -eq $expression) { return $false }

        # Check Top-Level and Nested Level for "VirtualMachine" member_type
        # Using @() ensures we are always piping an array to Where-Object
        $hasVM = (@($expression | ForEach-Object { Get-SafeProp $_ 'member_type' }) -contains "VirtualMachine") -or 
                 (@($expression | ForEach-Object { Get-SafeProp $_ 'expressions' } | ForEach-Object { Get-SafeProp $_ 'member_type' }) -contains "VirtualMachine")

        return $hasVM
    }

    if (-not $custom) { Write-Log "No VM-based Security Groups found." WARN; return }

    # 3. Process the filtered groups into CSV rows
    $rows = foreach ($grp in $custom) {
        $null = Remove-ReadOnlyFields -Obj $grp
		$expression = Get-SafeProp $grp 'expression'
		$groupId    = Get-SafeProp $grp 'id'
        
        # Safely build the summary string for resource types
        # This replaces the dot-notation ($_.resource_type) that caused the FATAL error
        $exprSummary = if ($expression) {
            (@($expression | ForEach-Object { Get-SafeProp $_ 'resource_type' }) | Where-Object { $_ }) -join '; '
        } else { 
            'Static' # Should not hit this due to the filter above, but safe to keep
        }

        # Safely build the summary for nested resource types
        $nestedSummary = if ($expression) {
            (@($expression | ForEach-Object { Get-SafeProp $_ 'expressions' } | ForEach-Object { Get-SafeProp $_ 'resource_type' }) | Where-Object { $_ }) -join '; '
        } else { 
            'N/A' 
        }
		
		# ── NEW: Resolve ExternalIDExpression VM names ──────────────
		$resolvedVMs    = @{}
		$vmNamesSummary = ''
	
		if ($expression) {
			$hasExtIdExpr = @($expression | ForEach-Object { Get-SafeProp $_ 'resource_type' }) -contains 'ExternalIDExpression'
	
			if ($hasExtIdExpr) {
				$resolvedVMs = Resolve-ExternalIdVMNames -GroupId $groupId -GroupExpression $expression
	
				# Build a human-readable summary: "VMName; VMName2"
				$vmNamesSummary = ($resolvedVMs.Values | Where-Object { $_ -ne 'UNRESOLVED' }) -join '; '
			}
		}
		# ────────────────────────────────────────────────────────────

        [PSCustomObject]@{
            ObjectType      = 'Group'
            Id              = (Get-SafeProp $grp 'id')
            DisplayName     = (Get-SafeProp $grp 'display_name')
            #Description     = (Get-SafeProp $grp 'description')
            ExpressionTypes = $exprSummary
            NestedTypes     = if ($nestedSummary) { $nestedSummary } else { 'None' }
            #Tags            = (Format-Tags $grp)
            ResolvedVMNames  = $vmNamesSummary    # NEW column: "extId=VMName; ..."
			RawJson         = ($grp | ConvertTo-Json -Depth 20 -Compress)
        }
    }

    # 4. Export to CSV
    $csvPath = Join-Path $OutputFolder 'NSX_VM_Groups.csv'
    $rows | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
    
    # 5. Update Global Stats and Log Success
    $Stats.VMGroups = @($rows).Count
    Write-Log "  Exported $($Stats.VMGroups) VM-based Security Groups → $csvPath" SUCCESS
}

# ═════════════════════════════════════════════════════════════
# 1a. EXPORT VM SECURITY GROUPS IPv4 Members
# ═════════════════════════════════════════════════════════════
function Export-GroupIPMembers {
    Write-Log "━━━ Exporting Pure IPv4 Addresses for VM-Based Groups ━━━" INFO

    $inputPath  = Join-Path $OutputFolder 'NSX_VM_Groups.csv'
    $outputPath = Join-Path $OutputFolder 'NSX_Group_IPv4_Raw.csv'

    if (-not (Test-Path $inputPath)) {
        Write-Log "Source CSV not found at $inputPath." ERROR
        return
    }

    $groups = Import-Csv -Path $inputPath
    $rows = New-Object System.Collections.Generic.List[PSCustomObject]

    foreach ($group in $groups) {
        $groupId   = $group.Id
        $groupName = $group.DisplayName
        
        Write-Log "Processing IPv4 for: $groupName" INFO
        $path = "/policy/api/v1/infra/domains/$DomainId/groups/$groupId/members/ip-addresses"
        
        try {
            $response = Get-AllPages -Path $path
            $allMembers = if ($null -ne $response) { @($response) } else { @() }

            # Separate results into valid IPv4 vs Excluded (CIDR/Range/IPv6)
            $ipv4List = New-Object System.Collections.Generic.List[string]
            $excludedCounter = 0

            foreach ($item in $allMembers) {
                $isPureIp = $false
                try {
                    $ipObj = [ipaddress]$item
                    # Criteria: Must be IPv4, no CIDR slash, no Range hyphen
                    if ($ipObj.AddressFamily -eq 'InterNetwork' -and $item -notmatch '[/-]') {
                        $isPureIp = $true
                    }
                } catch {
                    $isPureIp = $false
                }

                if ($isPureIp) {
                    $ipv4List.Add($item)
                } else {
                    $excludedCounter++
                }
            }

            # Convert to JSON Array string
            $jsonOutput = if ($ipv4List.Count -eq 0) {
                "[]"
            } else {
                $converted = $ipv4List | ConvertTo-Json -Compress
                # Manually wrap single items to maintain array format ["x.x.x.x"]
                if (-not $converted.StartsWith("[")) { "[$converted]" } else { $converted }
            }

            $rows.Add([PSCustomObject]@{
                GroupId       = $groupId
                GroupName     = $groupName
                IPv4Count     = $ipv4List.Count
                ExcludedCount = $excludedCounter
                RawIPv4Json   = $jsonOutput
            })

        } catch {
            Write-Log "Failed to fetch members for group $groupId. Error: $($_.Exception.Message)" WARN
        }
    }

    if ($rows.Count -gt 0) {
        $rows | Export-Csv -Path $outputPath -NoTypeInformation -Encoding UTF8
        Write-Log "Saved data to $outputPath (Check ExcludedCount for filtered CIDRs/Ranges)" SUCCESS
    }
}

# ═════════════════════════════════════════════════════════════
# 1b. Create definition for new IPv4 MIG-IP_ VM SECURITY GROUPS
# ═════════════════════════════════════════════════════════════
function Transform-GroupToIPExpression {
    Write-Log "━━━ Transforming Groups to IP Expression Format ━━━" INFO

    $inputPath  = Join-Path $OutputFolder 'NSX_Group_IPv4_Raw.csv'
    $outputPath = Join-Path $OutputFolder 'NSX_Groups_Transformed.csv'

    if (-not (Test-Path $inputPath)) {
        Write-Log "Source CSV not found at $inputPath." ERROR
        return
    }

    $data = Import-Csv -Path $inputPath
    $seen = @{}
    $transformedRows = New-Object System.Collections.Generic.List[PSCustomObject]

    foreach ($row in $data) {
        # 1. Generate the New Display Name (Your Logic)
        $original = $row.GroupName
        
        # Replace invalid chars, collapse underscores, and trim
        $clean = $original -replace '[^a-zA-Z0-9_-]', '_'
        $clean = ($clean -replace '_+', '_').Trim('_')

        $baseName = "MIG-IP_$clean"
        $newName  = $baseName

        # Handle duplicates
        if ($seen.ContainsKey($baseName)) {
            $seen[$baseName]++
            $newName = "$baseName-$($seen[$baseName])"
        }
        else {
            $seen[$baseName] = 0
        }

        # 2. Re-parse the RawIPv4Json back into a PowerShell Array
        # We ensure it's treated as an array even if empty/single
        $ipList = @($row.RawIPv4Json | ConvertFrom-Json)

        # 3. Construct the New JSON Structure ONLY if IPs exist
        $finalJsonOutput = $null
		if ($ipList.Count -gt 0) {
			$newObject = [PSCustomObject]@{
				expression = @(
					[PSCustomObject]@{
						ip_addresses  = $ipList
						resource_type = "IPAddressExpression"
					}
				)
				display_name = $newName
			}
			$finalJsonOutput = ($newObject | ConvertTo-Json -Depth 20 -Compress)
		} else {
            Write-Log "No IPv4 addresses for $original - leaving FinalJson empty." INFO
        }

        # 4. Add to results (Row is always added, FinalJson might be empty)
        $transformedRows.Add([PSCustomObject]@{
            OriginalGroup   = $original
            OriginalGroupId = $row.GroupId
			MIGIP_GroupName    = $newName
			IPv4Count       = $ipList.Count
			MIGIP_GroupJson       = $finalJsonOutput
        })
    }

    if ($transformedRows.Count -gt 0) {
        $transformedRows | Export-Csv -Path $outputPath -NoTypeInformation -Encoding UTF8
        Write-Log "Transformation complete. Output saved to $outputPath" SUCCESS
    }
}

# ═════════════════════════════════════════════════════════════════════════
# 1c. Create definition for patching VM SECURITY GROUPS with MIG-IP groups
# ═════════════════════════════════════════════════════════════════════════
function Create-FinalMigrationGroups {
    Write-Log "━━━ Creating Final Migration Group Definitions ━━━" INFO

    $inputPath  = Join-Path $OutputFolder 'NSX_VM_Groups-MIGIP.csv'
    $outputPath = Join-Path $OutputFolder 'NSX_VM_Groups-Final.csv'

    if (-not (Test-Path $inputPath)) {
        Write-Log "Source CSV not found: $inputPath" ERROR
        return
    }

    $data = Import-Csv $inputPath
    $finalRows = New-Object System.Collections.Generic.List[PSCustomObject]

    foreach ($row in $data) {
        $updatedJson = $null

        # Process only if there are IPv4 addresses
        if ([int]$row.IPv4Count -gt 0 -and -not [string]::IsNullOrEmpty($row.MIGIP_GroupJson)) {
            try {
                # 1. Parse the original RawJson
                $groupObj = $row.RawJson | ConvertFrom-Json
                $newPath  = "/infra/domains/$DomainId/groups/$($row.MIGIP_GroupName)"
                
                # 2. Look for PathExpression only at the top level
                <# $existingPathExpr = @($groupObj.expression) | Where-Object { $_.resource_type -eq "PathExpression" }

                if ($null -ne $existingPathExpr) {
                    # CASE: PathExpression exists - Append path to existing array
                    Write-Log "Appending to existing PathExpression for $($row.DisplayName)" INFO
                    $existingPathExpr.paths = @($existingPathExpr.paths) + $newPath #>
				$existingPathExpr = @($groupObj.expression | Where-Object { $_.resource_type -eq "PathExpression" })
				if ($existingPathExpr.Count -gt 0) {
					# Append to existing PathExpression
					$existingPathExpr[0].paths = @($existingPathExpr[0].paths) + $newPath
                } 
                else {
                    # CASE: PathExpression does not exist - Append OR + PathExpression
                    Write-Log "Appending OR operator and PathExpression for $($row.DisplayName)" INFO
                    
                    $conjunction = [PSCustomObject]@{
                        conjunction_operator = "OR"
                        id                   = [guid]::NewGuid().ToString()
                        resource_type        = "ConjunctionOperator"
                    }

                    $pathExpr = [PSCustomObject]@{
                        id            = [guid]::NewGuid().ToString()
                        paths         = @($newPath)
                        resource_type = "PathExpression"
                    }

                    # Append: [Original...] + OR + PathExpression
                    $groupObj.expression = @($groupObj.expression) + $conjunction + $pathExpr
                }

                # 3. Serialize the updated object
                $updatedJson = $groupObj | ConvertTo-Json -Depth 20 -Compress

            } catch {
                Write-Log "Failed to patch JSON for $($row.DisplayName). Error: $($_.Exception.Message)" WARN
                $updatedJson = "ERROR_PARSING"
            }
        } 
        else {
            Write-Log "No IPv4 for $($row.DisplayName) - leaving UpdatedRawJson empty." INFO
        }

        # 4. Add the column (either with JSON or empty)
        $row | Add-Member -MemberType NoteProperty -Name "UpdatedRawJson" -Value $updatedJson -Force
        $finalRows.Add($row)
    }

    if ($finalRows.Count -gt 0) {
        $finalRows | Export-Csv -Path $outputPath -NoTypeInformation -Encoding UTF8
        Write-Log "Final migration definitions saved to $outputPath" SUCCESS
    }
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

    if ($ExportVMGroups) { 
    # 1. Discover Groups (Creates NSX_VM_Groups.csv)
    Export-VMGroups

    $groupCsv = Join-Path $OutputFolder 'NSX_VM_Groups.csv'
    if (Test-Path $groupCsv) {
        # 2. Extract and Filter IPs (Creates NSX_Group_IPv4_Raw.csv)
		Export-GroupIPMembers

        $ipCsv = Join-Path $OutputFolder 'NSX_Group_IPv4_Raw.csv'
        if (Test-Path $ipCsv) {
            # 3. Generate Migration IP Groups Payload (Creates NSX_Groups_Transformed.csv)
		    Transform-GroupToIPExpression
        } else {
            Write-Log "Skipping transformation: No IPv4 data was extracted." WARN
        }
        # --- STEP 4: MERGE TO A NEW MIGRATION-SPECIFIC FILE ---
        $transformedPath = Join-Path $OutputFolder 'NSX_Groups_Transformed.csv'
        $migIpPath       = Join-Path $OutputFolder 'NSX_VM_Groups-MIGIP.csv'

        if (Test-Path $transformedPath) {
            Write-Log "Merging data into new file: NSX_VM_Groups-MIGIP.csv" INFO
            
            $ipData = Import-Csv $transformedPath
            $originalData = Import-Csv $groupCsv

            # Create a lookup table using OriginalGroupId for mapping
            $lookup = @{}
            foreach ($item in $ipData) { $lookup[$item.OriginalGroupId] = $item }

            $finalMergedRows = foreach ($row in $originalData) {
                $match = $lookup[$row.Id]
                
                # Create a clean object combining both sources
                [PSCustomObject]@{
                    ObjectType      = $row.ObjectType
					Id              = $row.Id
                    DisplayName     = $row.DisplayName
                    ExpressionTypes = $row.ExpressionTypes
					NestedTypes     = $row.NestedTypes
					ResolvedVMNames = $row.ResolvedVMNames
					RawJson         = $row.RawJson
					
                    # New Columns from the Transformer
                    MIGIP_GroupName    = if ($match) { $match.MIGIP_GroupName } else { "N/A" }
                    IPv4Count       = if ($match) { $match.IPv4Count } else { 0 }
                    MIGIP_GroupJson       = if ($match) { $match.MIGIP_GroupJson } else { $null }
                }
            }

            # Export to the NEW filename
            $finalMergedRows | Export-Csv -Path $migIpPath -NoTypeInformation -Encoding UTF8
            Write-Log "Migration file created successfully at $migIpPath" SUCCESS
        }
		
		if (Test-Path (Join-Path $OutputFolder 'NSX_VM_Groups-MIGIP.csv')) {
            Create-FinalMigrationGroups
        }
		
		} else {
			Write-Log "Skipping processing: NSX_VM_Groups.csv was not found." WARN
		}
	}
} catch {
    Write-Log "FATAL: $_" ERROR
    exit 1
} finally {
    Write-Log "════════════════════════════════════════════" INFO
    Write-Log " EXPORT SUMMARY" INFO
    Write-Log "────────────────────────────────────────────" INFO
    Write-Log "  VMGroups      : $($Stats.VMGroups)"        INFO
    Write-Log "────────────────────────────────────────────" INFO
    Write-Log "  Output folder : $OutputFolder" INFO
    Write-Log "════════════════════════════════════════════" INFO
    Write-Log "Review the CSV files, remove any rows you do NOT want to import," INFO
    Write-Log "then run: .\Import-NSX-VMGroupsToIP.ps1 -NSXManager <SrcNSXManager> -InputFolder '$OutputFolder' [-Action]" INFO


}