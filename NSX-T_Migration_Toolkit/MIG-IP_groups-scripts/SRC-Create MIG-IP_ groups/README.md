🛡️ NSX VM-to-IP Migration Prep Suite

Goal: Transform existing NSX Security Groups on the Source environment from dynamic VM-Tag membership to a Hybrid membership (VM-Tags OR Static IPs). This ensures that when groups are migrated to a new destination via other tools, they already contain the necessary IP-based logic.

📂 Script Components

1-Export-NSX-VMGroupsToIP.ps1: Discovers VM-based groups and generates IP-based payloads.

2-Import-NSX-VMGroupsToIP.ps1: Executes the creation of helper groups and patches the original groups.

🚀 Step 1: Data Extraction & Transformation
Run the export script against your Source NSX Manager. This "snaps" the current membership of all VM-based groups and resolves them to their effective IPv4 addresses.

PowerShell
.\1-Export-NSX-VMGroupsToIP.ps1 -NSXManager <Source-NSX Manager> -ExportVMGroups $true

What happens in this step:

Discovery: Scans for custom groups using VirtualMachine criteria.

IP Resolution: Fetches the live IPv4 list for those VMs (filtering out IPv6 and CIDRs).

Payload Generation: Creates a NSX_VM_Groups-Final.csv containing the MIG-IP_ helper group definitions and the updated "Hybrid" JSON for your original groups.

🔍 Step 2: The Dry Run (Validation)
Before making any changes to your production NSX environment, it is highly recommended to perform a Dry Run. By appending the -WhatIf parameter, the script will simulate the entire process and report exactly what it would do without sending any write/patch commands to the API.

PowerShell
.\2-Import-NSX-VMGroupsToIP.ps1 -NSXManager <Source-NSX Manager> -InputFolder <Path> -CreateMIGIPGroups $true -PatchVMGroups $true -WhatIf

Check the Logs: The summary at the end of the log will show "WhatIf" counts for Created and Patched groups.
Verify Logic: Review the console output to ensure the dependency sorter is ordering your groups correctly.

🚀 Step 3: Source Environment Preparation
Apply the transformation to the Source NSX environment. This prepares the groups for their eventual migration.

Stage A: Create Helper Groups
Creates the standalone IP-address groups (prefixed with MIG-IP_). These are the targets for the new logic.

PowerShell
.\2-Import-NSX-VMGroupsToIP.ps1 -NSXManager <Source-NSX Manager> -InputFolder <Path> -CreateMIGIPGroups $true

Stage B: Patch Original Groups
Updates your production Security Groups on the source to the "Hybrid" state.

PowerShell
.\2-Import-NSX-VMGroupsToIP.ps1 -NSXManager <Source-NSX Manager> -InputFolder <Path> -PatchVMGroups $true

Result: Your groups now function using either the original VM Tags OR the newly resolved Static IPs.

🆘 Emergency Rollback
If you need to revert the source environment to its original VM-only state:

PowerShell
.\2-Import-NSX-VMGroupsToIP.ps1 -NSXManager <Source-NSX Manager> -InputFolder <Path> -RollbackVMGroups $true

Logic: The script identifies groups containing MIG-IP_ references and restores them using the RawJson captured during the initial export.
Safety: A manual confirmation prompt is required. You can also use -WhatIf with Rollback to see what would be reverted.

🛠 Technical Implementation Details
Dependency Management: The suite automatically calculates group-in-group dependencies to ensure nested groups are patched in the correct order.
Idempotency: Both scripts are safe to run multiple times; the Import script will skip MIG-IP_ groups that already exist.

Logging: All actions are written to a timestamped .log file within the output folder.

