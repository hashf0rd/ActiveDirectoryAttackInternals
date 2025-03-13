# nothing here yet
Add-LocalGroupMember -Name "Remote Management Users" -Member "jim.duggan"

# Install RSAT & GPO stuff
Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0
Add-WindowsCapability -Online -Name Rsat.GroupPolicy.Management.Tools~~~~0.0.1.0