# Global variables
$labName = 'ACLAbuse'
$domainName = 'aclabuse.lab'
$admin = 'aclAdmin'
$adminPass = 'aclPass01'
$machineName = 'DC01'
$machineAddress = '192.168.6.10'
# Change the labISO variable to match the ISO you have available
$labISO = 'Windows Server 2019 Standard (Desktop Experience)'

# Lab defintion
New-LabDefinition `
    -Name $labName `
    -DefaultVirtualizationEngine HyperV

# lab network, do not alter the AddressSpace without also changing the $machineAddress
Add-LabVirtualNetworkDefinition `
    -Name $labName `
    -AddressSpace 192.168.6.0/24

# Lab credentials, these can be configured in the global variables at the top of the script
Set-LabInstallationCredential `
    -Username $admin `
    -Password $adminPass

# Active directory domain defintion
Add-LabDomainDefinition `
    -Name $domainName `
    -AdminUser $admin `
    -AdminPassword $adminPass

# The lab configuration script is defined here as a post install activity
$scriptPath = Join-Path $PSScriptRoot '.\Lab-Configuration'
$labConfig = Get-LabInstallationActivity -ScriptFileName 'ACLAbuse.ps1' -DependencyFolder $scriptPath

# Definition for DC01
Add-LabMachineDefinition `
    -Name $machineName `
    -MinMemory 512MB `
    -Memory 1GB `
    -MaxMemory 2GB `
    -Network $labName `
    -IpAddress $machineAddress `
    -DnsServer1 $machineAddress `
    -DomainName $domainName `
    -Roles RootDC `
    -OperatingSystem $labISO `
    -PostInstallationActivity $labConfig

# Install lab & report
Install-Lab
Show-LabDeploymentSummary -Detailed 

# Set up the vEthernet interface on the host to use the newly created DC as its DNS server
$index = (Get-NetAdapter | Where-Object Name -Match $labName).ifIndex
Set-DnsClientServerAddress -InterfaceIndex $index -ServerAddresses $machineAddress
Write-Host "Host vEthernet interface configured..."
Get-NetIPConfiguration -InterfaceIndex $index
