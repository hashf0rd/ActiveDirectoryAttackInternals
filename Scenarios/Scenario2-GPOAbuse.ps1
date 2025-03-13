# set up a test user
New-LocalUser `
    -Name "test01" `
    -AccountExpires (get-date).AddHours(1) `
    -Password (ConvertTo-SecureString "testPass01" -AsPlaintext -Force) `
    -ErrorAction 'silentlycontinue'

$share = "C:\tempShare"

# Set up a SMB share on the host
New-Item `
    -ItemType Directory `
    -Path $share `
    -Force `
    -ErrorAction 'silentlycontinue'
    
Remove-SmbShare `
    -Name Temp `
    -Force `
    -ErrorAction 'silentlycontinue'

New-SMBShare `
    -Name Temp `
    -Path $share

Unblock-SmbShareAccess `
    -Name Temp `
    -AccountName "test01" `
    -Force

# Global variables
$labName = 'GPOAbuse'
$domainName = 'gpoabuse.lab' 
$admin = 'gpoAdmin'
$adminPass = 'gpoPass01'
$machineNameDC = 'DC01'
$machineAddressDC = '192.168.6.10'
$machineNameWS = 'WS01'
$machineAddressWS = '192.168.6.88'

# Change the labISO_X variables to match the ISOs you have available
$labISO_DC = 'Windows Server 2019 Standard (Desktop Experience)'
$labISO_WS = 'Windows 11 Pro'

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
$scriptPath = Join-Path $PSScriptRoot '.\Scenario-Configuration'
$labConfigDC = Get-LabInstallationActivity -ScriptFileName 'Config-GPOAbuse-DC01.ps1' -DependencyFolder $scriptPath
#$labConfigWS = Get-LabInstallationActivity -ScriptFileName 'Config-GPOAbuse-WS01.ps1' -DependencyFolder $scriptPath

# Definition for DC01
Add-LabMachineDefinition `
    -Name $machineNameDC `
    -MinMemory 512MB `
    -Memory 1GB `
    -MaxMemory 2GB `
    -Network $labName `
    -IpAddress $machineAddressDC `
    -DnsServer1 $machineAddressDC `
    -DomainName $domainName `
    -Roles RootDC `
    -OperatingSystem $labISO_DC `
    -PostInstallationActivity $labConfigDC

# Definition for WS01
# Make sure the DnsServer is set to DC01's IP Address
Add-LabMachineDefinition `
    -Name $machineNameWS `
    -MinMemory 512MB `
    -Memory 1GB `
    -MaxMemory 2GB `
    -Network $labName `
    -IpAddress $machineAddressWS `
    -DnsServer1 $machineAddressDC `
    -DomainName $domainName `
    -OperatingSystem $labISO_WS `
    -PostInstallationActivity $labConfigWS

# Install lab & report
Install-Lab 
Show-LabDeploymentSummary 

# Set up the vEthernet interface on the host to use the newly created DC as its DNS server
$index = (Get-NetAdapter | Where-Object Name -Match $labName).ifIndex
Set-DnsClientServerAddress -InterfaceIndex $index -ServerAddresses $machineAddressDC
Write-Host "Host vEthernet interface configured..."
Get-NetIPConfiguration -InterfaceIndex $index

Restart-LabVM -ComputerName "DC01" -Wait
Wait-LabADReady -ComputerName "DC01"

# This needs to be done after the DC has rebooted for some reason
Invoke-LabCommand -ComputerName "DC01" -ScriptBlock {
    # Move DC to Dunwhich site
    $DC = Get-ADDomainController -Discover
    New-ADReplicationSite -Name "Dunwhich" -Server $DC
    $site = Get-ADReplicationSite -Filter 'Name -eq "Dunwhich"' 
    Get-ADDomainController -Filter 'Name -like "DC01*"' | Move-ADDirectoryServer -Site $site -Server $DC

    # Site Policy Admins can write tp/read from the gpLink property of the Dunwhich site
    $siteDN = "AD:\$((Get-ADReplicationSite -Identity "Dunwhich").DistinguishedName)"
    $siteACL = Get-ACL -Path $siteDN
    $groupSID = (Get-ADGroup -Identity 'Site Policy Admins').SID

    # Write
    $writeACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
        $groupSID,
        [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty,
        [System.Security.AccessControl.AccessControlType]::Allow,
        [GUID]'f30e3bbe-9ff0-11d1-b603-0000f80367c1' # gpLink
        )
    $siteACL.AddAccessRule($writeACE)

    # Read
    $readACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
        $groupSID,
        [System.DirectoryServices.ActiveDirectoryRights]::ReadProperty,
        [System.Security.AccessControl.AccessControlType]::Allow,
        [GUID]'f30e3bbe-9ff0-11d1-b603-0000f80367c1' # gpLink
        )
    $siteACL.AddAccessRule($readACE)
    
    Set-Acl -AclObject $siteACL -Path $siteDN
}