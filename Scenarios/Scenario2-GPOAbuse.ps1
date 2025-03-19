# Global variables
$labName = 'GPOAbuse'
$domainName = 'gpoabuse.lab' 
$admin = 'gpoAdmin'
$adminPass = 'gpoPass01'
$domainControllerName = 'DC01'
$domainControllerAddress = '192.168.6.10'
$workstationName = 'WS01'
$workstationAddress = '192.168.6.88'

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
$scriptPath = Join-Path $PSScriptRoot 'Scenario-Configuration'
$domainControllerPostInstall = Get-LabInstallationActivity -ScriptFileName 'Config-GPOAbuse-DC01.ps1' -DependencyFolder $scriptPath
$workstationPostInstall = Get-LabInstallationActivity -ScriptFileName 'Config-GPOAbuse-WS01.ps1' -DependencyFolder $scriptPath

# Definition for DC01
Add-LabMachineDefinition `
    -Name $domainControllerName `
    -MinMemory 512MB `
    -Memory 1GB `
    -MaxMemory 2GB `
    -Network $labName `
    -IpAddress $domainControllerAddress `
    -DnsServer1 $domainControllerAddress `
    -DomainName $domainName `
    -Roles RootDC `
    -OperatingSystem $labISO_DC `
    -PostInstallationActivity $domainControllerPostInstall

# Definition for WS01
# Make sure the DnsServer is set to DC01's IP Address
Add-LabMachineDefinition `
    -Name $workstationName `
    -MinMemory 512MB `
    -Memory 1GB `
    -MaxMemory 2GB `
    -Network $labName `
    -IpAddress $workstationAddress `
    -DnsServer1 $domainControllerAddress `
    -DomainName $domainName `
    -OperatingSystem $labISO_WS `
    -PostInstallationActivity $workstationPostInstall

# Install lab & report
Install-Lab 
Show-LabDeploymentSummary 

# Set up the vEthernet interface on the host to use the newly created DC as its DNS server
$index = (Get-NetAdapter | Where-Object Name -Match $labName).ifIndex
Set-DnsClientServerAddress -InterfaceIndex $index -ServerAddresses $machineAddressDC
Write-Host "Host vEthernet interface configured..."
Get-NetIPConfiguration -InterfaceIndex $index

Restart-LabVM -ComputerName $domainControllerName -Wait
Wait-LabADReady -ComputerName $domainControllerName

# This needs to be done after the DC has rebooted for some reason
Invoke-LabCommand -ComputerName $domainControllerName -ScriptBlock {
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

# Set up temporary local user
New-LocalUser `
    -Name "gpoAdmin" `
    -AccountExpires (get-date).AddHours(1) `
    -Password (ConvertTo-SecureString "gpoPass01" -AsPlaintext -Force) `
    -ErrorAction 'silentlycontinue'

# Set up a SMB share on the host
$sharePath = "C:\tmpPrinter"
$shareName = "tmpPrinter"

New-Item `
    -ItemType Directory `
    -Path $sharePath `
    -Force `
    -ErrorAction 'silentlycontinue'
    
Remove-SmbShare `
    -Name $shareName `
    -Force `
    -ErrorAction 'silentlycontinue'

New-SMBShare `
    -Name $shareName `
    -Path $sharePath

Unblock-SmbShareAccess `
    -Name Temp `
    -AccountName "gpoAdmin" `
    -Force