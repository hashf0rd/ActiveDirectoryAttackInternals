<#
Attack Path

The attacker gains initial access to the network and discovers John's account has a weak password.

After accessing John's account, initial recon shows John is part of the Office Admins

The Office Admins group has write access over the SetWallpaper GPO linked to the EnterpriseComputers OU

The attacker modifies the GPO to mount an attacker controlled share via an immediate task, and to add a scheduled task that dumps LSA secrets to this share

Cracking the passwords from these hives gives the attacker access to the Jim Duggan account

This account is part of the Group Policy Creators Owners group, meaning it has the privileges to create GPOs in the domain

This account is also part of the Site Policy Admins group, which allows the account to link GPOs to the Dunwhich site

Bad luck, as this site contains the DC - meaning we can now create a GPO and link it to the site, where it will be applied to the DC

Using this the attacker adds themselves to the restricted groups for the DC as a local admin

#>

# Global variables
$labName = 'GPOAbuse'
$domainName = 'gpoabuse.lab' 
$admin = 'gpoAdmin'
$adminPass = 'gpoPass01'
$domainControllerName = 'DC01'
$domainControllerAddress = '192.168.6.10'
$workstationName = 'AdminWS01'
$workstationAddress = '192.168.6.88'
$domainName = "gpoabuse.lab"

# Add users
New-ADUser -Name "John Dee" `
    -GivenName "John" -Surname "Dee" `
    -SamAccountName "john.dee" `
    -UserPrincipalName ("John.Dee@" + $domainName) `
    -AccountPassword (ConvertTo-SecureString "johnsPass01" -AsPlainText -Force) `
    -PassThru | Enable-ADAccount

New-ADUser -Name "Jim Duggan" `
    -GivenName "Jim" -Surname "Duggan" `
    -SamAccountName "jim.duggan" `
    -UserPrincipalName ("Jim.Duggan@" + $domainName) `
    -AccountPassword (ConvertTo-SecureString "jimsPass01" -AsPlainText -Force) `
    -PassThru | Enable-ADAccount

# User groups
New-ADGroup -Name "Office Admins" -GroupScope Global  
New-ADGroup -Name "Site Policy Admins" -GroupScope Global
Add-ADGroupMember -Identity "Office Admins" -Members "john.dee"
Add-ADGroupMember -Identity "Site Policy Admins" -Members "jim.duggan"
Add-ADGroupMember -Identity "Group Policy Creator Owners" -Members "Site Policy Admins"

# Set up workstation OU
New-ADOrganizationalUnit -Name "EnterpriseWorkstations" -Path "DC=gpoabuse,DC=lab" -PassThru

# Move WS01 to workstation OU
Get-ADComputer -Identity "AdminWS01" | Move-ADObject -TargetPath "OU=EnterpriseWorkstations,DC=gpoabuse,DC=lab"

# adapted from https://raw.githubusercontent.com/Orange-Cyberdefense/GOAD/refs/heads/main/ad/GOAD/scripts/gpo_abuse.ps1
$gpo_exist = Get-GPO -Name "Set Wallpaper" -erroraction ignore

if ($gpo_exist) {
    # pass
} else {
    New-GPO -Name "SetWallapper" -comment "Office admins can set the wallpaper"
    New-GPLink -Name "SetWallapper" -Target "OU=EnterpriseWorkstations,DC=gpoabuse,DC=lab"
    Set-GPRegistryValue -Name "SetWallapper" -key "HKEY_CURRENT_USER\Control Panel\Colors" -ValueName Background -Type String -Value "100 175 200"
    Set-GPRegistryValue -Name "SetWallapper" -key "HKEY_CURRENT_USER\Control Panel\Desktop" -ValueName Wallpaper -Type String -Value ""
    Set-GPRegistryValue -Name "SetWallapper" -Key "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\CurrentVersion\WinLogon" -ValueName SyncForegroundPolicy -Type DWORD -Value 1
    Set-GPPermissions -Name "SetWallapper" -PermissionLevel GpoEdit -TargetName "Office Admins" -TargetType "Group"
}

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
