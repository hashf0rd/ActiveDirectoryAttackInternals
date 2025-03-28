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

# Weird SMB bug requires this for my localization, opsec fail but whatever
Copy-Item C:\WINDOWS\system32\WindowsPowerShell\v1.0\Modules\SmbShare\en-US C:\WINDOWS\system32\WindowsPowerShell\v1.0\Modules\SmbShare\en-GB