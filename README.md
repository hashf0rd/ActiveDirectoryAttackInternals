## Overview
This repo contains the notebooks and associated scripts used to generate the AD attack internals series on my blog: 

The series is an attempt to explore and demonstrate how modern attacks against Active Directory work from the ground up, without using existing tooling. The notebooks use a combination of PowerShell and Python, specifically the Impacket library. 

## Disclaimer
The code contained in these notebooks is __POC only__: no consideration has been given for performance, scalability, compatibility, or more importantly, operational security.

## Requirements
These notebooks were developed in the following environment:
- [Hyper-V](https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/quick-start/enable-hyper-v)
- [Automatedlab](https://automatedlab.org/en/latest/)
- Windows Server ISOs (any version really, but when writing these notebooks __Windows Server 2019 Standard (Desktop Experience)__ specifically was used)
- [.Net interactive kernel](https://github.com/dotnet/interactive)
- VsCode [Polyglot Notebook extension](https://marketplace.visualstudio.com/items?itemName=ms-dotnettools.dotnet-interactive-vscode)

### Installing Impacket on Windows
Some notebooks use the Impacket library. To get this working on Windows, do the following from an admin terminal:
- `git clone https://github.com/SecureAuthCorp/impacket.git $home\impacket`
- `Add-MpPreference -ExclusionPath $home\impacket`
- `Add-MpPreference -ExclusionPath $home\AppData\Roaming\Python\Python312\Scripts`
- `pip3 install -r $home/impacket/requirements.txt`
- `cd $home\impacket && pip3 install .`
- `python3 ./setup.py install`


### Virtualisation Options
If you wish to use a different hypervisor to Hyper-v, the lab configuration scripts for the most part work standalone - simply build your virtual environment 

## Recreating an attack scenario
The scripts that build each virtualized scenario utilise [Automatedlab](https://automatedlab.org/en/latest/). The scripts that configure each scenario are based off of the [excellent work by Safebuffer](https://github.com/safebuffer/vulnerable-AD) and the [Orange Cyberdefense team](https://github.com/Orange-Cyberdefense/GOAD/tree/main/ad/GOAD/scripts). 

The scripts to build each scenario are stored in the `Scenarios` folder and are individually named `scenario<chapter number>-<scenario name>.ps1`, with each script then calling a corresponding configuration script stored in the `Scenarios\Scenario-Configuration` folder. Calling the appropriate `Scenario<chapter number>-<scenario name>.ps1` script should be all that is required to set up each scenario.

Simply call the script for the scenario you want to run, Automatedlab will do the rest.

## Troubleshooting
If you need to close the scenario and come back to it later, do so by stopping the scenario VM(s) and closing the admin console: `Stop-LabVM <vm name>`.

Coming back to the scenario later: `Import-Lab <scenario name>` and `Start-LavVM <vm name>`.

If you need to check the configuration on any of the scenario VMs for any reason, you can do this by running `Enter-PSLabSession <vm name>` from an admin console.

__Note:__ The VM with the Domain Controller role is configured as a DNS server for the virtualised network. You may find this causes a slight delay in your regular internet browsing. When not running the scenario, disable the virtual network adapter with `Disable-NetAdapter vEther*`, and enable it again when you bring the VM(s) back up: `Enable-NetAdapter vEther*`. Alternatively, a simpler solution is to set a custom DNS provider in your browsers DNS-over-HTTPS settings.

## Scenarios
1. [ACL Abuse](./1.%20ACL%20Abuse)
2. [GPO Abuse](./2.%20GPO%20Abuse)
3. [Kerberoasting](./3.%20Kerberoasting)
4. [Targeted Kerberoast]()
5. [ASREP Roast]()
6. [ASREQ Roast]()
7. [Timeroasting]()
8. [Bronze Ticket]()
9. [Silver Ticket]()
10. [Golden Ticket]()
11. [Diamond Ticket]()
12. [Sapphire Ticket]()
13. [Unconstrained Delegation]()
14. [Constrained Delegation]()
15. [Resource Based Constrained Delegation]()
16. [S4u2self Abuse]()
17. [Kerberos Relaying]()
18. [Pass the Ticket]()
19. [Overpass the Hash]()
20. [Pass the Key]()
21. [UNPac the Hash]()
22. [Encryption Downgrade]()
23. [Skeleton Key]()
24. [SAMAccountName Spoofing]()
25. [SPN Jacking]()
26. [Ticket Creation with SID History]()
27. [Shadow Credentials]()
28. [PrimaryGroupID Attack]()
