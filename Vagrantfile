# -*- mode: ruby -*-
# vi: set ft=ruby :

# Set up the vEthernet interface on the host to use the newly created DC as its DNS server
# $index = (Get-NetAdapter | Where-Object Name -Match $labName).ifIndex
# Set-DnsClientServerAddress -InterfaceIndex $index -ServerAddresses $machineAddress
# Write-Host "Host vEthernet interface configured..."
# Get-NetIPConfiguration -InterfaceIndex $index

BOX_DC = "gusztavvargadr/windows-server"

Vagrant.configure("2") do |config|
  config.vm.define "aclAbuse", autostart: false, do |aclabuse|
    aclabuse.vm.box = BOX_DC 
    aclabuse.vm.hostname = "dc01.aclabuse.lab"

    # use the plaintext WinRM transport and force it to use basic authentication.
    # NB this is needed because the default negotiate transport stops working
    #    after the domain controller is installed.
    #    see https://groups.google.com/forum/#!topic/vagrant-up/sZantuCM0q4
    aclabuse.winrm.transport = :plaintext
    aclabuse.winrm.basic_auth_only = true

    aclabuse.vm.communicator = "winrm"
    aclabuse.vm.network :forwarded_port, guest: 5985, host: 5985, id: "winrm", auto_correct: true
    aclabuse.vm.network :forwarded_port, guest: 22, host: 2222, id: "ssh", auto_correct: true
    aclabuse.vm.network :forwarded_port, guest: 3389, host: 3389, id: "rdp", auto_correct: true
    aclabuse.vm.network :private_network, ip: "192.168.6.1"
    aclabuse.vm.network "public_network", bridge: "{YOUR_V_SWITCH_NAME}"

    aclabuse.vm.network :forwarded_port, guest: 389, host: 7389, id: "ldap", auto_correct: true
    aclabuse.vm.network :forwarded_port, guest: 636, host: 7636, id: "ldaps", auto_correct: true

    aclabuse.vm.provder "shell", inline:
    aclabuse.vm.provision "shell", reboot: true
    aclabuse.vm.provision "shell", :path: "VM-Configuration/ACLAbuse.ps1", privileged: true

    
    aclabuse.vm.provider "hyperv" do |, override|
      vb.name = vmname
      vb.memory = 1024
    end
  end
end
