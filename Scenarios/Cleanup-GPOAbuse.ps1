Remove-LocalUser `
    -Name "test01" `
    -Force

Remove-SmbShare `
    -Name Temp `
    -Force `
    -ErrorAction 'silentlycontinue'

Remove-Lab