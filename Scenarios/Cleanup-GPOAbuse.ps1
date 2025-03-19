Remove-LocalUser `
    -Name "gpoAdmin" `
    
Remove-Item `
    -Path "C:\tmpPrinter" `
    -Force

Remove-SmbShare `
    -Name TmpPrinter `
    -Force `
    -ErrorAction 'silentlycontinue'

Remove-Lab