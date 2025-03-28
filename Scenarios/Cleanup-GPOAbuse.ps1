Remove-Lab

Remove-LocalUser `
    -Name "printerUser" `
    
Remove-Item `
    -Path "C:\tmpPrinter" `
    -Force

Remove-SmbShare `
    -Name TmpPrinter `
    -Force `
    -ErrorAction 'silentlycontinue'