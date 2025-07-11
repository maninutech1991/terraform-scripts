Install-ADDSForest `
    -DomainName "corp.contoso.com" `
    -SafeModeAdministratorPassword (ConvertTo-SecureString 'P@ssword1234!' -AsPlainText -Force) `
    -InstallDNS `
    -Force

# This will reboot automatically. Put anything else AFTER reboot as a scheduled task