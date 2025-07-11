# Install the AD Domain Services role
Install-WindowsFeature AD-Domain-Services

# Promote this server to a Domain Controller with a new forest
Install-ADDSForest `
    -DomainName "corp.contoso.com" `
    -SafeModeAdministratorPassword (ConvertTo-SecureString 'P@ssword1234!' -AsPlainText -Force) `
    -InstallDNS `
    -Force

# After reboot, AD Tools will usually be installed automatically, but to ensure it:
