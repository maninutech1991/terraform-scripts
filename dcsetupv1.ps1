# Install the AD Domain Services role
Install-WindowsFeature AD-Domain-Services

# Promote this server to a Domain Controller with a new forest
Install-ADDSForest `
    -DomainName "corp.contoso.com" `
    -SafeModeAdministratorPassword (ConvertTo-SecureString 'P@ssword1234!' -AsPlainText -Force) `
    -InstallDNS `
    -Force

# After reboot, AD Tools will usually be installed automatically, but to ensure it:
# You can run this part as a second script post-reboot, or add it as a scheduled task.
Write-Output "Creating scheduled task to run run-on-reboot.ps1 on startup..."

# Define task variables
$TaskName = "RunAfterRebootScript"
$ScriptPath = "C:\Scripts\run-on-reboot.ps1"

# Ensure the script directory exists
if (-not (Test-Path "C:\Scripts")) {
    New-Item -ItemType Directory -Path "C:\Scripts"
}

# Download the run-on-reboot script from GitHub
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/maninutech1991/terraform-scripts/main/run-on-reboot.ps1" -OutFile $ScriptPath

# Create scheduled task action and trigger
$Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -File `"$ScriptPath`""
$Trigger = New-ScheduledTaskTrigger -AtStartup
$Principal = New-ScheduledTaskPrincipal -UserId "azureadmin" -LogonType Password -RunLevel Highest

# Create secure password
$Password = ConvertTo-SecureString "P@ssword1234!" -AsPlainText -Force

# Register the scheduled task
Register-ScheduledTask -Action $Action -Trigger $Trigger -Principal $Principal -TaskName $TaskName -Description "Run run-on-reboot.ps1 after reboot" -User "azureadmin" -Password $Password -Force

Write-Output "Scheduled task created successfully."
