function New-CustomADOU {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$OUName,

        [Parameter(Mandatory = $true)]
        [string]$ParentDN,  # e.g. "DC=example,DC=com"

        [switch]$ProtectFromDeletion
    )

    # Import AD module if needed
    if (-not (Get-Module -Name ActiveDirectory)) {
        Import-Module ActiveDirectory
    }

    $OUdn = "OU=$OUName,$ParentDN"

    try {
        # Check if OU already exists
        if (Get-ADOrganizationalUnit -LDAPFilter "(distinguishedName=$OUdn)" -ErrorAction SilentlyContinue) {
            Write-Host "OU '$OUName' already exists in '$ParentDN'" -ForegroundColor Yellow
        } else {
            # Create the OU
            New-ADOrganizationalUnit -Name $OUName -Path $ParentDN -ProtectedFromAccidentalDeletion:$ProtectFromDeletion.IsPresent
            Write-Host "OU '$OUName' successfully created in '$ParentDN'" -ForegroundColor Green
        }
    }
    catch {
        Write-Error "Failed to create OU: $_"
    }
}


<#
function New-GPOForOU {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$GPOName,

        [Parameter(Mandatory = $true)]
        [string]$OU,  # e.g., "OU=Finance,DC=domain,DC=local"

        [switch]$Enforced
    )

    # Import necessary modules
    if (-not (Get-Module -Name GroupPolicy)) {
        Import-Module GroupPolicy
    }

    try {
        # Create GPO if it doesn't already exist
        $existingGPO = Get-GPO -Name $GPOName -ErrorAction SilentlyContinue
        if (-not $existingGPO) {
            $gpo = New-GPO -Name $GPOName -Comment "Created by script"
            Write-Host "GPO '$GPOName' created successfully." -ForegroundColor Green
        } else {
            $gpo = $existingGPO
            Write-Host "GPO '$GPOName' already exists." -ForegroundColor Yellow
        }

        # Link GPO to OU with proper EnforceLink enum
        $enforceValue = if ($Enforced.IsPresent) {
            [Microsoft.GroupPolicy.EnforceLink]::Yes
        } else {
            [Microsoft.GroupPolicy.EnforceLink]::No
        }

        New-GPLink -Name $GPOName -Target $OU -Enforced $enforceValue
        Write-Host "GPO '$GPOName' linked to '$OU' with Enforced = $enforceValue." -ForegroundColor Green
    }
    catch {
        Write-Error "Error creating or linking GPO: $_"
    }
}

#>



function New-GPOForOU {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$GPOName,

        [Parameter(Mandatory = $true)]
        [string]$OU,  # e.g., "OU=Finance,DC=uptin,DC=local"

        [switch]$Enforced
    )

    # Import necessary module
    if (-not (Get-Module -Name GroupPolicy)) {
        Import-Module GroupPolicy
    }

    try {
        # Create the GPO if it doesn't exist
        $existingGPO = Get-GPO -Name $GPOName -ErrorAction SilentlyContinue
        if (-not $existingGPO) {
            $gpo = New-GPO -Name $GPOName -Comment "Created by script"
            Write-Host "GPO '$GPOName' created successfully." -ForegroundColor Green
        } else {
            $gpo = $existingGPO
            Write-Host "GPO '$GPOName' already exists." -ForegroundColor Yellow
        }

        # Set the enforce value to the required enum
        $enforceEnum = if ($Enforced.IsPresent) {
            [Microsoft.GroupPolicy.EnforceLink]::Yes
        } else {
            [Microsoft.GroupPolicy.EnforceLink]::No
        }

        # Link GPO to OU with link disabled and enforce setting
        New-GPLink -Name $GPOName -Target $OU -Enforced $enforceEnum -LinkEnabled No
        Write-Host "GPO '$GPOName' linked to '$OU' with Enforced = $enforceEnum and LinkEnabled = No (disabled)." -ForegroundColor Cyan
    }
    catch {
        Write-Error "Error creating or linking GPO: $_"
    }
}



function Initialize-WallpaperShare {
    param (
        [string]$WallpaperFolderName = "Wallpapers",
        [string]$DomainName = "uptin.local"
    )

    # Path inside SYSVOL Netlogon
    $scriptsPath = "C:\Windows\SYSVOL\sysvol\$DomainName\scripts"
    $wallpaperFolderPath = Join-Path $scriptsPath $WallpaperFolderName

    # Create folder if not exists
    if (-not (Test-Path $wallpaperFolderPath)) {
        New-Item -ItemType Directory -Path $wallpaperFolderPath -Force | Out-Null
        Write-Host "Created folder: $wallpaperFolderPath" -ForegroundColor Green
    } else {
        Write-Host "Folder already exists: $wallpaperFolderPath" -ForegroundColor Yellow
    }

    # Set NTFS Permissions: Read for Authenticated Users
    $acl = Get-Acl $wallpaperFolderPath
    $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        "Authenticated Users",
        "ReadAndExecute",
        "ContainerInherit,ObjectInherit",
        "None",
        "Allow"
    )

    $acl.SetAccessRule($accessRule)
    Set-Acl -Path $wallpaperFolderPath -AclObject $acl
    Write-Host "Set 'Read & Execute' permissions for 'Authenticated Users'" -ForegroundColor Green

    # Return UNC path
    return "\\$DomainName\netlogon\$WallpaperFolderName"
}


function Set-WallpaperPolicy {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$GPOName,

        [Parameter(Mandatory = $true)]
        [string]$WallpaperFolder = "\\yourdomain\netlogon\Wallpapers",  # Ensure this folder exists and is accessible by users

        [Parameter(Mandatory = $false)]
        [string]$WallpaperURL = "https://picsum.photos/1920/1080"  # Random image each time
    )

    # Ensure GPO exists
    $gpo = Get-GPO -Name $GPOName -ErrorAction Stop

    # Download image
    $fileName = "wallpaper_$((Get-Random).ToString()).jpg"
    $filePath = Join-Path -Path $WallpaperFolder -ChildPath $fileName

    try {
        Invoke-WebRequest -Uri $WallpaperURL -OutFile $filePath
        Write-Host "Wallpaper downloaded to: $filePath" -ForegroundColor Cyan
    } catch {
        Write-Error "Failed to download wallpaper: $_"
        return
    }

    # Define registry path for wallpaper
    $wallpaperPolicyPath = "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System"

    # Set Registry value using GPO
    Set-GPRegistryValue -Name $GPOName -Key $wallpaperPolicyPath -ValueName "Wallpaper" -Type String -Value $filePath
    Set-GPRegistryValue -Name $GPOName -Key $wallpaperPolicyPath -ValueName "WallpaperStyle" -Type String -Value "2"  # 2 = Stretch
    Set-GPRegistryValue -Name $GPOName -Key $wallpaperPolicyPath -ValueName "TileWallpaper" -Type String -Value "0"

    Write-Host "Wallpaper policy set in GPO '$GPOName'." -ForegroundColor Green
}


function New-FinanceUserAndMoveComputer {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Username,

        [Parameter(Mandatory = $true)]
        [string]$Password,

        [Parameter(Mandatory = $true)]
        [string]$ComputerName,

        [string]$OUName = "Finance",
        [string]$DomainDN = "DC=uptin,DC=local"
    )

    # Import AD module if needed
    if (-not (Get-Module -Name ActiveDirectory)) {
        Import-Module ActiveDirectory
    }

    $financeOU = "OU=$OUName,$DomainDN"

    try {
        # Create user
        $securePassword = ConvertTo-SecureString $Password -AsPlainText -Force

        if (Get-ADUser -Filter "SamAccountName -eq '$Username'" -ErrorAction SilentlyContinue) {
            Write-Host "User '$Username' already exists." -ForegroundColor Yellow
        } else {
            New-ADUser -Name $Username `
                       -SamAccountName $Username `
                       -AccountPassword $securePassword `
                       -Enabled $true `
                       -Path $financeOU `
                       -PasswordNeverExpires $false `
                       -ChangePasswordAtLogon $false

            Write-Host "User '$Username' created in OU '$OUName' with password '$Password'." -ForegroundColor Green
        }

        # Move computer
        $comp = Get-ADComputer -Identity $ComputerName -ErrorAction Stop
        Move-ADObject -Identity $comp.DistinguishedName -TargetPath $financeOU
        Write-Host "Computer '$ComputerName' moved to OU '$OUName'." -ForegroundColor Green
    }
    catch {
        Write-Error "Error: $_"
    }
}


New-CustomADOU -OUName "Finance" -ParentDN "DC=corp,DC=contoso,Dc=com" -ProtectFromDeletion

#New-GPOForOU -GPOName "Finance GPO" -OU "OU=Finance,DC=uptin,DC=local" -Enforced

#New-GPOForOU -GPOName "Finance GPO" -OU "OU=Finance,DC=uptin,DC=local"

New-GPOForOU -GPOName "Finance GPO" -OU "OU=Finance,DC=corp,DC=contoso,Dc=com"



$wallpaperShareUNC = Initialize-WallpaperShare

New-FinanceUserAndMoveComputer -Username "unique" -Password "Cyberark1" -ComputerName "DcClient"


Set-WallpaperPolicy -GPOName "Finance GPO" -WallpaperFolder "\\corp.contoso.com\netlogon\Wallpapers"

