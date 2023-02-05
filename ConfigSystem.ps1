[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Set our varaibles
$UserProfileFolder = $ENV:USERPROFILE
$DocumentsFolder = [Environment]::GetFolderPath('MyDocuments')
$PWSH5Root = Join-Path -Path $DocumentsFolder -ChildPath 'WindowsPowerShell'
$PWSH7Root = Join-Path -Path $DocumentsFolder -ChildPath 'PowerShell'
$VSCodeRoot = Join-Path -Path $UserProfileFolder -ChildPath 'AppData\Roaming\Code\User'

Install-PackageProvider -Name NuGet -Force
Set-PSRepository -Name PSGallery -InstallationPolicy Trusted

# Ensure OhMyPosh is installed
IF (!(Get-Command oh-my-posh.exe)) {
    IF (Get-Command WinGet) {
        & winget install JanDeDobbeleer.OhMyPosh -s winget
    }
    ELSE {
        Write-Host 'Please install WinGet and re-run this script.'
        BREAK;
    }
    Write-Host 'Oh-My-Posh is Installed.'
}

# Install helpful modules
Install-Module -Name Terminal-Icons -Force -AllowClobber
Install-Module -Name 7Zip4PowerShell -Force -AllowClobber
Write-Host 'Modules Installed.'

# Lets begin downloading our dotSource files
# PowerShell 5
Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/HSVAdam/DotSource/main/PWSH5/Microsoft.PowerShell_profile.ps1' -OutFile "$PWSH5Root\Microsoft.PowerShell_profile.ps1"
Write-Host 'PowerShell 5 Profile Downloaded'

#PowerShell 7
Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/HSVAdam/DotSource/main/PWSH7/Microsoft.PowerShell_profile.ps1' -OutFile "$PWSH7Root\Microsoft.PowerShell_profile.ps1"
Write-Host 'PowerShell 7 Profile Downloaded'

# VSCode
Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/HSVAdam/DotSource/main/VSCode/settings.json' -OutFile "$VSCodeRoot\settings.json"
Write-Host 'Visual Studio Code Profile Downloaded'