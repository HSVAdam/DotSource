#Requires -RunAsAdministrator
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Check if profile already exists, if not lets get to building it
IF (!(Test-Path -Path $PROFILE -PathType Leaf)) {
    # Detect current PowerShell version and create profile folders
    IF ($PSVersionTable.PSEdition -eq 'Core') {
        $null = New-Item -Path "$($env:USERPROFILE)\Documents\PowerShell" -ItemType Directory
    }
    IF ($PSVersionTable.PSEdition -eq 'Desktop') {
        $null = New-Item -Path "$($env:USERPROFILE)\Documents\WindowsPowerShell" -ItemType Directory
    }
}

# Install modules from PSGallery
Install-PackageProvider -Name NuGet -Force
Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
Install-Module -Name Terminal-Icons -Scope CurrentUser -Repository PSGallery -Force
Install-Module -Name 7Zip4Powershell -Scope CurrentUser -Repository PSGallery -Force

# Install OhMyPosh
Set-ExecutionPolicy Bypass -Scope Process -Force; Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://ohmyposh.dev/install.ps1'))

# Font Install
# Get all installed font families
[void] [System.Reflection.Assembly]::LoadWithPartialName('System.Drawing')
$FontFamilies = (New-Object System.Drawing.Text.InstalledFontCollection).Families
# Check if CaskaydiaCove NF is installed
IF ($FontFamilies -notcontains 'CaskaydiaCove NF') {

    # Download and install CaskaydiaCove NF
    $WebClient = New-Object System.Net.WebClient
    $WebClient.DownloadFile('https://github.com/ryanoasis/nerd-fonts/releases/download/v3.0.2/CascadiaCode.zip', '.\CascadiaCode.zip')

    Expand-Archive -Path '.\CascadiaCode.zip' -DestinationPath '.\CascadiaCode' -Force
    $Destination = (New-Object -ComObject Shell.Application).Namespace(0x14)
    Get-ChildItem -Path '.\CascadiaCode' -Recurse -Filter '*.ttf' | ForEach-Object {
        IF (-not(Test-Path "C:\Windows\Fonts\$($_.Name)")) {
            # Install font
            $Destination.CopyHere($_.FullName, 0x10)
        }
    }
    # Clean up
    Remove-Item -Path '.\CascadiaCode' -Recurse -Force
    Remove-Item -Path '.\CascadiaCode.zip' -Force
}


# Lets begin downloading our dotSource files
# PowerShell 5
Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/HSVAdam/DotSource/main/Microsoft.PowerShell_profile.ps1' -OutFile "$($env:USERPROFILE)\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1"

#PowerShell Core
Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/HSVAdam/DotSource/main/Microsoft.PowerShell_profile.ps1' -OutFile "$($env:USERPROFILE)\Documents\PowerShell\Microsoft.PowerShell_profile.ps1"

# Restart profile
. $PROFILE