FUNCTION Set-MyProfile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [uri]$PS5Profile = 'https://raw.githubusercontent.com/HSVAdam/DotSource/main/Microsoft.PowerShell_profile.ps1',
        [Parameter(Mandatory = $false)]
        [uri]$PSCoreProfile = 'https://raw.githubusercontent.com/HSVAdam/DotSource/main/Microsoft.PowerShell_profile.ps1',
        [Parameter(Mandatory = $false)]
        [uri]$FontPack = 'https://github.com/ryanoasis/nerd-fonts/releases/download/v3.0.2/CascadiaCode.zip',
        [Parameter(Mandatory = $false)]
        [string]$PSRepository = 'PSGallery',
        [Parameter(Mandatory = $false)]
        [string[]]$ModuleInstall = @('Terminal-Icons', '7Zip4Powershell', 'dbatools')
    )

    BEGIN {
        #Requires -RunAsAdministrator
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    }

    PROCESS {
        TRY {
            # Profile File Setup based on PowerShell version running
            IF ($PSVersionTable.PSEdition -eq 'Core') {
                IF (!(Test-Path -Path $PROFILE -PathType Leaf)) { $null = New-Item -Path "$($env:USERPROFILE)\Documents\PowerShell" -ItemType Directory }
                Invoke-WebRequest -Uri $PSCoreProfile -OutFile "$($env:USERPROFILE)\Documents\PowerShell\Microsoft.PowerShell_profile.ps1"
            }
            IF ($PSVersionTable.PSEdition -eq 'Desktop') {
                IF (!(Test-Path -Path $PROFILE -PathType Leaf)) { $null = New-Item -Path "$($env:USERPROFILE)\Documents\WindowsPowerShell" -ItemType Directory }
                Invoke-WebRequest -Uri $PS5Profile -OutFile "$($env:USERPROFILE)\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1"
            }

            # Setup Repository
            Install-PackageProvider -Name NuGet -Force
            Set-PSRepository -Name $PSRepository -InstallationPolicy Trusted

            # Install OhMyPosh
            Set-ExecutionPolicy Bypass -Scope Process -Force; Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://ohmyposh.dev/install.ps1'))

            # Install Modules
            $ModuleInstall | ForEach-Object { Install-Module -Name $_ -Scope CurrentUser -Repository $PSRepository -Force }

            # Install Fonts
            [void] [System.Reflection.Assembly]::LoadWithPartialName('System.Drawing')
            $FontFamilies = (New-Object System.Drawing.Text.InstalledFontCollection).Families
            # Check if Cascadia Mono is installed
            IF ($FontFamilies -notcontains 'Cascadia Mono') {

                # Download and install Cascadia Mono
                $WebClient = New-Object System.Net.WebClient
                $WebClient.DownloadFile($FontPack, '.\CascadiaCode.zip')

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
        }
        CATCH {
            Write-Error $Error[0]
        }
    }

    END {
        # Reload Profile
        . $PROFILE
    }
}

Set-MyProfile