# Set our varaibles
$UserProfileFolder = $ENV:USERPROFILE
$DocumentsFolder = [Environment]::GetFolderPath('MyDocuments')
$PWSH5Root = Join-Path -Path $DocumentsFolder -ChildPath 'WindowsPowerShell'
$PWSH7Root = Join-Path -Path $DocumentsFolder -ChildPath 'PowerShell'
$VSCodeRoot = Join-Path -Path $UserProfileFolder -ChildPath 'AppData\Roaming\Code\User'

# Ensure OhMyPosh is installed
IF (!(Get-Command oh-my-posh.exe)) {
    IF (Get-Command WinGet) {
        & winget install JanDeDobbeleer.OhMyPosh -s winget
    }
    ELSE {
        Write-Host 'Please install WinGet and re-run this script.'
        BREAK;
    }
}

# Lets begin downloading our dotSource files
# PowerShell 5
Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/HSVAdam/DotSource/main/PWSH5/Microsoft.PowerShell_profile.ps1' -OutFile "$PWSH5Root\Microsoft.PowerShell_profile.ps1"

#PowerShell 7
Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/HSVAdam/DotSource/main/PWSH7/Microsoft.PowerShell_profile.ps1' -OutFile "$PWSH7Root\Microsoft.PowerShell_profile.ps1"

# VSCode
Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/HSVAdam/DotSource/main/VSCode/settings.json' -OutFile "$VSCodeRoot\settings.json"