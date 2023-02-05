Clear-Host
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Determine if OneDrive exists to define start location
IF ($OneDrive = Get-ChildItem -Path $UserProfileFolder | Where-Object { $_.Name -like 'OneDrive*'}) {
    Set-Location -Path (Join-Path -Path $OneDrive.FullName -ChildPath 'GiT')
}

Import-Module -Name Terminal-Icons
oh-my-posh init pwsh --config 'https://raw.githubusercontent.com/JanDeDobbeleer/oh-my-posh/main/themes/craver.omp.json' | Invoke-Expression

New-Alias -Name git -Value "$Env:ProgramFiles\Git\bin\git.exe"
New-Alias -Name ngen -Value 'C:\Windows\Microsoft.NET\Framework64\v4.0.30319\ngen.exe'