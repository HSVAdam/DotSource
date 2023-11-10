[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

#region FUNCTIONS
FUNCTION Get-PublicIP {
 (Invoke-WebRequest http://ifconfig.me/ip ).Content
}

FUNCTION Get-Uptime {
    #Windows Powershell only
    If ($PSVersionTable.PSVersion.Major -eq 5 ) {
        Get-WmiObject win32_operatingsystem |
            Select-Object @{EXPRESSION = { $_.ConverttoDateTime($_.lastbootuptime) } } | Format-Table -HideTableHeaders
    }
    Else {
        net statistics workstation | Select-String 'since' | ForEach-Object { $_.ToString().Replace('Statistics since ', '') }
    }
}

FUNCTION Parse-IISLogs {
    <#
        .SYNOPSIS
        Parses IIS server logs.

        .DESCRIPTION
        Imports IIS server logs and returns object of data.

        .PARAMETER Files
        Array of IIS logs files.

        .INPUTS
        Array

        .OUTPUTS
        System.Array

        .EXAMPLE
        PS> $Logs = Get-ChildItem | Parse-IISLogs
        PS> $Logs | Select -First 5 | FT
        date       time     s-sitename s-computername s-ip       cs-method cs-uri-stem                                                 cs-uri-query    s-port cs-username
        ----       ----     ---------- -------------- ----       --------- -----------                                                 ------------    ------ -----------
        2019-12-13 23:59:38 W3SVC2     DummyServer  192.168.1.240 GET       /Controls/media/T_small.GIF                                 -               443    -
        2019-12-13 23:59:44 W3SVC2     DummyServer  192.168.1.240 POST      /device/ServiceSetup.aspx/GetStates                         -               443    user1
        2019-12-13 23:59:38 W3SVC2     DummyServer  192.168.1.240 POST      /IssueTrackingReport.aspx                                   UserSeansCode=2 443    user4874
        2019-12-13 23:59:40 W3SVC2     DummyServer  192.168.1.240 POST      /IssueTrackingReport.aspx                                   UserSeansCode=5 443    service-accnt
        2019-12-13 23:59:42 W3SVC2     DummyServer  192.168.1.240 POST      /Adapter_Test/Service.asmx                                  -               443    -

        .LINK
        NA
    #>
    [CmdletBinding()]
    PARAM
    (
        [ValidateScript({
                IF (-Not ($_ | Test-Path) ) { THROW 'File or folder does not exist' } RETURN $true
            })]
        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true)]
        [PSCustomObject[]]$Files
    )

    BEGIN {
        $Data = @()
    }

    PROCESS {
        FOREACH ($File in $Files) {
            $ThisObject = New-Object PSObject

            # Get header data
            $Headers = @((Get-Content -Path $File -ReadCount 4 -TotalCount 4)[3].split(' ') | Where-Object { $_ -ne '#Fields:' });

            $ThisObject = Import-Csv -Delimiter ' ' -Header $Headers -Path $File | Where-Object { $_.date -notlike '#*' }

            $Data += $ThisObject
        }
    }

    END {
        RETURN $Data
    }
}

FUNCTION New-SimpleHTTP {
    <#
        .SYNOPSIS
        Creates a simple HTTP web server.
        .DESCRIPTION
        Creates a simple HTTP web server using provided port.

        .PARAMETER Port
        Port used for HTTP server.

        .INPUTS
        None. You cannot pipe objects to Add-Extension.

        .OUTPUTS
        None

        .EXAMPLE
        PS> New-SimpleHTTP -Port 5454

        .LINK
        NA
    #>
    [CmdletBinding()]
    PARAM
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [STRING]$Port
    )

    $HTTP = [System.Net.HttpListener]::new()
    $HTTP.Prefixes.Add("http://+:$Port/")
    $HTTP.Start()

    IF ($HTTP.IsListening) {
        Write-Host 'HTTP Server Online:'
        Write-Host "Address $($HTTP.Prefixes)"
    }

    WHILE ($HTTP.IsListening) {
        $Context = $HTTP.GetContext()

        IF ($Context.Request.HttpMethod -eq 'GET' -and $Context.Request.RawURL -eq '/') {
            Write-Host "$($Context.Request.UserHostAddress) => $($Context.Requesr.URL)"

            [STRING]$HTML = "<h1>Connection successful on port $Port</h1>"

            # Convert to bytes
            $Buffer = [System.Text.Encoding]::UTF8.GetBytes($HTML)
            $Context.Response.ContentLength64 = $Buffer.Length
            # Stream to browser
            $Context.Response.OutputStream.Write($Buffer, 0, $Buffer.Length)
            # Close out response
            $Context.Response.OutputStream.Close()
        }

        IF ($Context.Request.HttpMethod -eq 'GET' -and $Context.Request.RawURL -eq '/exit') {
            Write-Host "$($Context.Request.UserHostAddress) => $($Context.Requesr.URL)"

            [STRING]$HTML = "<h1>Connection successful on port $Port</h1>"

            # Convert to bytes
            $Buffer = [System.Text.Encoding]::UTF8.GetBytes($HTML)
            $Context.Response.ContentLength64 = $Buffer.Length
            # Stream to browser
            $Context.Response.OutputStream.Write($Buffer, 0, $Buffer.Length)
            # Close out response
            $Context.Response.OutputStream.Close()
            $HTTP.Stop()
        }
    }
}

FUNCTION Remove-DisconnectedRDP {
    <#
        .SYNOPSIS
        Removes disconnected RDP sessions from server.

        .DESCRIPTION
        Removes diconnected RDP sessions from servers remotely using supplied server names.

        .PARAMETER Computers
        List of computer objects to scan for disconnected RDP sessions

        .INPUTS
        Accepts piped computer names.

        .OUTPUTS
        Write-Host output of actions taken.

        .EXAMPLE
        PS> Remove-DisconnectedRDP -Computers 'server1'
        Disconnecting adam on server1

        .EXAMPLE
        PS> $servers = 'server1'
        PS> $servers | Remove-DisconnectedTDP
        Disconnecting adam on server1
    #>
    [CmdletBinding()]
    PARAM (
        [Parameter(Mandatory = $true)]
        [string] $Computers
    )

    FOREACH ($Computer in $Computers) {
        # Obtain list of all RDP sessions
        $Sessions = qwinsta /server:$Computer

        # Loop through each line
        FOREACH ($Line in $Sessions) {
            # Fine lines matching a disconnected session
            IF ($Line -match 'Disc') {
                # Split the line into an array of strings
                $Parts = $Line -split ' +'

                # Parse out information needed
                $SessionUser = $Parts[1]
                $SessionID = $Parts[2]

                # Do not try to terminate the services session
                IF ($SessionUser -ne 'services') {
                    Write-Host "Disconnecting $SessionUser on $Computer"
                    rwinsta $SessionID /server:$Computer
                }
            }
        }
    }
}

FUNCTION Search-String {
    <#
        .SYNOPSIS
        Searches txt based files for supplied string.
        .DESCRIPTION
        Searches plain text files for supplied string.
        .PARAMETER Folder
        Folder containing files to be searched.
        .PARAMETER Search
        String to search for within files.
		.PARAMETER Recurse
		Bool to recurse search folder structure or not.
        .INPUTS
        None. You cannot pipe objects to Add-Extension.
        .OUTPUTS
        Array
        .EXAMPLE
        PS> Search-String -Folder 'D:\Logs\DataCollector' -Search 'Apples' -Recurse:$false
		.LINK
		NA
    #>
    [CmdletBinding()]
    PARAM (
        [Parameter(Mandatory = $true, Position = 1)]
        [string]$Search,
        [Parameter(Mandatory = $false, Position = 2)]
        [System.IO.FileInfo]$Folder = '.',
        [Parameter(Mandatory = $false, Position = 3)]
        [switch]$Recurse
    )

    IF ($Recurse.IsPresent) {
        Get-ChildItem -Path $Folder -Recurse | Select-String $Search | Select-Object LineNumber, Path, @{ Name = 'LineText'; Expression = { $_.Line.Trim() } } | Sort-Object Path

    }
    ELSE {
        Get-ChildItem -Path $Folder | Select-String $Search | Select-Object LineNumber, Path, @{ Name = 'LineText'; Expression = { $_.Line.Trim() } } | Sort-Object Path
    }
}

FUNCTION Test-TLSConnection {
    <#
    .Synopsis
        Test if a TLS Connection can be established.
    .DESCRIPTION
        This function uses System.Net.Sockets.Tcpclient and System.Net.Security.SslStream to connect to a ComputerName and
        authenticate via TLS. This is useful to check if a TLS connection can be established and if the certificate used on
        the remote computer is trusted on the local machine.
        If the connection can be established, the certificate's properties will be output as custom object.
        Optionally the certificate can be downloaded using the -SaveCert switch.
        The Protocol parameter can be used to specifiy which SslProtocol is used to perform the test. The CheckCertRevocationStatus parameter
        can be used to disable revocation checks for the remote certificate.
    .EXAMPLE
        Test-TlsConnection -ComputerName www.ntsystems.it

        This example connects to www.ntsystems.it on port 443 (default) and outputs the certificate's properties.
    .EXAMPLE
        Test-TlsConnection -ComputerName sipdir.online.lync.com -Port 5061 -Protocol Tls12 -SaveCert

        This example connects to sipdir.online.lync.com on port 5061 using TLS 1.2 and saves the certificate to the temp folder.
    .EXAMPLE
        Test-TlsConnection -IPAddress 1.1.1.1 -ComputerName whatever.cloudflare.com

        This example connects to the IP 1.1.1.1 using a Hostname of whatever.cloudflare.com. This can be useful to test hosts that don't have DNS records configured.
    .EXAMPLE
        "host1.example.com","host2.example.com" | Test-TLSConnection -Protocol Tls11 -Quiet

        This example tests connection to the hostnames passed by pipeline input. It uses the -Quiet parameter and therefore only returns true/flase.
    #>
    [CmdletBinding(HelpUri = 'https://ntsystems.it/PowerShell/TAK/Test-TLSConnection/')]
    [Alias('ttls')]
    [OutputType([psobject], [bool])]
    param (
        # Specifies the DNS name of the computer to test
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [Alias('Server', 'Name', 'HostName')]
        $ComputerName,

        # Specifies the IP Address of the computer to test. Can be useful if no DNS record exists.
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [System.Net.IPAddress]
        $IPAddress,

        # Specifies the TCP port on which the TLS service is running on the computer to test
        [Parameter(Mandatory = $false,
            Position = 1)]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [Alias('RemotePort')]
        [ValidateRange(1, 65535)]
        $Port = '443',

        # Specifies a path to a file (.cer) where the certificate should be saved if the SaveCert switch parameter is used
        [Parameter(Mandatory = $false,
            Position = 3)]
        [System.IO.FileInfo]
        $FilePath = "$env:TEMP\$computername.cer",

        [Parameter(Mandatory = $false,
            Position = 2)]
        [ValidateNotNullOrEmpty()]
        [ValidateSet('Default', 'Ssl2', 'Ssl3', 'Tls', 'Tls11', 'Tls12', 'Tls13')]
        [System.Security.Authentication.SslProtocols[]]
        $Protocol = 'Tls12',

        # Check revocation information for remote certificate. Default is true.
        [Parameter(Mandatory = $false)]
        [bool]$CheckCertRevocationStatus = $true,

        # Saves the remote certificate to a file, the path can be specified using the FilePath parameter
        [switch]
        $SaveCert,

        # Only returns true or false, instead of a custom object with some information.
        [Alias('Silent')]
        [switch]
        $Quiet
    )

    begin {
        function Get-SanAsArray {
            param($io)
            $io.replace('DNS Name=', '').split("`n")
        }
    }

    process {
        if (-not($IPAddress)) {
            # if no IP is specified, use the ComputerName
            [string]$IPAddress = $ComputerName
        }

        try {
            $TCPConnection = New-Object System.Net.Sockets.Tcpclient($($IPAddress.ToString()), $Port)
            Write-Verbose 'TCP connection has succeeded'
            $TCPStream = $TCPConnection.GetStream()
            try {
                $SSLStream = New-Object System.Net.Security.SslStream($TCPStream)
                Write-Verbose "SSL connection has succeeded with $($SSLStream.SslProtocol)"
                try {
                    # AuthenticateAsClient (string targetHost, X509CertificateCollection clientCertificates, SslProtocols enabledSslProtocols, bool checkCertificateRevocation)
                    $SSLStream.AuthenticateAsClient($ComputerName, $null, $Protocol, $CheckCertRevocationStatus)
                    Write-Verbose 'SSL authentication has succeeded'
                }
                catch {
                    Write-Warning "There's a problem with SSL authentication to $ComputerName `n$_"
                    Write-Warning "Tried to connect using $Protocol protocol. Try another protocol with the -Protocol parameter."
                    return $false
                }
                $certificate = $SSLStream.get_remotecertificate()
                $certificateX509 = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($certificate)
                $SANextensions = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection($certificateX509)
                $SANextensions = $SANextensions.Extensions | Where-Object { $_.Oid.FriendlyName -eq 'subject alternative name' }

                $data = [ordered]@{
                    'ComputerName'    = $ComputerName;
                    'Port'            = $Port;
                    'Protocol'        = $SSLStream.SslProtocol;
                    'KeyExchange'     = SWITCH ($SSLStream.KeyExchangeAlgorithm) { '44550' { 'ECDH_Ephem' } }
                    'CipherAlgorithm' = $SSLStream.CipherAlgorithm
                    'Encrypted'       = $SSLStream.IsEncrypted
                    'Hash'            = $SSLStream.HashAlgorithm
                    'CheckRevocation' = $SSLStream.CheckCertRevocationStatus;
                    'Issuer'          = $SSLStream.RemoteCertificate.Issuer;
                    'Subject'         = $SSLStream.RemoteCertificate.Subject;
                    'SerialNumber'    = $SSLStream.RemoteCertificate.GetSerialNumberString();
                    'ValidTo'         = $SSLStream.RemoteCertificate.GetExpirationDateString();
                    'SAN'             = (Get-SanAsArray -io $SANextensions.Format(1));
                }

                if ($Quiet) {
                    Write-Output $true
                }
                else {
                    Write-Output (New-Object -TypeName PSObject -Property $Data)
                }
                if ($SaveCert) {
                    Write-Host "Saving cert to $FilePath" -ForegroundColor Yellow
                    [system.io.file]::WriteAllBytes($FilePath, $certificateX509.Export('cer'))
                }

            }
            catch {
                Write-Warning "$ComputerName doesn't support SSL connections at TCP port $Port `n$_"
            }

        }
        catch {
            $exception = New-Object System.Net.Sockets.SocketException
            $errorcode = $exception.ErrorCode
            Write-Warning "TCP connection to $ComputerName failed, error code:$errorcode"
            Write-Warning "Error details: $exception"
        }

    } # process

    end {
        # cleanup
        Write-Verbose 'Cleanup sessions'
        if ($SSLStream) {
            $SSLStream.Dispose()
        }
        if ($TCPStream) {
            $TCPStream.Dispose()
        }
        if ($TCPConnection) {
            $TCPConnection.Dispose()
        }
    }
}

FUNCTION Copy-FolderStructure {
    <#
        .SYNOPSIS
        Copy folder structure from a to b

        .DESCRIPTION
        Exactly replicates a folder structure from source to destination with no files

        .PARAMETER Source
        The source folder to clone

        .PARAMETER Destination
        The blank destination folder to build source structure

        .INPUTS
        Does not accept piping

        .OUTPUTS
        None

        .EXAMPLE
        PS> Copy-FolderStructure -Source C:\Logs -Destination D:\

        .LINK
    #>
    [CmdletBinding()]
    PARAM
    (
        [Parameter(Mandatory = $true)]
        [ValidateScript({ IF (Test-Path $_) { $true } ELSE { THROW "Path $_ is not valid" } })]
        [string]$Source,
        [Parameter(Mandatory = $true)]
        [ValidateScript({ IF (Test-Path $_) { $true } ELSE { THROW "Path $_ is not valid" } })]
        [string]$Destination
    )

    Get-ChildItem $Source -Recurse | Where-Object { $_.PSIsContainer } | `
            ForEach-Object {
            $TargetFolder = $Destination + $_.FullName.SubString($Source.Length);
            New-Item -ItemType Directory -Path $TargetFolder -Force;
        }
}

FUNCTION Backup-Code {
    <#
        .SYNOPSIS
        Performs a backup of the supplied folder.
        .DESCRIPTION
        Performs a full backup of the supplied folder with the option to exclude files/folders and the ability to auto zip.
        .PARAMETER Source
        Root folder of files to backup.
        .PARAMETER Destination
        Destination folder to copy files and folders to.
        .PARAMETER ExcludeAudio
        Switch designed to supress the copy of wav files
        .PARAMETER ExcludeConfigs
        Excludes the web.config and appsettings.json files from the backup.
        .PARAMETER Zip
        Performs a zip of all backed up files to your desktop.
        .PARAMETER DeleteBackupFiles
        After a successful zip will remove the backup folder from your desktop, parameter will be ignored if the zip parameter is not used.
        .EXAMPLE
        PS> Backup-Code -Source 'D:\inetpub\wwwroot'
        .EXAMPLE
        PS> Backup-Code -Source 'D:\inetpub\wwwroot' -ExcludeAudio -ExcludeConfigs -Zip -DeleteBackupFiles
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateScript({ IF ( -Not ($_ | Test-Path) ) { THROW 'Source does not exist.' } RETURN $true })]
        [System.IO.FileInfo]$Source,
        [Parameter(Mandatory = $false)]
        [System.IO.FileInfo]$Destination = ([Environment]::GetFolderPath('Desktop') + "\$($env:COMPUTERNAME)-CodeBackup-$(Get-Date -Format 'yyyyMMdd')"),
        [Parameter(Mandatory = $false)]
        [switch]$ExcludeAudio,
        [Parameter(Mandatory = $false)]
        [switch]$ExcludeConfigs,
        [Parameter(Mandatory = $false)]
        [switch]$Zip,
        [Parameter(Mandatory = $false, HelpMessage = 'Delete the backup files after successful zip, will only function if zip is also requested.')]
        [switch]$DeleteBackupFiles
    )

    BEGIN {
        $Exclude = @('dummyfile.file')
        IF ($ExcludeConfigs) { $Exclude += 'web.config', 'appsettings.json' }
        $ExcludeMatch = @('Processed', 'Failed', '_chart_temp', 'Unknown')
        IF ($ExcludeAudio) { $Exclude += '*.wav', '*.mp3', '*.m4a' }
        [regex]$ExcludeMatchRegEx = '(?i)' + (($ExcludeMatch | ForEach-Object { [regex]::escape($_) }) -join '|') + ''
    }

    PROCESS {
        TRY {
            # Ensure destination folder exists, if not create it
            IF (!(Test-Path -Path $Destination)) { $null = New-Item -Path $Destination -ItemType Directory -Force }

            # Get collection of all objects to backup
            $Objects = Get-ChildItem -Path $Source -Recurse -Exclude $Exclude | Where-Object { $null -eq $ExcludeMatch -or $_.FullName.Replace($Source.FullName, '') -notmatch $ExcludeMatchRegEx }

            # Process each object individually, copy over as needed
            FOREACH ($Object in $Objects) {
                IF ($Object -is [System.IO.DirectoryInfo]) {
                    Write-Host "[+] $(Join-Path -Path $Destination $Object.Parent.FullName.Substring($Source.FullName.Length))"
                    Copy-Item -Path $Object.FullName -Destination (Join-Path -Path $Destination $Object.Parent.FullName.Substring($Source.FullName.Length)) -Exclude $Exclude
                }
                ELSE {
                    Write-Host "[-] $(Join-Path -Path $Destination $Object.FullName.Substring($Source.FullName.Length))"
                    Copy-Item -Path $Object.FullName -Destination (Join-Path -Path $Destination $Object.FullName.Substring($Source.FullName.Length)) -Exclude $Exclude
                }
            }

            # If zip switch is requested, zip files
            IF ($Zip.IsPresent) {
                Compress-Archive -Path "$($Destination)\*" -CompressionLevel Fastest -DestinationPath ([Environment]::GetFolderPath('Desktop') + "\$($env:COMPUTERNAME)-CodeBackup-$(Get-Date -Format 'yyyyMMdd').zip")

                # If delete backup files is requested ensure zip files is created, then delete folder
                IF ($DeleteBackupFiles.IsPresent -and (Test-Path -Path ([Environment]::GetFolderPath('Desktop') + "\$($env:COMPUTERNAME)-CodeBackup-$(Get-Date -Format 'yyyyMMdd').zip"))) {
                    Get-Item -Path ([Environment]::GetFolderPath('Desktop') + "\$($env:COMPUTERNAME)-CodeBackup-$(Get-Date -Format 'yyyyMMdd')") | Remove-Item -Recurse -Force
                }
            }
        }
        CATCH {
            Write-Error $Error[0]
        }
    }

    END {

    }
}

FUNCTION Copy-IISConfigFiles {
    <#
        .SYNOPSIS
        Copies IIS configuration files from wwwroot folder

        .DESCRIPTION
        Generates copies of IIS configuration files while retaining directory structure

        .PARAMETER Source
        The source folder with IIS files

        .PARAMETER Destination
        The destination for code backup

        .PARAMETER Files
        Default set to @('*.config', 'appsettings.json') but can be changed with parameter

        .INPUTS
        Does not accept piping

        .OUTPUTS
        None

        .EXAMPLE
        PS> Copy-IISConfigFiles -Source C:\inetpub\wwwroot\ -Destination D:\Backups

        .EXAMPLE
        PS> Copy-IISConfigFiles -Source C:\inetpub\wwwroot\ -Destination D:\Backups -Files $Files = @('*.jpg', '*.gif', 'appsettings.json')

        .LINK
    #>
    [CmdletBinding()]
    PARAM
    (
        [Parameter(Mandatory = $true)]
        [ValidateScript({ IF (Test-Path $_) { $true } ELSE { THROW "Path $_ is not valid" } })]
        [string]$Source,
        [Parameter(Mandatory = $true)]
        [ValidateScript({ IF (Test-Path $_) { $true } ELSE { THROW "Path $_ is not valid" } })]
        [string]$Destination,
        [Parameter(Mandatory = $false)]
        $Files = @('*.config', 'appsettings.json')
    )

    Get-ChildItem -Path $Source -Recurse -Include $Files | `
            ForEach-Object {
            $TargetFile = $Destination + $_.FullName.SubString($Source.Length);
            New-Item -Path $TargetFile -ItemType File -Force;
            Copy-Item $_.FullName -Destination $TargetFile
        }
}

FUNCTION Get-DotNetFramework() {
    # loop through various keys .Net has used over the years

    $versions = @('v4\Client', 'v4\Full', 'v3.5', 'v3.0', 'v2.0.50727', 'v1.1.4322') |
        ForEach-Object {
            $parenthPath = "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\$($_)"

            # loop through each key and get propreties
            Get-ChildItem $parenthPath -ea SilentlyContinue | ForEach-Object {
                $arr = $($_.PsPath).Split('\')
                $regPath = $arr[1..$arr.Count] -join ('\')

                # filter keys
                Get-ItemProperty $regPath |
                    Where-Object { ($null -ne $_.version) -and ($_.install -eq 1) } |

                        # select desired properties
                        Select-Object @{n = 'Name'; e = { 'Microsoft .Net Framework' } },
                        Version, Release
                    }
                }

    $versions
}
#endregion FUNCTIONS

#region ALIASES
New-Alias -Name git -Value "$Env:ProgramFiles\Git\bin\git.exe"
New-Alias -Name ngen -Value 'C:\Windows\Microsoft.NET\Framework64\v4.0.30319\ngen.exe'
#endregion ALIASES

Set-PSReadLineKeyHandler -Key UpArrow -Function HistorySearchBackward
Set-PSReadLineKeyHandler -Key DownArrow -Function HistorySearchForward
Set-PSReadLineOption -HistorySearchCursorMovesToEnd

Import-Module -Name Terminal-Icons
oh-my-posh init pwsh --config "$env:POSH_THEMES_PATH\emodipt-extend.omp.json" | Invoke-Expression