$currentVersion = [double]'12'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$scriptPath = $MyInvocation.MyCommand.Path
$workingDirectory = Split-Path -Path $scriptPath
$configPath = Join-Path -Path $workingDirectory -ChildPath 'config.xml'
$logFile = Join-Path -Path $workingDirectory -ChildPath 'output.log'
$logFileContent = Get-Content -Path $logFile

[xml]$scriptConfig = Get-Content -Path $configPath

if ($scriptConfig.Configuration.NoProxy) {
    [System.Net.WebRequest]::DefaultWebProxy = [System.Net.GlobalProxySelection]::GetEmptyWebProxy()
}

function Log {
    param (
        [string]$message
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp - $message" | Add-Content -Path $logFile
}

function Backup-CurrentScript {
    $backupDirectory = Join-Path -Path $workingDirectory -ChildPath 'Backup'

    try {
        if (-not (Test-Path -Path $backupDirectory)) {
            New-Item -Path $backupDirectory -ItemType Directory
        }
    }
    catch {
        Log "Failed to create backup directory: $backupDirectory"
        return $false
    }

    $backupFileName = "doctool-collector_v${currentVersion}.ps1.old"
    try {
        $copiedItem = Copy-Item -Path $scriptPath -Destination $backupDirectory\$backupFileName -Force -PassThru
        Log "Backup created at: $copiedItem"
        return $true
    }
    catch {
        Log "Failed to create backup. Error: $_"
        return $false
    }

}

function Update-Script {

    $currentTime = Get-Date

    try {
        $lastUpdateCheck = [DateTime]::ParseExact($scriptConfig.Configuration.LastUpdateCheck, 'yyyy-MM-ddTHH:mm:ss', $null)
        Log "Last update check found."
    }
    catch {
        Log "Last update check element not found, setting default date."
        $lastUpdateCheck = [DateTime](Get-Date "2000-01-01T00:00:00")
    }

    $timeDifference = New-TimeSpan -Start $lastUpdateCheck -End $currentTime

    if ($timeDifference.TotalMinutes -lt 10) {
        Log "Last update check was less than 10 minutes ago. Skipping update check."
        return
    }
    else {
        try {
            $apiPath = "https://api.github.com/repos/doctool/doctool-collector/releases/latest"
            $release = Invoke-RestMethod -Uri $apiPath -UseBasicParsing

            $latestVersion = $release.tag_name.Trim()
            if ($latestVersion.StartsWith('v')) {
                $latestVersion = [double]$latestVersion.Substring(1)
            }

            Log "Latest script version: $latestVersion"
        }
        catch {
            Log "Failed to check for updates. Error: $_"
        }

        if (-not $scriptConfig.Configuration.LastUpdateCheck) {
            Log "Last update check element not found. Creating new element."
            $xmlElement = $scriptConfig.CreateElement("LastUpdateCheck")
            $xmlElement.InnerText = $currentTime.ToString("yyyy-MM-ddTHH:mm:ss")
            $scriptConfig.Configuration.AppendChild($xmlElement)
        }
        else {
            $scriptConfig.Configuration.LastUpdateCheck = $currentTime.ToString("yyyy-MM-ddTHH:mm:ss")
        }
        $scriptConfig.Save($configPath)

        if ($currentVersion -ge $latestVersion) {
            Log "The script is up to date."
        }
        else {
            Log "Updating script..."

            $asset = $release.assets | Where-Object { $_.name -eq 'doctool-collector.ps1' }

            if ($null -ne $asset) {
                if (-not (Backup-CurrentScript)) {
                    Log "Backup failed. Aborting update."
                    return
                }
    
                $downloadUrl = $asset.browser_download_url
                $tempPath = Join-Path $env:TEMP $asset.name
    
                Invoke-WebRequest -Uri $downloadUrl -OutFile $tempPath
                Copy-Item -Path $tempPath -Destination $scriptPath -Force
                Log "Script updated to version $latestVersion, restarting."
                & $scriptPath
                exit
            }
            else {
                Log "No script asset found in the release."
            }   
        }
    }
}

function New-ApiCall {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Endpoint,

        [Parameter(Mandatory = $false)]
        [object]$Body,

        [Parameter(Mandatory = $true)]
        [string]$Method = 'get'
    )
    
    $url = $scriptConfig.Configuration.ApiBaseUrl + $Endpoint
    $apiKey = $scriptConfig.Configuration.ApiKey

    $headers = @{
        'Authorization' = "Bearer $apiKey"
        'Accept'        = 'application/json'
    }

    if ($null -ne $Body) {
        $jsonBody = $Body | ConvertTo-Json -Compress -Depth 5
        $headers['Content-Type'] = 'application/json'
    }
    
    Log "Attempting to send API request to: $url"
    try {
        $response = Invoke-RestMethod -Uri $url -Method $Method -Headers $Headers -Body $jsonBody -ContentType 'application/json'
        Log "Success!"
    }
    catch {
        Log "Invoke-RestMethod failed. Error: $($_.Exception.Message)"
        if ($_.Exception.InnerException) {
            Log "Inner exception: $($_.Exception.InnerException.Message)"
        }
        if ($_.Exception.Response -and $_.Exception.Response.StatusCode -eq 422) {
            try {
                # Capture the raw response content and parse the JSON
                $errorResponse = $_.Exception.Response.GetResponseStream() | % { [System.IO.StreamReader]::new($_).ReadToEnd() }
                $parsedError = $errorResponse | ConvertFrom-Json
    
                # Output the error message
                Log "HTTP 422 Error Message: $($parsedError.message)"
            }
            catch {
                Log "Failed to capture the raw response. Error: $($_.Exception.Message)"
            }
        }
        else {
            try {
                Log "Invoke-RestMethod failed. Attempting Invoke-WebRequest..."
                $webResponse = Invoke-WebRequest -Uri $url -Method $Method -Headers $Headers -Body $jsonBody -ContentType 'application/json'
                Log "Fallback to Invoke-WebRequest succeeded. Status code: $($webResponse.StatusCode)"
            }
            catch {
                if ($_.Exception -and $_.Exception.Response -and $_.Exception.Response.StatusCode) {
                    $statusCode = $_.Exception.Response.StatusCode.value__
                    $statusDescription = $_.Exception.Response.StatusDescription
                    Log "Invoke-WebRequest failed with status code ${statusCode}: ${statusDescription}"
                }
                else {
                    Log "Invoke-WebRequest failed. Error: $($_.Exception.Message)"
                    if ($_.Exception.InnerException) {
                        Log "Inner exception: $($_.Exception.InnerException.Message)"
                    }
                }
            }
        }
    }
}

#Get network address from IP and subnet mask
function Get-NetworkAddress {
    param (
        [Parameter(Mandatory = $true)]
        [string]$IPAddress,
        
        [Parameter(Mandatory = $true)]
        [string]$SubnetMask
    )

    # Convert the IP address and subnet mask to byte arrays
    $ipBytes = [System.Net.IPAddress]::Parse($IPAddress).GetAddressBytes()
    $maskBytes = [System.Net.IPAddress]::Parse($SubnetMask).GetAddressBytes()

    # Perform the bitwise AND operation to calculate the network address
    $networkBytes = [byte[]]@(0, 0, 0, 0)
    for ($i = 0; $i -lt $ipBytes.Length; $i++) {
        $networkBytes[$i] = $ipBytes[$i] -band $maskBytes[$i]
    }

    # Convert the result back to an IP address
    $networkAddress = [System.Net.IPAddress]::new($networkBytes)

    return $networkAddress.IPAddressToString
}

# Function to calculate the network range based on IP address and subnet mask
function Get-NetworkRange {
    param (
        [string]$ipAddress,
        [string]$subnetMask
    )

    # Convert the IP address and subnet mask into byte arrays
    $ipBytes = [System.Net.IPAddress]::Parse($ipAddress).GetAddressBytes()
    $maskBytes = [System.Net.IPAddress]::Parse($subnetMask).GetAddressBytes()

    # Calculate the network address by performing bitwise AND between IP and subnet mask
    $networkBytes = @()
    for ($i = 0; $i -lt 4; $i++) {
        $networkBytes += $ipBytes[$i] -band $maskBytes[$i]
    }

    # Calculate the first and last IP address in the range
    $firstIPBytes = $networkBytes.Clone()
    $lastIPBytes = $networkBytes.Clone()

    for ($i = 0; $i -lt 4; $i++) {
        $lastIPBytes[$i] = $networkBytes[$i] -bor ($maskBytes[$i] -bxor 255)
    }

    # Convert byte arrays back into IP addresses
    $firstIP = [System.Net.IPAddress]::new($firstIPBytes)
    $lastIP = [System.Net.IPAddress]::new($lastIPBytes)

    # Return the first and last IP as a hashtable
    return @{
        FirstIP = $firstIP.ToString()
        LastIP  = $lastIP.ToString()
    }
}

# Convert IP addresses to integers for easy range iteration
function Convert-IPToInt {
    param ([string]$ipAddress)
    $bytes = [System.Net.IPAddress]::Parse($ipAddress).GetAddressBytes()
    
    # Check if the system is little-endian, and reverse the byte array if necessary
    if ([BitConverter]::IsLittleEndian) {
        [Array]::Reverse($bytes)
    }
    
    return [BitConverter]::ToUInt32($bytes, 0)
}

# Convert integer back to IP address
function Convert-IntToIP {
    param ([uint32]$intAddress)
    $bytes = [BitConverter]::GetBytes($intAddress)

    # Reverse the byte array again if the system is little-endian
    if ([BitConverter]::IsLittleEndian) {
        [Array]::Reverse($bytes)
    }

    return [System.Net.IPAddress]::new($bytes).ToString()
}

# Function to resolve hostname from IP address
function Get-Hostname {
    param (
        [string]$ipAddress
    )
    try {
        # Try to resolve the hostname using DNS lookup
        $hostEntry = [System.Net.Dns]::GetHostEntry($ipAddress)
        return $hostEntry.HostName
    }
    catch {
        # If the hostname cannot be resolved, return "Unknown"
        return "Unknown"
    }
}

function Convert-SubnetMaskToCIDR {
    param ([string]$subnetMask)

    $maskBytes = [System.Net.IPAddress]::Parse($subnetMask).GetAddressBytes()
    $binaryMask = ($maskBytes | ForEach-Object { [Convert]::ToString($_, 2).PadLeft(8, '0') }) -join ''
    return ($binaryMask -split '1').Length - 1
}

function Test-TCPPort {
    #Derived from https://copdips.com/2019/09/fast-tcp-port-check-in-powershell.html
    param (
        [string]$ipAddress,
        [int]$port,
        [int]$timeout = 1000
    )

    $result = [System.Collections.ArrayList]::new()

    if ($port -lt 1 -or $port -gt 65535) {
        throw "Invalid port number: $port"
    }

    if ($timeout -lt 1) {
        throw "Timeout value must be greater than 0"
    }

    if (-not $ipAddress) {
        throw "IP address cannot be null or empty"
    }

    $tcpClient = New-Object System.Net.Sockets.TcpClient
    $portOpened = $tcpClient.ConnectAsync($ipAddress, $port).Wait($timeout)

    $null = $result.Add([PSCustomObject]@{
            IPAddress        = $ipAddress
            Protocol         = 'TCP'
            Port             = $port
            TcpTestSucceeded = $portOpened
        })

    return $result
}

function Test-UDPPort {
    param (
        [string]$ipAddress,
        [int]$port,
        [int]$timeout = 1000
    )

    $result = [System.Collections.ArrayList]::new()

    if ($port -lt 1 -or $port -gt 65535) {
        throw "Invalid port number: $port"
    }

    if ($timeout -lt 1) {
        throw "Timeout value must be greater than 0"
    }

    if (-not $ipAddress) {
        throw "IP address cannot be null or empty"
    }

    $udpClient = New-Object System.Net.Sockets.UdpClient
    $udpClient.Client.SendTimeout = $timeout
    $udpClient.Client.ReceiveTimeout = $timeout

    try {
        # Send a simple byte message to the UDP port
        $sendBytes = # Example payload, just sending the byte for 'A'
        $remoteEndPoint = New-Object System.Net.IPEndPoint ([System.Net.IPAddress]::Parse($ipAddress), $port)

        # Send the packet
        $udpClient.Send($sendBytes, $sendBytes.Length, $remoteEndPoint)

        # Wait to receive a response (blocking)
        $receiveResult = $udpClient.Receive([ref]$remoteEndPoint)

        $udpTestSucceeded = $true
    }
    catch {
        # If we hit a timeout or another error, consider the port unreachable
        $udpTestSucceeded = $false
    }
    finally {
        $udpClient.Close()
    }

    $null = $result.Add([PSCustomObject]@{
            IPAddress        = $ipAddress
            Protocol         = 'UDP'
            Port             = $port
            UdpTestSucceeded = $udpTestSucceeded
        })

    return $result
}


# Function to check if HTTP is available on the device and get the page title
function Get-HttpTitle {
    param (
        [string]$ipAddress
    )

    # Test if port 80 is open
    $httpConnection = Test-TCPPort -IPAddress $ipAddress -Port 80

    if ($httpConnection.TcpTestSucceeded) {
        try {
            # Send an HTTP request and capture the title
            $response = Invoke-WebRequest -Uri "http://$ipAddress" -UseBasicParsing -TimeoutSec 5
            $htmlContent = $response.Content

            # Regex to check for meta refresh tag
            $metaRefreshPattern = '<meta\s+http-equiv=["'']refresh["'']\s+content=["''][^"'']*url=(?<url>[^"'']+)["'']'
            $metaRefreshMatch = [regex]::Match($htmlContent, $metaRefreshPattern)

            if ($metaRefreshMatch.Success) {
                $refreshUrl = $metaRefreshMatch.Groups['url'].Value
                # Follow the meta refresh
                $response = Invoke-WebRequest -Uri "http://$ipAddress$refreshUrl" -UseBasicParsing -TimeoutSec 5
                $htmlContent = $response.Content
            }

            # Extract the title using regex
            $titlePattern = '<title>(?<title>.*?)<\/title>'
            $titleMatch = [regex]::Match($htmlContent, $titlePattern)

            if ($titleMatch.Success) {
                return @{
                    port     = 80
                    protocol = "TCP"
                    state    = "Open"
                    detail   = "Title: '$($titleMatch.Groups['title'].Value)'"
                }
            }
            else {
                return @{
                    port     = 80
                    protocol = "TCP"
                    state    = "Open"
                    detail   = "No title found"
                }
            }
        }
        catch {
            return @{
                port     = 80
                protocol = "TCP"
                state    = "Open"
                detail   = "Unable to retrieve title"
            }
        }
    }
    else {
        return @{
            port     = 80
            protocol = "TCP"
            state    = "Closed"
        }
    }
}

function Test-UUID {
    param (
        [string]$UUID
    )

    $uuidRegex = '^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[1-5][a-fA-F0-9]{3}-[89abAB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}$'

    return $UUID -match $uuidRegex
}

Update-Script

if($logFileContent.Count -gt 10000) {
    $lines = $logFileContent | Select-Object -Last 10000
    $lines | Set-Content -Path $logFile
    Log "Log file trimmed to 10000 lines."
}

$productType = (Get-CimInstance -ClassName Win32_OperatingSystem).ProductType

# if the product is a server
if ($productType -eq 2 -or $productType -eq 3) {

    $hostname = (Get-ComputerInfo).CsDNSHostName
    $fullHostname = [System.Net.Dns]::GetHostByName($env:COMPUTERNAME).HostName
    $biosSerialNumber = (Get-CimInstance -ClassName Win32_BIOS).SerialNumber
    $osVersion = Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber, OSArchitecture
    if (($scriptConfig.Configuration.DeviceUuid) -and (Test-UUID($scriptConfig.Configuration.DeviceUuid))) {
        $osUuid = $scriptConfig.Configuration.DeviceUuid
    }
    else {
        $osUuid = (Get-CimInstance -ClassName Win32_ComputerSystemProduct).UUID
    }
    $cpuSockets = (Get-CimInstance -ClassName Win32_ComputerSystem).NumberOfProcessors
    if ($cpuSockets -eq 1) {
        $cpu = (Get-CimInstance -ClassName Win32_Processor).Name
    }
    else {
        $cpu = "2x " + (Get-CimInstance -ClassName Win32_Processor).Name
    }
    $totalCores = (Get-CimInstance -ClassName Win32_Processor | Measure-Object -Property NumberOfCores -Sum).Sum
    $totalMemory = (Get-CimInstance -ClassName Win32_ComputerSystem).TotalPhysicalMemory
    $manufacturer = (Get-CimInstance -ClassName Win32_ComputerSystem).Manufacturer
    $model = (Get-CimInstance -ClassName Win32_ComputerSystem).Model
    $fixedDisks = Get-Volume | Where-Object { ($_.DriveLetter -ne $null) -and ($_.DriveType -eq 'Fixed') }

    $shadowCopies = Get-CimInstance -ClassName Win32_ShadowCopy | Select-Object VolumeName, DeviceObject

    $fixedDisks = Get-Volume | Where-Object { ($_.DriveLetter -ne $null) -and ($_.DriveType -eq 'Fixed') }
    $shadowCopies = Get-CimInstance -ClassName Win32_ShadowCopy

    $lastBootTime = (Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime

    $fixedDisksInfo = foreach ($disk in $fixedDisks) {
        # Check if there's a shadow copy for the volume by matching VolumeName with Path
        $hasShadowCopy = ($shadowCopies | Where-Object { $_.VolumeName -eq $disk.Path }).Count -gt 0
    
        # Construct the output object for the disk
        [PSCustomObject]@{
            volume_identifier = $disk.DriveLetter
            file_system_label = $disk.FileSystemLabel
            size              = $disk.Size
            size_remaining    = $disk.SizeRemaining
            file_system_type  = $disk.FileSystemType
            has_shadow_copy   = $hasShadowCopy
        }
    }


    $networkInfo = @()
    $networkAdapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" } 

    foreach ($adapter in $networkAdapters) {
    
        $ipConfig = Get-NetIPAddress -InterfaceIndex $adapter.InterfaceIndex -AddressFamily IPv4
        $dnsServers = Get-DnsClientServerAddress -InterfaceIndex $adapter.InterfaceIndex -AddressFamily IPv4
        $gateway = (Get-NetIPConfiguration -InterfaceIndex $adapter.InterfaceIndex).Ipv4DefaultGateway
    
        foreach ($ip in $ipConfig) {
            $dhcpEnabled = if ($ip.PrefixOrigin -eq "Dhcp") { $true } else { $false }
        
            $obj = [PSCustomObject]@{
                adapter_name         = $adapter.Name
                ip_address           = $ip.IPAddress
                subnet_prefix_length = $ip.PrefixLength
                dhcp_enabled         = $dhcpEnabled
                dns_servers          = $dnsServers.ServerAddresses -join ', '
                mac_address          = $adapter.MacAddress
                gateway              = $gateway.NextHop
            }
    
            $networkInfo += $obj
        }
    }

    # If Hyper-V is installed
    if (((Get-WmiObject -Class Win32_ComputerSystem).DomainRole).Installed -eq $true) {

        Import-Module Hyper-V
        $hyperVInfo = @()

        $VMs = Get-VM
        foreach ($VM in $VMs) {
            $VHDs = Get-VMHardDiskDrive -VMName $VM.Name
            $NetworkAdapters = Get-VMNetworkAdapter -VMName $VM.Name | ForEach-Object {
                [PSCustomObject]@{
                    AdapterName = $_.Name
                    SwitchName  = $_.SwitchName
                }
            }

            $hyperVInfo += [PSCustomObject]@{
                VMName          = $VM.Name
                VHDDetails      = $VHDs | Select-Object Path
                NetworkAdapters = $NetworkAdapters
            }
        }
    }
    else {
        Log "Hyper-V is not installed on this server."
    }

    # If the server is a primary domain controller
    if ((Get-CimInstance -ClassName Win32_ComputerSystem).DomainRole -eq 5) {
        $adDomainName = (Get-ADDomain).DNSRoot
        $netBIOSDomainName = (Get-ADDomain).NetBIOSName
    
        $domainDn = (Get-ADDomain).DistinguishedName
        $domainGuid = (Get-ADDomain).ObjectGUID.ToString()
        $configurationDn = (Get-ADRootDSE).configurationNamingContext
    
        $dhcpSearchBase = "CN=NetServices,CN=Services,$configurationDN"
        $dhcpQuery = Get-ADObject -SearchBase $dhcpSearchBase -Filter 'objectClass -eq "dhcpClass" -AND Name -ne "dhcproot"'
        $dhcpServers = $dhcpQuery | ForEach-Object { $_.Name }

        $adRecycleBinFeature = Get-ADOptionalFeature -Identity 'Recycle Bin Feature'

        if ($null -ne $adRecycleBinFeature.FeatureScope) {
            $adRecycleBin = $true
        }
        else {
            $adRecycleBin = $false
        }
            
        $domainControllersQuery = Get-ADDomainController -Filter * -Server $adDomainName
        $domainControllers = $domainControllersQuery | ForEach-Object { $_.HostName }

        $dnsQuery = Resolve-DnsName -Type NS -Name $adDomainName | Where-Object { $_.NameHost -ne $null }
        $dnsServers = $dnsQuery | ForEach-Object { $_.NameHost }

        $domainFunctionalLevel = (Get-ADDomain).DomainMode.ToString()
        $forestFunctionalLevel = (Get-ADForest).ForestMode.ToString()
    
        # Get the security groups and member counts
        $securityGroups = Get-ADGroup -Filter * | Select-Object Name, ObjectGUID
        $securityGroupsWithCounts = foreach ($group in $securityGroups) {
            try {
                $memberCount = (Get-ADGroupMember -Identity $group.Name -ErrorAction Stop).Count
                # Create a custom object for each group with the member count
                [PSCustomObject]@{
                    name         = $group.Name
                    guid         = $group.ObjectGUID
                    member_count = $memberCount
                }
            }
            catch {
                Log "Could not retrieve members for group: $($group.Name)"
                # Create a custom object with null or zero member count
                [PSCustomObject]@{
                    name         = $group.Name
                    member_count = $null
                }
            }
        }

        $gpoList = Get-GPO -All | Select-Object @{Name = 'display_name'; Expression = { $_.DisplayName } }, @{Name = 'id'; Expression = { $_.Id } }, @{Name = 'gpo_status'; Expression = { $_.GpoStatus } }, @{Name = 'creation_time'; Expression = { $_.CreationTime } }, @{Name = 'modification_time'; Expression = { $_.ModificationTime } }
        
        $orgUnits = Get-ADOrganizationalUnit -Filter * -Properties CanonicalName | Select-Object @{Name = 'name'; Expression = { $_.Name } }, @{Name = 'distinguished_name'; Expression = { $_.DistinguishedName } }, @{Name = 'canonical_name'; Expression = { $_.CanonicalName } }

        $activeDirectoryInfo = @{
            full_domain_name        = $adDomainName
            netbios_domain_name     = $netBIOSDomainName
            domain_dn               = $domainDn
            domain_guid             = $domainGuid
            domain_controllers      = @($domainControllers)
            dhcp_servers            = @($dhcpServers)
            dns_servers             = @($dnsServers)
            domain_functional_level = $domainFunctionalLevel
            forest_functional_level = $forestFunctionalLevel
            security_groups         = $securityGroupsWithCounts
            ous                     = $orgUnits
            gpos                    = $gpoList
            ad_recycle_bin          = $adRecycleBin
        }

        New-ApiCall -Endpoint 'active-directory' -Method 'put' -Body $activeDirectoryInfo

        $adOutPath = Join-Path -Path $workingDirectory -ChildPath 'Active_Directory_Information.json'
        $jsonContent = $activeDirectoryInfo | ConvertTo-Json -Depth 5 -Compress
        $jsonContent | Out-File -FilePath $adOutPath

        $localNetwork = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration | Where-Object { $_.IPAddress -ne $null -and $_.IPEnabled -eq $true }
        $localIP = $localNetwork.IPAddress[0]
        $subnetMask = $localNetwork.IPSubnet[0]
        $networkRange = Get-NetworkRange -ipAddress $localIP -subnetMask $subnetMask
        $firstIP = $networkRange.FirstIP
        $lastIP = $networkRange.LastIP
        $currentTime = Get-Date

        try {
            $lastNetworkScan = [DateTime]::ParseExact($scriptConfig.Configuration.LastNetworkScan, 'yyyy-MM-ddTHH:mm:ss', $null)
            Log "Last network scan found."
        }
        catch {
            Log "Last network scan element not found, setting default date."
            $lastNetworkScan = [DateTime](Get-Date "2000-01-01T00:00:00")
        }

        $timeDifference = New-TimeSpan -Start $lastNetworkScan -End $currentTime

        if ($timeDifference.TotalHours -lt 24) {
            Log "Last network scan was less than 24 hours ago. Skipping network scan."
        }
        else {
            $totalTested = 0
            $activeCount = 0
            $networkScanResults = @()
            
            # Convert the first and last IP to integers
            $firstIPInt = Convert-IPToInt $firstIP
            $lastIPInt = Convert-IPToInt $lastIP
            
            # Loop through each IP address in the range, add them to a batch and ping them
            For ($ipInt = $firstIPInt; $ipInt -le $lastIPInt; $ipInt++) {
                $reachableIPs = @()
                $ipAddress = Convert-IntToIP $ipInt
                $totalTested++
                    
                # Test if the IP address is responding using Test-Connection
                $pingResult = Test-Connection -ComputerName $ipAddress -Count 1 -Quiet
                if ($pingResult) {
                    $reachableIPs += $ip
                    $activeCount++

                    if ($ipAddress -eq $localIP) {
                        $macAddress = $localNetwork.MACAddress
                    }
                    else {
                        $neighbor = Get-NetNeighbor -IPAddress $ipAddress
                        if ($neighbor.LinkLayerAddress -is [Array]) {
                            
                            $validMac = $neighbor.LinkLayerAddress | Where-Object { $_ -ne "" -and $_ -ne "00-00-00-00-00-00" } | Select-Object -First 1
                            if ($validMac) {
                                $macAddress = $validMac
                            }
                            else {
                                $macAddress = "Unknown"
                            }
                        }
                        else {
                            $macAddress = if ($neighbor) { $neighbor.LinkLayerAddress } else { "Unknown" }
                        }
                    }
                    $scanHostname = Get-Hostname -ipAddress $ipAddress
                    $ports = @()
                    $httpPortInfo = Get-HttpTitle -ipAddress $ipAddress
                    $ports += $httpPortInfo
                    $networkScanResults += [pscustomobject]@{
                        ip_address  = $ipAddress
                        mac_address = $macAddress
                        hostname    = $scanHostname
                        ports       = $ports
                    }
                }
                
    
            }
            
            # End the timer and calculate total duration
            $endTime = Get-Date
            $totalDuration = $endTime - $currentTime
            
            # Output summary information
            Log "Tested $totalTested addresses in $($totalDuration.TotalSeconds) seconds. $activeCount addresses found."

            if (-not $scriptConfig.Configuration.LastNetworkScan) {
                Log "Last network scan element not found. Creating new element."
                $xmlElement = $scriptConfig.CreateElement("LastNetworkScan")
                $xmlElement.InnerText = $currentTime.ToString("yyyy-MM-ddTHH:mm:ss")
                $scriptConfig.Configuration.AppendChild($xmlElement)
            }
            else {
                $scriptConfig.Configuration.LastNetworkScan = $currentTime.ToString("yyyy-MM-ddTHH:mm:ss")
            }
            $scriptConfig.Save($configPath)

            $networkAddress = Get-NetworkAddress -IPAddress $localIP -SubnetMask $subnetMask

            try {
                $dhcpScope = Get-DhcpServerv4Scope -ScopeId $networkAddress
                $exclusions = Get-DhcpServerv4ExclusionRange -ScopeId $networkAddress
                $excludedIPcount = 0
                foreach ($exclusion in $exclusions) {
                    $startIP = [System.Net.IPAddress]::Parse($exclusion.StartRange)
                    $endIP = [System.Net.IPAddress]::Parse($exclusion.EndRange)
                    $startIPInt = Convert-IPToInt $startIP
                    $endIPInt = Convert-IPToInt $endIP
                    $excludedIPcount += ($endIPInt - $startIPInt + 1)  # +1 to include the start and end IP
                }

                $reservations = Get-DhcpServerv4Reservation -ScopeId $networkAddress
                $leases = Get-DhcpServerv4Lease -ScopeId $networkAddress
                $startIPInt = Convert-IPToInt $dhcpScope.StartRange
                $endIPInt = Convert-IPToInt $dhcpScope.EndRange
                $totalIPs = $endIPInt - $startIPInt + 1
                $inUseCount = $leases.Count
                $freeCount = $totalIPs - $inUseCount - $excludedIPcount
                
                try {
                    $routerOption = Get-DhcpServerv4OptionValue -ScopeId $networkAddress -OptionId 3 -ErrorAction Stop
                }
                catch {
                    Log "Option 3 (Router) not set or could not be retrieved for scope. Error: $($_.Exception.Message)"
                }

                if ($null -ne $routerOption -and $null -ne $routerOption.Value) {
                    $routerOption = $routerOption.Value[0]
                }
                else {
                    try {
                        $routerOption = Get-DhcpServerv4OptionValue -OptionId 3 -ErrorAction Stop
                    }
                    catch {
                        Log "Option 3 (Router) not set or could not be retrieved globally. Error: $($_.Exception.Message)"
                    }

                    if ($null -ne $routerOption -and $null -ne $routerOption.Value) {
                        $routerOption = $routerOption.Value[0]
                    }
                    else {
                        Log "Global Router option is also null or not found."
                    }
                }

                foreach ($result in $networkScanResults) {
                    if ($result.ip_address -eq $routerOption) {
                        $routerMac = $result.mac_address
                        $routerInfo = [pscustomobject]@{
                            ip          = $routerOption
                            mac_address = $routerMac
                        }
                        break
                    }
                }
                
                $dnsServersOption = @()
                try {
                    $dhcpOption = Get-DhcpServerv4OptionValue -ScopeId $networkAddress -OptionId 6 -ErrorAction Stop
                }
                catch {
                    Log "Option 6 (DNS Servers) not set or could not be retrieved for scope. Error: $($_.Exception.Message)"
                }

                if ($null -ne $dhcpOption -and $null -ne $dhcpOption.Value) {
                    $dnsServersOption = $dhcpOption.Value
                }
                else {
                    try {
                        $dhcpOptionGlobal = Get-DhcpServerv4OptionValue -OptionId 6 -ErrorAction Stop
                    }
                    catch {
                        Log "Option 6 (DNS Servers) not set or could not be retrieved globally. Error: $($_.Exception.Message)"
                    }

                    if ($null -ne $dhcpOptionGlobal -and $null -ne $dhcpOptionGlobal.Value) {
                        $dnsServersOption = $dhcpOptionGlobal.Value
                    }
                    else {
                        Log "Global DNS Server option is also null or not found."
                    }
                }

                $dnsDomainNameOption = $null
                try {
                    $dhcpOption = Get-DhcpServerv4OptionValue -ScopeId $networkAddress -OptionId 15 -ErrorAction Stop
                }
                catch {
                    Write-Host "Option 15 (DNS Domain Name) not set or could not be retrieved for scope. Error: $($_.Exception.Message)"
                }

                if ($null -ne $dhcpOption -and $null -ne $dhcpOption.Value -and $null -ne $dhcpOption.Value[0]) {
                    $dnsDomainNameOption = $dhcpOption.Value[0]
                }
                else {
                    Log "Scope-specific DNS Domain Name option is null or not found. Attempting global option retrieval..."

                    try {
                        $dhcpOptionGlobal = Get-DhcpServerv4OptionValue -OptionId 15 -ErrorAction Stop
                    }
                    catch {
                        Log "Option 15 (DNS Domain Name) not set or could not be retrieved globally. Error: $($_.Exception.Message)"
                    }

                    if ($null -ne $dhcpOptionGlobal -and $null -ne $dhcpOptionGlobal.Value -and $null -ne $dhcpOptionGlobal.Value[0]) {
                        $dnsDomainNameOption = $dhcpOptionGlobal.Value[0]
                    }
                    else {
                        Log "Global DNS Domain Name option is also null or not found."
                    }
                }

                $leaseDurationOption = (Get-DhcpServerv4OptionValue -ScopeId $networkAddress -OptionId 51).Value[0]
                $reservationsList = $reservations | Select-Object @{Name = 'ip_address'; Expression = { $_.IPAddress.IPAddressToString } }, @{Name = 'mac_address'; Expression = { $_.ClientId } }
                $networkAddress = Get-NetworkAddress -IPAddress $dhcpScope.StartRange -SubnetMask $subnetMask
                $cidr = Convert-SubnetMaskToCIDR -subnetMask $subnetMask

                $collatedNetworkInfo = @{
                    network_id   = $networkAddress
                    subnet       = $cidr
                    dhcp_scopes  = @(
                        @{
                            scope_id            = $dhcpScope.ScopeId.IPAddressToString
                            start_range         = $dhcpScope.StartRange.IPAddressToString
                            end_range           = $dhcpScope.EndRange.IPAddressToString
                            reservations        = @($reservationsList)
                            total_ip_count      = $totalIPs
                            leased_ip_count     = $inUseCount
                            unassigned_ip_count = $freeCount
                            excluded_ip_count   = $excludedIPcount
                            reserved_ip_count   = @($reservationsList).Count
                            router              = $routerInfo
                            dns_servers         = @($dnsServersOption)
                            dns_domain_name     = $dnsDomainNameOption
                            lease_duration      = $leaseDurationOption
                        }
                    )
                    network_scan = $networkScanResults
                }

                New-ApiCall -Endpoint 'lan' -Method 'put' -Body $collatedNetworkInfo

                $networkOutPath = Join-Path -Path $workingDirectory -ChildPath 'Network_Information.json'
                $collatedNetworkInfo | ConvertTo-Json -Depth 5 | Out-File -FilePath $networkOutPath
                
            }
            catch {
                Log "Failed to retrieve DHCP information. Error: $_ at line $($_.InvocationInfo.ScriptLineNumber)"
            }
        }
    
    }
    else {
        Log "This server is not a primary domain controller."
    }

    $serverInformation = @{
        hostname         = $hostname
        full_hostname    = $fullHostname
        manufacturer     = $manufacturer
        model            = $model
        serial_number    = $biosSerialNumber
        os               = $osVersion.Caption
        os_version       = $osVersion.Version
        uuid             = $osUuid
        fixed_disks      = @($fixedDisksInfo)
        ram              = $totalMemory
        cpu              = $cpu
        cpu_cores        = $totalCores
        network_adapters = $networkInfo
        last_boot        = $lastBootTime
    }

    New-ApiCall -Endpoint 'server' -Method 'put' -Body $serverInformation

    $serverOutPath = Join-Path -Path $workingDirectory -ChildPath 'Server_Information.json'
    $jsonContent = $serverInformation | ConvertTo-Json -Depth 5
    $jsonContent | Out-File -FilePath $serverOutPath

}
else {
    Log "This script is not intended to run on end user devices."
}
