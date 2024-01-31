function IPThreatScan([Parameter(Mandatory=$true,ValueFromPipeline=$true,HelpMessage="Enter one or more IPv4 addresses separated by commas")] $IP, [Parameter(Mandatory=$false,ValueFromPipeline=$false,HelpMessage="Switch for report creation")] [switch]$Report){

    # IP list for multiple addresses

    # Read config file
    try {
        $Config = Get-Content -Path ([Environment]::GetFolderPath("MyDocuments")+"\IPSpy\IPSpyConfig.json") -Raw | ConvertFrom-Json
    }
    catch {
        Write-Host "No configuration file was found.`nA default configuration will be used."
        $Config = New-Object psobject -Property @{
            "VirusTotal Weights" = @{
                "1+Suspicious" = 1
                "1+Malicious" = 2
                "2+Malicious" = 3
                "5+Malicious" = 4
            }
            "CountryCodes" = @{
                "DefaultScore" = 1
                "BlacklistScore" = 2
                "Whitelist" = @("US")
                "Blacklist" = @("CN","IR","RU","KP")
            }
            "ASNs" = @{
                "DefaultScore" = 1
                "BlacklistScore" = 2
                "Whitelist" = @()
                "Blacklist" = @()
            }
            "Orgs" = @{
                "DefaultScore" = 1
                "BlacklistScore" = 2
                "Whitelist" = @()
                "Blacklist" = @()
            }
        }
        try {
            try {
                New-Item -path ([Environment]::GetFolderPath("MyDocuments")) -Name "IPSpy" -ItemType "directory" -erroraction Stop
            }
            catch {}
            if((Read-Host -Prompt "Do you want to save the default configuration? Press enter to skip")){
                Out-File -InputObject ($Config | ConvertTo-Json) -FilePath ([Environment]::GetFolderPath("MyDocuments")+"\IPSpy\IPSpyConfig.json") 
                Write-Host "Default configuration has been saved to $([Environment]::GetFolderPath("MyDocuments")+"\IPSpy\IPSpyConfig.json")"
            }
        }
        catch {
            Write-Host "Could not save the configuration file in location $([Environment]::GetFolderPath("MyDocuments")+"\IPSpy\IPSpyConfig.json")"
        }
    }
    try {
        $APIKeys = Get-Content -Path ([Environment]::GetFolderPath("MyDocuments")+"\IPSpy\IPSpyAPIKeys.json") -Raw -ErrorAction Stop| ConvertFrom-Json
    }
    catch {
        Write-Host "No API key file found.`nPlease enter API keys or press enter to exclude services from running."
        $VirusTotalKey = Read-Host -Prompt "VirusTotal key" -AsSecureString
        $VirusTotalKey = [Runtime.InteropServices.Marshal]::PtrToStringBSTR([Runtime.InteropServices.Marshal]::SecureStringToBSTR($VirusTotalKey))
        $ShodanKey = Read-Host -Prompt "Shodan API key" -AsSecureString
        $ShodanKey = [Runtime.InteropServices.Marshal]::PtrToStringBSTR([Runtime.InteropServices.Marshal]::SecureStringToBSTR($ShodanKey))
        $NISTKey = Read-Host -Prompt "NIST CVE key" -AsSecureString
        $NISTKey = [Runtime.InteropServices.Marshal]::PtrToStringBSTR([Runtime.InteropServices.Marshal]::SecureStringToBSTR($NISTKey))
        $APIKeys = New-Object psobject -Property @{
            "VirusTotalKey" = $VirusTotalKey
            "ShodanKey" = $ShodanKey
            "NISTKey" = $NISTKey
        }
        if((Read-Host -Prompt "Do you want to save these keys for future use? Press enter to skip")){
            Out-File -InputObject ($APIKeys | ConvertTo-Json) -FilePath ([Environment]::GetFolderPath("MyDocuments")+"\IPSpy\IPSpyAPIKeys.json")
        }
    }

    # Process each submitted address
    foreach($Address in $IP){
        # Validate address 
        if(-Not (IsValidIPv4Address($Address))){
            Write-Host "$Address is invalid...`nSkipping..."
            return
        }

        # Make VirusTotal Request
        if($APIKeys.VirusTotalKey){
            $VirusTotalRequest = Invoke-WebRequest ("https://www.virustotal.com/api/v3/ip_addresses/"+$Address) -Headers @{"x-apikey" = $APIKeys.VirusTotalKey} -Method GET -SessionVariable VirusTotalSession
            if($VirusTotalRequest.StatusCode -eq 200){
                $VirusTotalResponse = $VirusTotalRequest | Select-Object -ExpandProperty Content | ConvertFrom-Json | Select-Object -ExpandProperty data | Select-Object -ExpandProperty attributes
            }else{
                Write-Host "VirusTotal request failed. Review error log."
            }
        }

        # Make Shodan request
        if($APIKeys.ShodanKey){
            $ShodanRequest = Invoke-WebRequest -URI ("https://api.shodan.io/shodan/host/"+$Address+"?key="+$APIKeys.ShodanKey) -Method GET -SessionVariable ShodanSession
            if($ShodanRequest.StatusCode -eq 200){
                $ShodanResponse = $ShodanRequest | Select-Object -expandproperty Content | ConvertFrom-Json
            }else{
                Write-Host "Shodan request failed. Review error log."
                $error[0]
            }
        }

        # Make NIST Request
        if($APIKeys.NISTKey -And $ShodanResponse.vulns){
            $NISTResponses = @()
            foreach($x in $ShodanResponse.vulns){
                $NISTResponses += Invoke-RestMethod -URI ("https://services.nvd.nist.gov/rest/json/cves/2.0?cveId="+$x) -Headers @{"apikey" = $APIKeys.NISTKey} -Method GET -SessionVariable NISTSession | Select-Object -ExpandProperty vulnerabilities | Select-Object -ExpandProperty cve
            }
        }

        # Make OpenStreetMap request
        if($ShodanResponse.latitude){
            $OpenStreetMapRequest = Invoke-RestMethod -URI ("https://nominatim.openstreetmap.org/reverse?lat="+$ShodanResponse.latitude+"&lon="+$ShodanResponse.longitude) -Method GET -SessionVariable OpenStreetMapSession
            if($OpenStreetMapRequest){
                $OpenStreetMapResponse = $OpenStreetMapRequest | Select-Object -ExpandProperty reversegeocode | Select-Object -ExpandProperty result | Select-Object "#text"
                $GoogleMapsLink = ($OpenStreetMapResponse."#text").Replace(",","+").Replace(" ","")
                $GoogleMapsLink = "https://www.google.com/maps/search/"+$GoogleMapsLink
            }
        }

        # Severity Ranking
        $SeverityScore = 0
        $SeverityDescription = "The severity ranking was calculated from the following: "
        if($VirusTotalResponse.last_analysis_stats.suspicious -ge 1){
            $SeverityScore += $Config."VirusTotal Weights"."1+Suspicious"
            $SeverityDescription += "VirusTotal had 1 or more suspicous detections. "
        }elseif ($VirusTotalResponse.last_analysis_stats.malicious -ge 1) {
            $SeverityScore += $Config."VirusTotal Weights"."1+Malicious"
            $SeverityDescription += "VirusTotal had 1 malicious detection. "
        }elseif ($VirusTotalResponse.last_analysis_stats.malicious -ge 2) {
            $SeverityScore += $Config."VirusTotal Weights"."2+Malicious"
            $SeverityDescription += "VirusTotal had 2 or more malicious detections. "
        }elseif ($VirusTotalResponse.last_analysis_stats.malicious -ge 5) {
            $SeverityScore += $Config."VirusTotal Weights"."5+Malicious"
            $SeverityDescription += "VirusTotal had 5 or more malicious detections. "
        }
        if($ShodanResponse.country_code -in $Config.CountryCodes.Blacklist){
            $SeverityScore += $Config.CountryCodes.BlacklistScore
            $SeverityDescription += "The country code was within the user defined blacklist. "
        }elseif ($ShodanResponse.country_code -notin $Config.CountryCodes.Whitelist) {
            $SeverityScore += $Config.CountryCodes.DefaultScore
            $SeverityDescription += "The country code was not in the user defined whitelist. "
        }
        if($ShodanResponse.asn -in $Config.ASNs.Blacklist){
            $SeverityScore += $Config.ASNs.BlacklistScore
            $SeverityDescription += "The ASN was within the user defined blacklist. "
        }elseif($ShodanResponse.asn -notin $Config.ASNs.Whitelist){
            $SeverityScore += $Config.ASNs.DefaultScore
            $SeverityDescription += "The ASN was not in the user defined whitelist. "
        }
        if($ShodanResponse.org -in $Config.Orgs.Blacklist){
            $SeverityScore += $Config.Orgs.BlacklistScore
            $SeverityDescription += "The organization was within the user defined blacklist. "
        }elseif($ShodanResponse.org -notin $Config.Orgs.Whitelist){
            $SeverityScore += $Config.Orgs.DefaultScore
            $SeverityDescription += "The organization was not in the user defined whitelist. "
        }
        switch ($SeverityScore) {
             {$_ -le 2} {$Severity = "Low"; $SeverityDescription += "As a result, the severity is LOW and this address does not appear to pose a significant threat."; break}
             {$_ -in 3..4} {$Severity = "Medium"; $SeverityDescription += "As a result, the severity is MEDIUM and this address may pose a threat."; break}
             {$_ -in 5..8} {$Severity = "High"; $SeverityDescription += "As a result, the severity is HIGH and this address poses a threat."; break}
             {$_ -ge 9} {$Severity = "Critical"; $SeverityDescription += "As a result, the severity is CRITICAL and this address may pose a significant threat"; break}
            Default {break}
        }

        # Create Object
        $Results = [PSCustomObject][ordered]@{
            "Address" = $Address
            "Severity" = $Severity
            "SeverityScore" = $SeverityScore
            "SeverityDescription" = $SeverityDescription
            "RawData" = @{
                "VirusTotal" = $VirusTotalResponse
                "Shodan" = $ShodanResponse
                "NIST" = $NISTResponses
            }
            "LocationString" = $OpenStreetMapResponse."#text"
            "LocationLink" = $GoogleMapsLink
        }

        # Write report if selected
        if($Report){
            # word stuff ~
        }
        Write-Host "Results for $address`nSeverity: $Severity`nSeverityScore: $SeverityScore`nSeverity Description: $SeverityDescription`nVirusTotalDetections: $($VirusTotalResponse.Total_votes)`nLocation: $($OpenStreetMapResponse."#text")`nLink: $GoogleMapsLink"
        $Results
    }

}

# https://stackoverflow.com/a/65657387
function IsValidIPv4Address ($ip) {
    return ($ip -match "^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$" -and [bool]($ip -as [ipaddress]))
}

Export-ModuleMember -Function IPThreatScan