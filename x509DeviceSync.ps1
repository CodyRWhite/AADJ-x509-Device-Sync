[CmdletBinding(DefaultParameterSetName = 'Default')]
param(
    [Parameter(Mandatory = $False)] [Switch] $NameMap
)

$TenantId = "<Your Tenant ID>"
$ClientId = "<Your Application Client ID>"
#$ClientSecret = ""
$Thumbprint = "<Your Client Certificate Thumbprint>"

$RequiredModules = "ActiveDirectory", "PSPKI", "Microsoft.Graph" #"Microsoft.Graph.Authentication", "Microsoft.Graph.DeviceManagement", "Microsoft.Graph.Groups" #, "Microsoft.Graph.Device"

# Set the OU for computer object creation
$domain = "DOMAIN.TLD"
$orgUnit = "OU=AAD Computers,OU=Autopilot Domain Join,DC=domain,DC=tld" 

# Set User groups for NPS 
$groupList = @"
[ 
    {
        "GroupName" : "Internal_WiFi_Devices",
        "ADGroupName" : "Internal_WiFi_Devices",
        "EntraGroupID" : "f9e4a2a5-...-59f17de8030b"
    },
    {
        "GroupName" : "Internal_WiFi_2-Devices",
        "ADGroupName" : "Internal_WiFi_2-Devices",
        "EntraGroupID" : "df896196-...-942f32bcf955"
    }
]
"@ | ConvertFrom-Json

## Install, Update, and Import Required Powershell Modules where required
ForEach ($Module in $RequiredModules) {
    Write-Host -ForegroundColor DarkGray "Checking for $Module Module"
    [Version]$OnlineVersion = (Find-Module -Name $Module -ErrorAction SilentlyContinue).Version
    [Version]$InstalledVersion = (Get-Module -ListAvailable -Name $Module | Sort-Object Version -Descending  | Select-Object Version -First 1).Version
    Write-Host -ForegroundColor DarkGray "Installed Version: $InstalledVersion /// Online Version: $OnlineVersion "
    IF ( $OnlineVersion -gt $InstalledVersion) {        
        #$OldModule = @{
        #   ModuleName = $Module
        #   ModuleVersion = $InstalledVersion
        #}
        #Remove-Module -FullyQualifiedName $OldModule -Force

        Write-Host -ForegroundColor DarkGray "Installing $Module Module "
        Install-Module -Name $Module -Force -AllowClobber        

    }
    IF (!(Get-Module -Name $Module)) {
        Write-Host -ForegroundColor DarkGray "Importing $Module Module"
        Import-Module -Name $Module -Force
    }
}

# Connect to MgGraph with application credentials
Connect-MgGraph -TenantId $TenantId -AppId $ClientId -CertificateThumbprint $Thumbprint -NoWelcome

#region Add Autopilot Devices
Write-Host "<Autopilot Device Mapping> Starting Autopilot to AD group mapping..." -ForegroundColor Green

Write-Host "<Autopilot Device Mapping> Gathering autopilot members from Intune..." -ForegroundColor Green
# Pull latest Autopilot device information
Try{
    $AutopilotDevices = Get-MgDeviceManagementWindowsAutopilotDeviceIdentity -ErrorAction Stop
} catch {
    Write-Host "<Autopilot Device Mapping> Unable to download autopilot list... " -ForegroundColor Red
    Write-Host "<Error> $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}


# Create new Autopilot computer objects in AD while skipping already existing computer objects
Write-Host "<Autopilot Device Mapping> Adding missing objects to $orgUnit."  -ForegroundColor Green
foreach ($Device in $AutopilotDevices) {
    Clear-Variable ADDevice, deviceDescription, altSecurityIdentities -ErrorAction SilentlyContinue -Force

    $deviceDescription = "$($Device.Displayname) - $($Device.SerialNumber)" 
    $ADDevice = Get-ADComputer -Properties * -Filter "Name -eq `"$($Device.azureActiveDirectoryDeviceId)`"" -SearchBase $orgUnit -ErrorAction SilentlyContinue
    
    if ($ADDevice) {
        if ($ADDevice.Description -ne $deviceDescription) {
            Write-Host "<Autopilot Device Mapping> Device $($Device.azureActiveDirectoryDeviceId) already exists but description is not expected. Updating AD device description." -ForegroundColor Green
            Set-ADComputer -Identity "$($Device.azureActiveDirectoryDeviceId.Substring(0,[math]::min(15,$Device.azureActiveDirectoryDeviceId.length)))" -Description $deviceDescription  
        }
        else {
            #Write-Host "<Autopilot Device Mapping> Skipping $($Device.azureActiveDirectoryDeviceId) because it already exists. " -ForegroundColor Yellow
        }
    }
    else {
        # Create new AD computer object
        try {
            New-ADComputer -Name "$($Device.azureActiveDirectoryDeviceId)" -Path $orgUnit -SAMAccountName "$($Device.azureActiveDirectoryDeviceId.Substring(0,[math]::min(15,$Device.azureActiveDirectoryDeviceId.length)))`$" -ServicePrincipalNames "HOST/$($Device.azureActiveDirectoryDeviceId)", "HOST/$($Device.azureActiveDirectoryDeviceId).$domain" -Description $deviceDescription 
            Write-Host "<Autopilot Device Mapping> Computer object created. ($($Device.azureActiveDirectoryDeviceId))" -ForegroundColor Green
        }
        catch {
            Write-Host "<Autopilot Device Mapping> Error. Skipping computer object creation." -ForegroundColor Red
        }
    }
}

# Reverse the process and remove any dummmy computer objects in AD that are no longer in Autopilot
Write-Host "<Autopilot Device Mapping> Removing orpahaned objects from $orgUnit."  -ForegroundColor Green
$DummyDevices = Get-ADComputer -Filter * -SearchBase $orgUnit | Select-Object Name, SAMAccountName
foreach ($DummyDevice in $DummyDevices) {
    if ($AutopilotDevices.azureActiveDirectoryDeviceId -contains $DummyDevice.Name) {
        #Write-Host "<Remove AP Device> $($DummyDevice.Name) exists in Autopilot." -ForegroundColor Green
    }
    else {
        Write-Host "<Remove AP Device> $($DummyDevice.Name) does not exist in Autopilot." -ForegroundColor Yellow
        Remove-ADComputer -Identity $DummyDevice.SAMAccountName -Confirm:$False #-WhatIf 
        #Remove -WhatIf once you are comfortrable with this workflow and have verified the remove operations are only performed in the OU you specified
    }
}
#endregion 

#region Certificate mapping
Write-Host "<Certificate Binding> Starting certificate hash sync..." -ForegroundColor Green
Write-Host "<Certificate Binding> Fetching domain Certificate Authorities..." -ForegroundColor Green
$certificateAuthorities = Get-CertificationAuthority
try {
    Clear-Variable IssuedCerts, IssuedRaw -ErrorAction SilentlyContinue
    foreach ($CAHost in $certificateAuthorities) {
        Write-Host "<Certificate Binding> Getting all issued certs from '$($CAHost.ComputerName)'..." -ForegroundColor Green
        $IssuedRaw = Get-IssuedRequest -CertificationAuthority $CAHost -Property RequestID, ConfigString, CommonName, DistinguishedName, CertificateHash, SerialNumber, SubjectKeyIdentifier, RawPublicKey, RawCertificate
        $IssuedCerts += $IssuedRaw | Select-Object -Property RequestID, ConfigString, CommonName, DistinguishedName, @{
            name       = 'SANPrincipalName';
            expression = {
                Clear-Variable matches -ErrorAction SilentlyContinue
                ($(New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList @(, [Convert]::FromBase64String($_.RawCertificate))).Extensions | `
                    ? { $_.Oid.FriendlyName -eq "Subject Alternative Name" }).Format(0) -match "^(.*)(Principal Name=)([^,]*)(,?)(.*)$" | Out-Null;
                if ($matches.GetEnumerator() | ? Value -eq "Principal Name=") {
                    $n = ($matches.GetEnumerator() | ? Value -eq "Principal Name=").Name + 1;
                    $matches[$n]
                }
            }
        }, 
        @{
            name       = "Issuer";
            expression = {
                Clear-Variable issuer -ErrorAction SilentlyContinue
                $issuer = $(New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList @(, [Convert]::FromBase64String($_.RawCertificate))).Issuer.Split().Replace(',', '')
                [Array]::Reverse($issuer)
                $issuer -join (',')
            }
        }, 
        @{
            name       = "SerialNumber";
            expression = {
                Clear-Variable serialArray -ErrorAction SilentlyContinue
                $serialArray = $_.SerialNumber -split '(..)'
                [Array]::Reverse($serialArray)
                $serialArray -join ('')
            }
        }, 
        @{
            name       = "CertificateHash";
            expression = { $_.CertificateHash -Replace '\s', '' }
        }, 
        @{
            name       = "SubjectKeyIdentifier";
            expression = { $_.SubjectKeyIdentifier -Replace '\s', '' }
        }
    }
}
catch {  
    Write-Host "Error - $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "<Certificate Binding> Error getting issued certificates from ADCS servers" -ForegroundColor Red
}

try { 
    Write-Host "<Certificate Binding> Getting AD objects..." -ForegroundColor Green
    $AADx509Devs = Get-ADComputer -Filter '(objectClass -eq "computer")' -SearchBase $orgUnit -Property Name, Description, altSecurityIdentities
}
catch {  
    Write-Host "$($_.Exception.Message)" -ForegroundColor Green
    Write-Host  "<Certificate Binding> Error getting AADx509 computers for hash sync" -ForegroundColor Green
}

#$AADx509Devs = $AADx509Devs | Where-OBject -Property Name -EQ "0fd71e56-5102-467c-a96b-448d006a8169"
#$IssuedCerts = $null
#$device = $AADx509Devs | Where-OBject -Property Name -EQ "2cda6552-3728-40a0-b7d4-bc5e4b9f43c6"
foreach ($device in $AADx509Devs) {
    Clear-Variable altSecurityIdentities, certAltSecurityIdentities -ErrorAction SilentlyContinue -Force
    
    $certs = $IssuedCerts | Where-Object -Property "SANPrincipalName" -Like "host/$($device.Name)"
    if ($certs) {
        ForEach ($cert in $certs) {
            $certAltSecurityIdentities += @(
                "X509:<I>$($cert.Issuer)<S>$($cert.DistinguishedName)"
                "X509:<S>$($cert.DistinguishedName)"
                "X509:<I>$($cert.Issuer)<SR>$($cert.SerialNumber)"
                "X509:<SKI>$($cert.SubjectKeyIdentifier)"
                "X509:<SHA1-PUKEY>$($cert.CertificateHash)"
            )
        }

        $certAltSecurityIdentities = $certAltSecurityIdentities | Select-Object -Unique
        
        try {
            ForEach ($certAltSecurityIdentity in $certAltSecurityIdentities) {
                if (!($certAltSecurityIdentity -in $device.altSecurityIdentities)) {
                    $altSecurityIdentities = @{"altSecurityIdentities" = $certAltSecurityIdentity.ToString() }
                    Write-Host "<Certificate Binding> Mapping '$($device.Name) ($($device.description))' to '$certAltSecurityIdentity'" -ForegroundColor Green
                    Get-ADComputer -Filter "(servicePrincipalName -like 'host/$($device.Name)')" | Set-ADComputer -Add $altSecurityIdentities
                }
                else {
                    # Write-Host "<Certificate Binding> Mapping Exists for '$($device.Name) ($($device.description))' to '$certAltSecurityIdentity'" -ForegroundColor Yellow
                }
            }
        }
        catch {  
            Write-Host "$($_.Exception.Message)" -ForegroundColor Green
            Write-Host "<Certificate Binding> Error mapping AADx509 computer object '$($device.Name) ($($device.description))' to '$certAltSecurityIdentity'" -ForegroundColor Green
        }

        try {
            ForEach ($deviceAltSecurityIdentity in $device.altSecurityIdentities) {
                if (!($deviceAltSecurityIdentity -in $certAltSecurityIdentities)) {
                    $altSecurityIdentities = @{
                        "altSecurityIdentities" = $deviceAltSecurityIdentity
                    }
                    Write-Host "<Certificate Binding> Removing orphaned '$deviceAltSecurityIdentity' from '$($device.Name) ($($device.description))'" -ForegroundColor Yellow
                    Get-ADComputer -Filter "(servicePrincipalName -like 'host/$($device.Name)')" | Set-ADComputer -remove $altSecurityIdentities
                }
            }
        }
        catch {  
            Write-Host "$($_.Exception.Message)" -ForegroundColor Green
            Write-Host "<Certificate Binding> Error mapping AADx509 computer object '$($device.Name) ($($device.description))' to (CA-RequestID) SHA1-hash '$($certAltSecurityIdentity.certDetails)'" -ForegroundColor Green
        }
    }
    else {
        if ($device.altSecurityIdentities) {
            Write-Host "<Certificate Binding> No certificates found for '$($device.Name) ($($device.description))' altSecurityIdentities not <null>, clearing altSecurityIdentities" -ForegroundColor Yellow
            Get-ADComputer -Filter "(servicePrincipalName -like 'host/$($device.Name)')" | Set-ADComputer -Clear "altSecurityIdentities"
        }
    }
}
#endregion Certificate mapping

#region Device Group Matching / Creation
Write-Host "<Entra Group Mapping> Starting Entra to AD group mapping..." -ForegroundColor Green
ForEach ($Group in $groupList) {
    Clear-Variable entraGroup, entraGroupMembers, adGroup, adGroupMembers -Force -ErrorAction SilentlyContinue

    Write-Host "<Entra Group Mapping> Processing group $($group.GroupName)..." -ForegroundColor Green 
    $entraGroup = Get-MgGroup -GroupId $Group.EntraGroupID
    $entraGroupMembers = Get-MgGroupMember -All -GroupId $entraGroup.Id

    $adGroup = Get-ADGroup -Filter "cn -eq '$($group.ADGroupName)'" -Server $domain
    $adGroupMembers = Get-ADGroup -Filter "cn -eq '$($group.ADGroupName)'" -Server $domain | Get-ADGroupMember -Server $domain

    Write-Host "<Entra Group Mapping> Entra Group has $(($entraGroupMembers | Measure-Object).Count) members and AD has $(($adGroupMembers | Measure-Object).Count) members." -ForegroundColor Green
    Write-Host "<Entra Group Mapping> Checking to see if group $($adGroup.Name) is missing any members." -ForegroundColor Green
    $DeviceArray = [System.Collections.ArrayList]::new()
    forEach ($Member in $entraGroupMembers) {
        $Device = Get-MgDevice -DeviceId $Member.Id
        If ($Device.EnrollmentType -in ("AzureDomainJoined", "AzureADJoinUsingWhiteGlove") ) {
            $tempDevice = [System.Collections.Generic.List[PSObject]]::new()
            $tempDevice.Add([pscustomobject] @{
                    "Id"             = "$($Device.Id)"
                    "DeviceId"       = "$($Device.DeviceId)"
                    "DisplayName"    = "$($Device.DisplayName)"
                    "EnrollmentType" = "$($Device.EnrollmentType)"
                    "LookupValue"    = "$($Device.DeviceId)"
                })
            $DeviceArray.AddRange($tempDevice)
        }
        else {
            $tempDevice = [System.Collections.Generic.List[PSObject]]::new()
            $tempDevice.Add([pscustomobject] @{
                    "Id"             = "$($Device.Id)"
                    "DeviceId"       = "$($Device.DeviceId)"
                    "DisplayName"    = "$($Device.DisplayName)"
                    "EnrollmentType" = "$($Device.EnrollmentType)"                    
                    "LookupValue"    = "$($Device.DisplayName)"
                })
            $DeviceArray.AddRange($tempDevice)
        }
    }   

    # Compare Entra Devices to AD 
    Write-Host "<Entra Group Mapping> Adding missing objects to $($adGroup.Name)." -ForegroundColor Green
    ForEach ($Device in $DeviceArray) {
        IF ($Device.LookupValue -in $adGroupMembers.name) {
            #Write-Host "<Entra Group Mapping> Member $($Device.DisplayName)($($Device.LookupValue)) already exists in group $($adGroup.Name)" -ForegroundColor Green
        }
        else {     
            $adComputer = $null       
            $adComputer = Get-ADComputer -Filter "cn -eq '$($Device.LookupValue)'" -Server $domain
            IF ($adComputer) {
                Write-Host "<Entra Group Mapping> Adding $($Device.DisplayName)($($Device.LookupValue)) member to group $($adGroup.Name)" -ForegroundColor Yellow
                Add-ADGroupMember -Identity $adGroup.DistinguishedName -Members $adComputer.DistinguishedName -Server $domain -Confirm:$False
            }
            else {
                Write-Host "<Entra Group Mapping> Unable to locate member $($Device.DisplayName)($($Device.LookupValue)) in Active Directory" -ForegroundColor Red
            }            
        }
    }

    Write-Host "<Entra Group Mapping> Removing orpahaned objects from $($adGroup.Name)." -ForegroundColor Green
    # Compare AD Devices to Entra 
    ForEach ($Device in $adGroupMembers) {
        IF ($Device.name -in $DeviceArray.LookupValue) {
            #Write-Host "<Entra Group Mapping> Member $($Device.DisplayName)($($Device.LookupValue)) already exists in group $($adGroup.Name)" -ForegroundColor Green
        }
        else {     
            Write-Host "<Entra Group Mapping> Removing $($Device.DisplayName)($($Device.LookupValue)) member from group $($adGroup.Name)" -ForegroundColor Yellow
            Remove-ADGroupMember -Identity $adGroup.DistinguishedName -Members $Device.DistinguishedName -Server $domain -Confirm:$False      
        }
    }
}
#endregion Device Group Matching / Creation
