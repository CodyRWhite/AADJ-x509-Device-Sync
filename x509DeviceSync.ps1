[CmdletBinding(DefaultParameterSetName = 'Default')]
param(
    [Parameter(Mandatory = $False)] [Switch] $NameMap
)

# Set the Tenant and App details
$TenantId = "<Your Tenant ID>"
$ClientId = "<Your Application Client ID>"
$ClientSecret = "<Your Application Secret"

$RequiredModules = "ActiveDirectory", "WindowsAutopilotIntune", "PSPKI"

# Set the OU for computer object creation of Autopilot Devices
$orgUnit = "OU=AAD Computers,OU=Autopilot Domain Join,DC=domain,DC=com" 

# Set the domain for UPN Verification on certs 
$domain = "domain.com"

# Set User groups for NPS multiple groups are allowed
$groupList = @"
[ 
    {
        "GroupName" : "Internal_WiFi_Devices_1", #This is just a name for logging details
        "ADGroupName" : "Internal_WiFi_Devices_1",  # This is the name of the group in AD that you want to copy devices into
        "AADGroupID" : "Group_f9e402893-234-234-f-234-7de8030b" # This is the AD name of the group that is sync'd from AAD 
    },
    {
        "GroupName" : "Internal_WiFi_Devices_2",
        "ADGroupName" : "Internal_WiFi_Devices_2",
        "AADGroupID" : "Group_f9e402893-23443-234-f-234-7de8030b"
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
        Write-Host -ForegroundColor DarkGray "Installing $Module Module "
        Install-Module -Name $Module -Force -AllowClobber
    }
    IF (!(Get-Module -Name $Module)) {
        Write-Host -ForegroundColor DarkGray "Importing $Module Module"
        Import-Module -Name $Module -Force
    }
}

# Connect to MSGraph with application credentials
Connect-MSGraphApp -Tenant $TenantId -AppId $ClientId -AppSecret $ClientSecret

# Pull latest Autopilot device information
$AutopilotDevices = Get-AutopilotDevice

# Create new Autopilot computer objects in AD while skipping already existing computer objects
Write-Host "<Add/Update AP Device> Starting AP Device AD Compare to Update and Add Devices to AD"  -ForegroundColor Green
foreach ($Device in $AutopilotDevices) {
    Clear-Variable ADDevice, deviceDescription, altSecurityIdentities -ErrorAction SilentlyContinue -Force

    $deviceDescription = "$($Device.Displayname) - $($Device.SerialNumber)" 
    $ADDevice = Get-ADComputer -Properties * -Filter "Name -eq `"$($Device.azureActiveDirectoryDeviceId)`"" -SearchBase $orgUnit -ErrorAction SilentlyContinue
    
    if ($ADDevice) {
        if ($ADDevice.Description -ne $deviceDescription) {
            Write-Host "<Add/Update AP Device> Device $($Device.azureActiveDirectoryDeviceId) already exists but description is not expected. Updating AD device description." -ForegroundColor Green
            Set-ADComputer -Identity "$($Device.azureActiveDirectoryDeviceId.Substring(0,[math]::min(15,$Device.azureActiveDirectoryDeviceId.length)))" -Description $deviceDescription
        }
        else {
            Write-Host "<Add/Update AP Device> Skipping $($Device.azureActiveDirectoryDeviceId) because it already exists. " -ForegroundColor Yellow
        }
    }
    else {
        # Create new AD computer object
        try {
            New-ADComputer -Name "$($Device.azureActiveDirectoryDeviceId)" -Path $orgUnit -SAMAccountName "$($Device.azureActiveDirectoryDeviceId.Substring(0,[math]::min(15,$Device.azureActiveDirectoryDeviceId.length)))`$" -ServicePrincipalNames "HOST/$($Device.azureActiveDirectoryDeviceId)", "HOST/$($Device.azureActiveDirectoryDeviceId).$domain" -Description $deviceDescription 
            Write-Host "<Add/Update AP Device> Computer object created. ($($Device.azureActiveDirectoryDeviceId))" -ForegroundColor Green
        }
        catch {
            Write-Host "<Add/Update AP Device> Error. Skipping computer object creation." -ForegroundColor Red
        }
    }
}

# Reverse the process and remove any stale computer objects in AD that are no longer in Autopilot
Write-Host "<Add/Update AP Device> Starting AP Device AD Compare to Remove Devices from AD"  -ForegroundColor Green
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

#Starting Certificate details section
Write-Host "<Certificate Binding> Starting certificate hash sync..." -ForegroundColor Green
Write-Host "<Certificate Binding> Fetching domain Certificate Authorities..." -ForegroundColor Green

#Generating a list of all PKI cervers in your environment
$certificateAuthorities = Get-CertificationAuthority

try {
    Clear-Variable IssuedCerts, IssuedRaw -ErrorAction SilentlyContinue
    
    # Get all active public certificate information from all PKI Servers    
    foreach ($CAHost in $certificateAuthorities.ComputerName) {
        Write-Host "<Certificate Binding> Getting all issued certs from '$CAHost'..." -ForegroundColor Green
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

# Get all AD Computer Objects from your AP Group that were generated in the first phase.
try { 
    Write-Host "<Certificate Binding> Getting AD objects..." -ForegroundColor Green
    $AADx509Devs = Get-ADComputer -Filter '(objectClass -eq "computer")' -SearchBase $orgUnit -Property Name, Description, altSecurityIdentities
}
catch {  
    Write-Host "$($_.Exception.Message)" -ForegroundColor Green
    Write-Host  "<Certificate Binding> Error getting AADx509 computers for hash sync" -ForegroundColor Green
}

#Loop through all devices and update certificate information where missing.
foreach ($device in $AADx509Devs) {
    Clear-Variable altSecurityIdentities, certAltSecurityIdentities -ErrorAction SilentlyContinue -Force
    
    # Get certificate for current device
    $certs = $IssuedCerts | Where-Object -Property "SANPrincipalName" -Like "host/$($device.Name)"
    if ($certs) {
        #if the device has multiple active certificiates and generate security identities for each 
        ForEach ($cert in $certs) {
            $certAltSecurityIdentities += @(
                "X509:<I>$($cert.Issuer)<S>$($cert.DistinguishedName)"
                "X509:<S>$($cert.DistinguishedName)"
                "X509:<I>$($cert.Issuer)<SR>$($cert.SerialNumber)"
                "X509:<SKI>$($cert.SubjectKeyIdentifier)"
                "X509:<SHA1-PUKEY>$($cert.CertificateHash)"
            )
        }

        # Clean up any duplicate identiites, typically this is for the non cert specific ones
        $certAltSecurityIdentities = $certAltSecurityIdentities | Select-Object -Unique
        
        try {
            #Loop through each cert identity and add it to the device if missing
            ForEach ($certAltSecurityIdentity in $certAltSecurityIdentities) {
                if (!($certAltSecurityIdentity -in $device.altSecurityIdentities)) {
                    $altSecurityIdentities = @{"altSecurityIdentities" = $certAltSecurityIdentity.ToString()}
                    Write-Host "<Certificate Binding> Mapping '$($device.Name) ($($device.description))' to '$certAltSecurityIdentity'" -ForegroundColor Green
                    Get-ADComputer -Filter "(servicePrincipalName -like 'host/$($device.Name)')" | Set-ADComputer -Add $altSecurityIdentities
                }
                else {
                    Write-Host "<Certificate Binding> Mapping Exists for '$($device.Name) ($($device.description))' to '$certAltSecurityIdentity'" -ForegroundColor Yellow
                }
            }
        }
        catch {  
            Write-Host "$($_.Exception.Message)" -ForegroundColor Green
            Write-Host "<Certificate Binding> Error mapping AADx509 computer object '$($device.Name) ($($device.description))' to '$certAltSecurityIdentity'" -ForegroundColor Green
        }

        try {
            # Loop through all identities on the deivce and remove any stale entries
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
        # If device no longer has any valid certificates but has listed identities, clear the identities
        if ($device.altSecurityIdentities) {
            Write-Host "<Certificate Binding> No certificates found for '$($device.Name) ($($device.description))' altSecurityIdentities not <null>, clearing altSecurityIdentities" -ForegroundColor Yellow
            Get-ADComputer -Filter "(servicePrincipalName -like 'host/$($device.Name)')" | Set-ADComputer -Clear "altSecurityIdentities"
        }
    }
}

# AAD Group Writeback update local group. The writeback groups load in msDS-Device objects for AADJ Devices which will not work with NPS. The below matches those devices to computer devices and updates a AD Group that is used in NPS
$aadADObjectFilter = '(objectClass -eq "msDS-Device")'
Write-Host "<AAD Group Mapping> Starting AAD to AD group mapping..." -ForegroundColor Green
foreach ($group in $groupList) {
    Write-Host "<AAD Group Mapping> Processing group $($group.GroupName)..." -ForegroundColor Green
    #Get all Ojbjects from the 2 groups. 
    $adGroup = Get-ADGroup -Filter "cn -eq '$($group.ADGroupName)'"
    $aadGroup = Get-ADGroup -Filter "adminDescription -eq '$($group.AADGroupID)'"
    
    # Get all membership details from groups
    $adGroupMembers = Get-ADGroup -Filter "cn -eq '$($group.ADGroupName)'" | Get-ADGroupMember
    $aadGroupMembers = $(Get-ADObject -Filter $aadADObjectFilter -Properties MemberOf, servicePrincipalName, Name, DisplayName, objectClass, msDS-DeviceObjectVersion) | Where-Object -Property "MemberOf" -Contains $aadGroup.DistinguishedName | Sort-Object -Property "DisplayName"
    
    Write-Host "<AAD Group Mapping> AAD Group has $(($aadGroupMembers | Measure-Object).Count) members and AD has $(($adGroupMembers | Measure-Object).Count) members." -ForegroundColor Green
    Write-Host "<AAD Group Mapping> Checking to see if group $($adGroup.Name) is missing any members." -ForegroundColor Green
    foreach ($aadGroupMember in $aadGroupMembers) {
        try {
            Clear-Variable adComputer, aadComputerName, adComputerNames -Force -ErrorAction SilentlyContinue
            # Check if object is missing
            if (!($aadGroupMember.Name -in $adGroupMembers.Name -or $aadGroupMember.Name -in $adGroupMembers.ObjectGUID)) {
                # Match object by class to determan what property to compare to for AADJ vs AD Devices. 
                switch($aadGroupMember.ObjectClass){
                    "computer"{
                        $adComputer = Get-ADComputer -Filter "cn -eq '$($aadGroupMember.Name)'"
                    }
                    "msDS-Device"{
                        IF ($aadGroupMember."msDS-DeviceObjectVersion" -eq 2){
                            $adComputer = Get-ADComputer -Filter "cn -eq '$($aadGroupMember.Name)'"
                        }else{
                            $adComputer = Get-ADComputer -Filter "ObjectGUID -eq '$($aadGroupMember.Name)'"
                        }
                        
                    }
                }
                Write-Host "<AAD Group Mapping> Adding $($aadGroupMember.Name)($($aadGroupMember.DisplayName)) member to group $($adGroup.Name)" -ForegroundColor Green
                # Add deivce object to AD Group
                Add-ADGroupMember -Identity $adGroup.Name -Members $adComputer.DistinguishedName
            }
        }
        catch {
            Write-Host "<AAD Group Mapping> Unable to locate computer object $($aadGroupMember.Name)($($aadGroupMember.DisplayName))" -ForegroundColor Red
        }
    }

    Write-Host "<AAD Group Mapping> Checking to see if we need to remove any members from group $($adGroup.Name)." -ForegroundColor Green
    #Looking for any stale memberships and deleting stale devices from AD Group.
    foreach ($adGroupMember in $adGroupMembers) {
        try {
            if (!($adGroupMember.Name -in $aadGroupMembers.Name -or $adGroupMember.ObjectGUID -in $aadGroupMembers.Name)) {            
                Write-Host "<AAD Group Mapping> Removing $($adGroupMember.Name) member from group $($adGroup.Name)" -ForegroundColor Yellow
                Remove-ADGroupMember -Identity $adGroup.Name -Members $adGroupMember.distinguishedName -Confirm:$False
            }
        }
        catch {
            Write-Host "<AAD Group Mapping> Unable to remove computer object $($adGroupMember.Name)($($adGroupMember.Description)) from group $($adGroup.Name)" -ForegroundColor Red
        }
    }
}
