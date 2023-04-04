# AADJ-x509-Device-Sync
## Thanks
This is an adaptation of https://github.com/tcppapi/AADx509Sync by @tcppapi

This script completes the workflow for x509Certificates for Device Auth. We are not using user certificates in this version. 

# Prerequisites
- Azure App Registration for connecting to AAD/Intune
- Device Certificates issued via SCEP - PKCS Certificates may work, but the script is looking for a specific SAN when comparing certificate to device. 
- AAD Group Writeback v2 enabled in ADDC 
- PowerShell Modules 
  - ActiveDirectory
  - WindowsAuotpilotIntune
  - PSPKI
- AD Group for creating Intune AP Device Records
- AAD Group for maintaining device profiles for x509 Auth 
- AD Group for maintaining device objects for NPS


# Process 
## Phase 1 
In phase 1 of this script, we are pulling down all AP devices from Intune and comparing them to the AD OU provided to add the objects. 

NOTE! In the native version of this script, it will remove stale AP records from AD. If the device is deleted from Intune AP, this will remove it from AD on next sync.

## Phase 2
In Phase 2 we are gathering information about all the AP devices and active certificates in your PKI environment. From there we are matching the certificates to the devices and adding any missing entries in the AD Objects attribute "altSecurityIdentities"

NOTE! In the native version of this script is will remove all stale "altSecurityIdentities" entries that do not match your PKI records

## Phase 3
In Phase 3 we are comparing the AAD group to the AD group and updating the AD group membership so that NPS knows which devices to allow in the workflow. In this method all membership assignments should be made in AAD, and let this script manage the AD Group. Any manual entries to the AD group will be cleared out on next sync. 

NOTE! In the native version of this script, it will remove all stale members from the AD group that do not match the AAD Group. 

# Setup 
I will not go through each step-in detail on this but rather a quick overview of what needs setup. 

## Azure App Registration
Minimum permissions for App registration

![image](https://user-images.githubusercontent.com/56890437/229801998-5a2d8841-1c7d-4837-8f34-79b97d453acd.png)


## AAD Group Writeback v2
Nothing super specific here, just followed the following doc's

https://learn.microsoft.com/en-us/azure/active-directory/hybrid/how-to-connect-group-writeback-v2

https://learn.microsoft.com/en-us/azure/active-directory/hybrid/how-to-connect-group-writeback-enable

this is always good to have if it’s not enabled 😊

https://learn.microsoft.com/en-us/azure/active-directory/hybrid/how-to-connect-sync-recycle-bin


## Intune Device Certificate
Sample configuration of SCEP Certificate

Important parts are the subject alternative names specifically the host/{{AAD_Device_ID}} entry. This is used when filtering certificates to devices records.

![image](https://user-images.githubusercontent.com/56890437/229803126-03c85217-50af-472c-94d5-dc6089e95553.png)
