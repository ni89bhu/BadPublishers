#############################################################################################################################################################
#<Description>                                                                                                                                              #
#This script will find bad vendor from new signer event.                                                                                                    #
#                                                                                                                                                           #
#<Input>                                                                                                                                                    #
#EventTracker 9 with working instance of EDR.      													           						        	            #
#																																							#
#<Output>                                                                                                      												#
#Logs with event id 11004.                                                                                                                                  #
#                                                                                                                                                           #
#Author:kumarnitesh@eventtracker.com                                                                                                                        #
#CreatedOn:3/10/20                                                                                                                                          #
#ModifiedOn:7/14/20                                                                                                                                         #
#############################################################################################################################################################
param (
[string]$Event_log_type,
[string]$log_type,
[string]$computer,
[string]$source,
[string]$category,
[string]$event_id,
[string]$user,
[string]$description
)

$description = 'New activity found:
Signer: Pass and Play
Job Name: EventTracker_EDR_Found_New_Signer
System: W3674
Time: 2020-03-09 10:03:35

 

Source Event:
Id: 3524
Source: EventTracker
Description: A process has been audited by EventTracker.
Reason: Loaded binary not available in safe list
Hash (MD5): ed9b61946778208f07c6086f88e08594
Image Name: SolidCore.dll
Image File Name: C:\Program Files (x86)\Adobe\Acrobat 10.0\Acrobat\plug_ins\SaveAsNonPDF\Solid\SolidCore.dll
Account Name: Mdemeritte
Account Domain: BMA
Process ID: 6656
Process Name: Acrobat.exe
Process Image File Name: C:\Program Files (x86)\Adobe\Acrobat 10.0\Acrobat\Acrobat.exe
System Name: W3674
File Version: 7.0.915.0
File Description: SolidCore
Product Name: Solid Framework
Product Version: 7.0.915.0
Signed: Yes
Signer: Solid Documents
Signed On: 2011-03-05T23:36:45Z
Counter Signed: Yes
Counter Signer: VeriSign Time Stamping Services Signer - G2
Counter Signed On: 2011-03-05T23:36:45Z

 

OS Name : Microsoft Windows 7 Enterprise
Version : 6.1.7601

 

Antivirus Name : CylancePROTECT
instanceGuid : {BAE91205-425B-4A8A-6DBD-A8412F03F4FF}
pathToSignedProductExe : C:\Program Files\Cylance\Desktop\CylanceSvc.exe
pathToSignedReportingExe : C:\Program Files\Cylance\Desktop\CylanceSvc.exe
productState : 397312
status : Enabled
definitions : Up to date'
$path = (Get-ItemProperty -Path 'registry::hklm\SOFTWARE\Wow6432Node\Prism Microsystems\EventTracker\Manager').INSTALLPATH

$threshold = '2'

$regex = "(?si)New activity found\:.*?Signer\:\s+(.*?)Job Name\:.*?System\:(.*?)Time\:"

Filter Extract
{
$_ -match $regex > $null
[PSCustomObject]@{
Signer = ($Matches[1]).trim()
System = ($Matches[2]).trim()
}}

$sg = ($description | Extract).Signer
$sy = ($description | Extract).System

Function Get-VendorDetection {
  Param($vendor)
  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$query = Invoke-RestMethod -Method Get -Uri "https://www.freefixer.com/library/publisher/$vendor/" -ErrorAction SilentlyContinue -ErrorVariable "notfound"
If($notfound){
$myObject = [PSCustomObject]@{
    Vendor     = "$vendor"
    Detection = "Unknown"
}}
If(!$query){
$myObject = [PSCustomObject]@{
    Vendor     = "Unknown"
    Detection = "Unknown"
}}
else{
$HTML = New-Object -Com "HTMLFile"
$HTML.IHTMLDocument2_write($query)
$value = ($html.title).trim()
$detection = ([regex]::match($value,'^.*?\s+\-\s+(.*?)\s+Detection Rate$').Groups[1].Value).trim() -replace "%",""
$detection1 = $detection/100
$myObject = [PSCustomObject]@{
    Vendor     = "$vendor"
    Detection = "$detection"
}}
$myObject
  }

$result = Get-VendorDetection -vendor $sg

If (($result.Detection -gt $threshold) -and ($result.Detection -ne "Unknown"))
{$sc = $result.Detection
& "$path\ScheduledActionScripts\sendtrap.exe" ET $env:COMPUTERNAME $computer 3 2 "EventTracker" 0 11004 "Malicious vendor found `n`tSystemName: $sy `n`tSigner: $sg `n`tScore: $sc`%" N/A N/A " " 14505}
