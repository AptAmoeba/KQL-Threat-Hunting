# KQL Threat Hunting Queries
A collection of Threat Hunting queries I've written &amp; made public for 365 Defender's 'Advanced Threat Hunting'

Below are some sample queries. Full directory is above. 

&nbsp;

## Sample List:
### > Mirror Masquerade Spoofing (Sender Address == Recipient Address)
```KQL
// Created by BunchOfWetFrogs
// (MITRE T1672) - Searches for SenderFrom (Header) + SenderMailFrom (Server) spoofing where SPF fails. 
// Requirements: You must trust your own domain via SPF.
let SpoofEmailScan = EmailEvents
| where SenderFromAddress == RecipientEmailAddress and SenderMailFromAddress == RecipientEmailAddress
| where parse_json(AuthenticationDetails)["SPF"] in~ ('fail', 'softfail')
| where DeliveryLocation has 'Inbox'
| project Timestamp, RecipientEmailAddress, Subject, SenderFromAddress, AttachmentCount, SenderMailFromAddress, SenderIPv4, DeliveryLocation, AuthenticationDetails, InternetMessageId, NetworkMessageId;
SpoofEmailScan
| join kind=leftouter (
    EmailAttachmentInfo
    | project NetworkMessageId, FileName, SHA256
    ) on NetworkMessageId
| project Timestamp, ["Recipient"] = RecipientEmailAddress, Subject, ["Sender (Header - What User Sees)"] = SenderFromAddress, SenderIPv4, FileName, SHA256, ["Sender (MailFROM - What Server Sees)"] = SenderMailFromAddress, DeliveryLocation, AuthenticationDetails, InternetMessageId, NetworkMessageId
| sort by Timestamp desc
```
```KQL
// Find Downloads: Simply click the Hash in the output of the above query to scan your environment for matches.
// WARNING: Users do NOT have to download attachments to execute them, due to how emails handle .svg/.html/.pdf/etc. To search for non-download executions, use the following query:
DeviceEvents
| where ActionType == 'NamedPipeEvent'
| where parse_json(AdditionalFields)["FileOperation"] =~ "File opened"
| where FileName == "<FileName from phish>"
```
Future Improvements:
- Automatically check whether a user interacted with the payload via either method (Download or direct-execution)! 

&nbsp;

-----

&nbsp;

### > (BYOVD) Vulnerable Driver Load Events

```KQL
// Created by BunchOfWetFrogs
// (MITRE T1068) - Scans for Vulnerable Driver/Theoretically Vulnerable Driver Load Events
// Output: Find 'Vulnerable Driver' attributes at https://www.loldrivers.io/ 
let MaliciousDriverTable=externaldata(BYOVDTable:string)
// The AV repo is updated faster than the MD5 repo, so we manually extract the MD5 & match it to any DevImgLoadEvents MD5.
[h'https://raw.githubusercontent.com/magicsword-io/LOLDrivers/main/detections/av/LOLDrivers.hdb']
| parse BYOVDTable with Hash:string ":" Arbitrary:int ":" MDFileName:string
| extend ExtMD5 = substring(MDFileName, 0, strlen(MDFileName) -4);
//
DeviceImageLoadEvents
| where FileName endswith ".sys"
| join MaliciousDriverTable on $left.MD5 == $right.ExtMD5
| extend ParentProcess = strcat(InitiatingProcessFileName, " (", InitiatingProcessVersionInfoProductName, ")")
| project Timestamp, DeviceName, User=InitiatingProcessAccountName, ["Vulnerable Driver"]=FileName, Location=FolderPath, ["Parent Process"]=ParentProcess, ProcessCLI=InitiatingProcessCommandLine, SHA256, MD5, DeviceId, ReportId 
| sort by Timestamp desc
```
Future Improvements:
- Pull Vulnerable Drivers from more sources.
- Automatically extract Driver capabilities and list their attributes ("EDR-Killing", "Privilege Escalation", etc.).

