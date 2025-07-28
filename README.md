# KQL Threat Hunting Queries
A collection of Threat Hunting queries I've written &amp; made public for 365 Defender's 'Advanced Threat Hunting'

Below are some sample queries. Full directory is above. 

&nbsp;

## Sample List:
### > Locate Mirror Masquerade Spoofing & Detect Payload Execution Status per Victim
```KQL
// Created by BunchOfWetFrogs
// (MITRE T1672) This script does the following:
// - Identifies From+MailFROM spoofing, extracts payloads if present
// - Automatically detects whether the payload was executed by the user.
// 
// Requirements: You must trust your own domain via SPF; Adjut EmailServerWhitelist if necessary.
let EmailServerWhitelist = dynamic(['IPAddr1', 'IPAddr2', 'etc']); //These demo entries are fine to leave as-is! They won't break the query!
// ^Place your Email Security Provider IPs here if needed!
//
let SpoofEmailScan = EmailEvents
| where SenderFromAddress == RecipientEmailAddress and SenderMailFromAddress == RecipientEmailAddress
| where parse_json(AuthenticationDetails)["SPF"] in~ ('fail', 'softfail')
| where parse_json(AuthenticationDetails)["DMARC"] in~ ('fail', 'temperror', 'permerror')
| where DeliveryLocation == 'Inbox/folder'
| where SenderIPv4 !in (EmailServerWhitelist)
| project Timestamp, RecipientEmailAddress, Subject, SenderFromAddress, AttachmentCount, SenderMailFromAddress, SenderIPv4, AuthenticationDetails, InternetMessageId, NetworkMessageId;
let AttachmentData = EmailAttachmentInfo
| where not(FileName matches regex @"^base64Image_|\.png$|\.jpg$")
| project NetworkMessageId, FileName, SHA256, FileType;
let ConsolidationTable = SpoofEmailScan
| join kind=leftouter (AttachmentData) on NetworkMessageId
| extend Username = tostring(split(RecipientEmailAddress, "@")[0]);
ConsolidationTable
| join kind=leftouter (
    DeviceProcessEvents
    | project DeviceName, AccountName, InitiatingProcessCommandLine, ProcessCreationTime
) on $left.Username == $right.AccountName
| extend PayloadExecuted = iff(InitiatingProcessCommandLine has FileName, "True", "False")
| distinct Timestamp, RecipientEmailAddress, Subject, SenderFromAddress, SenderMailFromAddress, SenderIPv4, AttachmentCount, AuthenticationDetails, InternetMessageId, NetworkMessageId, SHA256, FileName, PayloadExecuted
| summarize PayloadExecuted = max(PayloadExecuted), Attachments = make_set(pack("FileName", FileName, "SHA256", SHA256)) by Timestamp, RecipientEmailAddress, Subject, SenderFromAddress, SenderMailFromAddress, SenderIPv4, AttachmentCount, AuthenticationDetails, InternetMessageId, NetworkMessageId
| project Timestamp, ["Payload executed?"] = PayloadExecuted,
          Recipient=RecipientEmailAddress, Subject,
          ["Sender (Header - What User Sees)"]=SenderFromAddress,
          ["Sender (MailFROM - What Server Sees)"]=SenderMailFromAddress,
          SenderIPv4, Attachments, AttachmentCount, AuthenticationDetails, InternetMessageId, NetworkMessageId
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

