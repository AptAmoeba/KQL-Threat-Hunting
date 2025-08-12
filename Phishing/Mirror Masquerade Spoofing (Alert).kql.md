```kql
// Created by BunchOfWetFrogs
// (MITRE T1672) This script automatically detects From+MailFROM spoofing.
// This script also automatically extracts payloads & checks if users executed them.
// 
// Requirements: You must trust your own domain via SPF; Add any Email Security Servers you own to EmailServerWhitelist
let EmailServerWhitelist = dynamic(['IPAddr1', 'IPAddr2', 'etc']);
// ^Place your Email Security Provider IPs here!
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
