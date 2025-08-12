```kql
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
