```kql
// Created by AptAmoeba/BunchOfWetFrogs
// Scans for Vulnerable Driver/Theoretically Vulnerable Drivers in new files. Caveat: Some of these drivers need Administrator perms to be abusable! Do the research on each result.
// Output: Find 'Vulnerable Driver' attributes at https://www.loldrivers.io/ 
let MaliciousDriverTable=externaldata(BYOVDTable:string)
// The AV repo is updated faster than the MD5 repo, so we manually extract the MD5 & match it to any downloads filenames matching it. 
[h'https://raw.githubusercontent.com/magicsword-io/LOLDrivers/main/detections/av/LOLDrivers.hdb']
| parse BYOVDTable with Hash:string ":" Arbitrary:int ":" MDFileName:string
| extend ExtMD5 = substring(MDFileName, 0, strlen(MDFileName) -4);
//
DeviceFileEvents
| join MaliciousDriverTable on $left.MD5 == $right.ExtMD5
| extend ParentProcess = strcat(InitiatingProcessFileName, " (", InitiatingProcessVersionInfoProductName, ")")
| project Timestamp, DeviceName, User=InitiatingProcessAccountName, ["Vulnerable Driver"]=FileName, Location=FolderPath, ["LOLDrivers.io Hash Hit"]=ExtMD5, ["Local File MD5"]=MD5, ["Parent Process"]=ParentProcess, ProcessCLI=InitiatingProcessCommandLine, ActionType, PreviousFileName, SHA1, SHA256, DeviceId, ReportId 
| sort by Timestamp desc
```
