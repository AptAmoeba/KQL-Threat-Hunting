```kql
// Created by BunchOfWetFrogs
// DLLs launched from common user directories
DeviceImageLoadEvents
| where ActionType == "ImageLoaded"
| where InitiatingProcessAccountName != "system"
| where FolderPath matches regex @"^C:\\Users\\[^\\]+\\(Desktop|Downloads|Documents|Pictures|Videos|Music)\\.*\.dll$" 
     or FolderPath matches regex @"^C:\\Users\\[^\\]+\\OneDrive - [^\\]+\\(Desktop|Downloads|Documents|Pictures|Videos|Music)\\.*\.dll$" //Accounting for OneDrive Envs
// -- WHITELIST:
//| where not(InitiatingProcessAccountName has_any ("<User1>", "<User2>"))
//| where not(FolderPath has_any ("<Path1>", "<path2>"))
// -- END WHITELIST
| extend Process = extract(@"[^\\]+$$", 0, InitiatingProcessFolderPath) //Grabbing the source Executable
| project Timestamp, Device=DeviceName, User=InitiatingProcessAccountName, DLL=FileName, ["DLL Path"]=FolderPath, Process, ProcessPath=InitiatingProcessFolderPath, InitiatingProcessIntegrityLevel, MD5, SHA1, DeviceId, ReportId
| sort by Timestamp desc
```
