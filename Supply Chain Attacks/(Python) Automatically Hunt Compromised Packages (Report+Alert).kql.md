## How This Query Works
This query pulls in a remote raw csv of known-compromised package versions from a github repo by DataDog, parses it for Python packages, and then compares the known-compromised packages in a case-insensitive search of your environment's Python library directories.

## Query 
```kql
// Created by AptAmoeba/BunchOfWetFrogs
// Python Supply Chain Hunting (case-insensitive IoC PackageName hunting, live-updatable via remote repo)
//
let UserInstallLibPath = @"C:\\Users\\[^\\]+\\AppData\\Local\\Packages\\[^\\]+\\LocalCache\\local-packages\\Python[^\\]+\\site-packages\\[^\\]+";
let SysInstallLibPath = @"C:\\Program Files[^\\]*\\Python[^\\]+\\Lib\\site-packages\\[^\\]+";//Supports both \Program Files\ & \Program Files (x86)\ (idk why you'd be running 32-bit Python but let your freak flag fly i guess) 
let CompromisedLibs =
    externaldata(artifact_type:string, name:string, affected_versions:string)
    [h'https://raw.githubusercontent.com/DataDog/indicators-of-compromise/refs/heads/main/teampcp/iocs.csv']
    with (format="csv", ignoreFirstRecord=true)
    | where artifact_type == "pypi package"
    | project name=tolower(name), affected_versions;
//
DeviceFileEvents
| where ActionType in ("FileCreated", "FileModified")
| where FolderPath matches regex UserInstallLibPath
      or FolderPath matches regex SysInstallLibPath
| extend LibraryFolder = tolower(extract(@"site-packages\\([^\\]+)", 1, FolderPath))
| where isnotempty(LibraryFolder)
| join kind=inner (CompromisedLibs) on $left.LibraryFolder == $right.name
| summarize FirstSeen=min(Timestamp) by DeviceName, RequestAccountName, LibraryFolder, InitiatingProcessCommandLine, InitiatingProcessParentFileName, affected_versions
| project FirstSeen, DeviceName, User=RequestAccountName, Library=LibraryFolder, ["Vulnerable Versions"]=affected_versions, CLI=InitiatingProcessCommandLine, ["Initiated By"]=InitiatingProcessParentFileName
```

