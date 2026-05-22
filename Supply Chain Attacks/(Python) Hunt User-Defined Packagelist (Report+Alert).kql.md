
```kql
// Created by AptAmoeba/BunchOfWetFrogs
// Python Supply Chain Hunting (fuzzysearch for affected libraries or search recently updated libs in your org)
//
//let HuntedLibs = dynamic(["Library1", "numpy", "yeet"]); //Uncomment for on-demand fuzzy library hunting
// ^You could also swap HuntedLibs and the associated search for a remote URL csv parser to pull directly from IoC repos to dynamically scan over time as they update! 
let UserInstallLibPath = @"C:\\Users\\[^\\]+\\AppData\\Local\\Packages\\[^\\]+\\LocalCache\\local-packages\\Python[^\\]+\\site-packages\\[^\\]+";
let SysInstallLibPath = @"C:\\Program Files[^\\]*\\Python[^\\]+\\Lib\\site-packages\\[^\\]+";//Supports both \Program Files\ & \Program Files (x86)\ (idk why you'd be running 32-bit Python but let your freak flag fly i guess) 
DeviceFileEvents
| where ActionType in ("FileCreated", "FileModified")
| where FolderPath matches regex UserInstallLibPath
      or FolderPath matches regex SysInstallLibPath
| extend LibraryFolder = extract(@"site-packages\\([^\\]+)", 1, FolderPath)
| where isnotempty(LibraryFolder)
//| where HuntedLibs in~ (CompromisedPackages) //uncomment if using HuntedLibs list
| summarize FirstSeen=min(Timestamp) by DeviceName, RequestAccountName, LibraryFolder, InitiatingProcessCommandLine, InitiatingProcessParentFileName
| project FirstSeen, DeviceName, User=RequestAccountName, Library=LibraryFolder, CLI=InitiatingProcessCommandLine, ["Initiated By"]=InitiatingProcessParentFileName
```
