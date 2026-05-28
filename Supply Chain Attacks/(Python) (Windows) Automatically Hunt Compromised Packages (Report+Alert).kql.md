## How This Query Works (Automatic Detection of Confirmed-Compromised Packages) 
This query implements our first automatic scraper for self-updating tables! Unrooted built a scraper that will pull updates for compromised package lists and compile them into a normalized csv file hosted on this github (/scrapers-output/packages.csv). This query fetches that csv, parses it, then compares the known-compromised packages in a case-insensitive search of your environment's Python library directories.

The ```CompromisedLibs``` remote list can be ANY remote list you desire; it doesn't have to be ours! For retrofitting this query for future breaches/lists, pull the raw data list URL and then import the data however you see fit. The other logic will stay the same. 

Because Python does not list version numbers in their directories, this script will alert on recent modifications/updates/installs to the associated package name. It will then display the known-vulnerable versions, and it is up to the Hunter to confirm the versioning. Additionally, the script will show the particular CLI args that caught the event, allowing you to hunt causal actions. 

## Query 
```kql
// Query created by AptAmoeba/BunchOfWetFrogs; Dynamic compromised package ingestion built by Unrooted
// Python Supply Chain Hunting (case-insensitive IoC PackageName hunting, live-updatable via remote repo)
//
let UserInstallLibPath = @"C:\\Users\\[^\\]+\\AppData\\Local\\Packages\\[^\\]+\\LocalCache\\local-packages\\Python[^\\]+\\site-packages\\[^\\]+";
let SysInstallLibPath = @"C:\\Program Files[^\\]*\\Python[^\\]+\\Lib\\site-packages\\[^\\]+";//Supports both \Program Files\ & \Program Files (x86)\ (idk why you'd be running 32-bit Python but let your freak flag fly i guess) 
let CompromisedLibs = externaldata(
    ecosystem:string, package:string, version:string,
    detected_at:datetime, published_at:datetime, scraped_at:datetime)
    [@"https://raw.githubusercontent.com/AptAmoeba/KQL-Threat-Hunting/refs/heads/main/scrapers-output/packages.csv"]
    with (format="csv", ignoreFirstRecord=true);
//
DeviceFileEvents
| where ActionType in ("FileCreated", "FileModified")
| where FolderPath matches regex UserInstallLibPath
      or FolderPath matches regex SysInstallLibPath
| extend LibraryFolder = tolower(extract(@"site-packages\\([^\\]+)", 1, FolderPath))
| where isnotempty(LibraryFolder)
| join kind=inner (CompromisedLibs) on $left.LibraryFolder == $right.package
| summarize FirstSeen=min(Timestamp) by DeviceName, RequestAccountName, LibraryFolder, InitiatingProcessCommandLine, InitiatingProcessParentFileName, version
| project FirstSeen, DeviceName, User=RequestAccountName, Library=LibraryFolder, ["Vulnerable Versions"]=version, CLI=InitiatingProcessCommandLine, ["Initiated By"]=InitiatingProcessParentFileName
```
