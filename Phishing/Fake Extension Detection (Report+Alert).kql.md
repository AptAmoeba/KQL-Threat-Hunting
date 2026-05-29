## Fake Extension Detection

Some malware campaigns (often ones delivered through phishing) utilize fake extensions and fake icons to make malicious files appear as documents. 

This also abuses the Windows default behavior to hide file extensions in explorer.exe, so files appear to the victim as different filetypes.

- Example: "Important-Document.pdf.exe"
- Looks like: "Important-Document.pdf"

The following query searches for commonly faked filetypes followed by file extensions associated with malicious capability.

```kql
// Created by AptAmoeba/BunchOfWetFrogs
// Fake Extension Detection - Reports Suspicious Files
let FakeExtension = dynamic(['.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.txt', '.jpg', '.jpeg', '.png', '.mp3', '.mp4', '.zip']);
let RealExtension = dynamic(['.exe', '.lnk', '.js', '.jse', '.mshta', '.url', '.hta', '.vbs', '.vbe', '.bat', '.cmd', '.ps1', '.scr', '.reg']);//, '.'
let FakePattern = replace_string(strcat_array(FakeExtension, '|'), '.', '\\.');
let RealPattern = replace_string(strcat_array(RealExtension, '|'), '.', '\\.');
let FullPattern = strcat('(?i)(', trim_end('|', FakePattern), ')(', trim_end('|', RealPattern), ')$');
DeviceFileEvents
| where ActionType == "FileCreated"
| where not(FolderPath has_any ('\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\', '\\AppData\\Roaming\\Microsoft\\Office\\Recent', '\\AppData\\Roaming\\Microsoft\\'))//Ignore MRU Cache
| where FileName !startswith "__PSScriptPolicyTest_"
| where FileName matches regex FullPattern
| extend susFileName = replace_string(FileName, '%20', ' ')
| extend SusExtension = extract(@'(\.[^.]+\.[^.]+)$', 1, FileName)
| project Timestamp, DeviceName, User=InitiatingProcessAccountName, SusExtension, ["Suspicious FileName"]=susFileName, FolderPath, SHA256, InitiatingProcessFileName, ["Raw FileName"]=FileName
| sort by Timestamp desc
```

Adjust each list as needed:
- FakeExtension is a list of commonly faked extensions in these attacks.
- RealExtension is a list of common extensions associated with malicious files. 
