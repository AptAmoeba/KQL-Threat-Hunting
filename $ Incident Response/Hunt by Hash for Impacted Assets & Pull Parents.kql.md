```kql
// Created by AptAmoeba/BunchOfWetFrogs
// Super simple hunting query to identify machines with a given hash across an environment, and yield its parent's hash.
DeviceFileEvents
| where MD5 == ''//Compatible alrogithms: hotswap between SHA1, SHA256, & MD5
| project DeviceName, RequestAccountName, FileName, MD5, FolderPath, InitiatingProcessFileName, InitiatingProcessSHA256, InitiatingProcessFolderPath
```
