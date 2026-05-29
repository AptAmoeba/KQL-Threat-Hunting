Technically this is in beta. Verified to work when Office files spawn scheduled tasks, but haven't tested all possibilities yet.

```kql
// Created by AptAmoeba/BunchOfWetFrogs
// User Creating Scheduled Task; Technically this may generate False Positives as programs can use a user's permissions to set a scheduled task, but that should be relatively uncommon, and would be worth investigating.
DeviceEvents
| extend Desc = tostring(parse_json(AdditionalFields).Description)
| where Desc contains "created the scheduled task"
| extend ScheduledTaskName = extract(@"created the scheduled task\s+(\S+)", 1, Desc)
| project Timestamp, DeviceName, Offender=InitiatingProcessAccountName, ["Scheduled Task Name"]=ScheduledTaskName, FileName, Description=Desc, InitiatingProcessCommandLine, FolderPath, SHA256, ReportId, DeviceId
```
