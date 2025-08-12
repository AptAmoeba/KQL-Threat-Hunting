```kql
//Created by BunchOfWetFrogs
//Organized, clean version! This is not NRT compatible. Check the Alert version for Real-Time alerting!
let MacroScheduledTaskEvents = DeviceEvents
| where InitiatingProcessCommandLine has_any ("WINWORD.EXE", "EXCEL.EXE", "POWERPNT.EXE", "MSPUB.EXE", "VISIO.EXE", "OUTLOOK.EXE")
| extend Desc = tostring(parse_json(AdditionalFields).Description)
| where Desc contains "created the scheduled task" //Format: "<Office Product> created the scheduled task <ScheduledTaskName>"
| extend MalDoc = extract(@'"([A-Z]:\\[^"]+\.(docx?|docm|xls[xm]?|ppt[xm]?))"', 1, InitiatingProcessCommandLine)
| extend ScheduledTaskName = extract(@"created the scheduled task\s+(\S+)", 1, Desc)
| sort by Timestamp desc;
//
MacroScheduledTaskEvents
| distinct Timestamp, DeviceName, Offender=InitiatingProcessAccountName, ["Scheduled Task Name"]=ScheduledTaskName, ["Execution Source (Maldoc)"]=MalDoc, FileName, Description=Desc, InitiatingProcessCommandLine, FolderPath, SHA256, ReportId, DeviceId
| sort by Timestamp desc
```
