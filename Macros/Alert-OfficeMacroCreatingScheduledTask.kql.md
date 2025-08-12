```kql
// Created by BunchOfWetFrogs
// NRT Ver. - this dumps the raw events for each individual trigger. These are system-generated events. 
// Check the Report version of this query for organized, deduplicated output!
DeviceEvents
| where InitiatingProcessCommandLine has_any ("WINWORD.EXE", "EXCEL.EXE", "POWERPNT.EXE", "MSPUB.EXE", "VISIO.EXE", "OUTLOOK.EXE")
| extend Desc = tostring(parse_json(AdditionalFields).Description)
| where Desc contains "created the scheduled task" //Format: "<Office Product> created the scheduled task <ScheduledTaskName>"
| extend MalDoc = extract(@'"([A-Z]:\\[^"]+\.(docx?|docm|xls[xm]?|ppt[xm]?))"', 1, InitiatingProcessCommandLine)
| extend ScheduledTaskName = extract(@"created the scheduled task\s+(\S+)", 1, Desc)
| project Timestamp, DeviceName, Offender=InitiatingProcessAccountName, ["Scheduled Task Name"]=ScheduledTaskName, ["Execution Source (Maldoc)"]=MalDoc, FileName, Description=Desc, InitiatingProcessCommandLine, FolderPath, SHA256, ReportId, DeviceId
| sort by Timestamp desc
```
