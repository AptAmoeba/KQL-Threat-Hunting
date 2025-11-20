```kql
// Search for endpoints inheriting Class B addresses matching the known-default Wifi Pineapple subnetting schema
// MITRE T1557.004
DeviceNetworkInfo
| where IPAddresses contains '172.16.42.' or DefaultGateways contains '172.16.42.' or DnsAddresses contains '172.16.42.'
| extend NetworkName = tostring(parse_json(ConnectedNetworks)[0].Name)
| project Timestamp, DeviceName, ["Adapter Status"]=NetworkAdapterStatus, ["Resolved Network Name"]=NetworkName, IPAddresses, DefaultGateways, NetworkAdapterType, DeviceId, ReportId
| sort by Timestamp desc
```
