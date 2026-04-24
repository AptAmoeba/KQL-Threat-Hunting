```kql
// Public IP in NIC Config
// Identifies devices with public IP Addresses in their NIC config. E.g: User plugs their laptop straight into their WAN.
// Pulls most recent user but does not necessarily indicate fault directly. They could have simply joined a poorly-configured network.
DeviceNetworkInfo
| join kind=leftouter (DeviceLogonEvents
    | where Timestamp > ago(1d)
    | where LogonType in ("Interactive", "CachedInteractive")
    | summarize arg_max(Timestamp, AccountName, AccountDomain) by DeviceId) on DeviceId
//
| where ipv4_is_private(IPv4Dhcp) == false
| extend IPAddress = tostring(parse_json(IPAddresses)[0].IPAddress)
| distinct DeviceName, AccountName, IPAddress, NetworkAdapterType, MacAddress, DeviceId, DefaultGateways, IPAddresses, DnsAddresses, NetworkAdapterVendor
| project Timestamp, DeviceName, AccountName, IPAddress, NetworkAdapterType, ["Verbose Info"]=pack("Mac Address", MacAddress, "Device ID", DeviceId, "Gateway", DefaultGateways, "IP Addresses", IPAddresses, "DNS Servers", DnsAddresses, "NIC Vendor", NetworkAdapterVendor)
//| sort by Timestamp desc //Redundant with "| distinct" operator in practice. to sort, comment-out the Distinct line. 
```
