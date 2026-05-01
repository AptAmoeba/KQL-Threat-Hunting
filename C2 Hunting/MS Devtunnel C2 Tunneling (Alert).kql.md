```kql
// Created by AptAmoeba
// (MITRE T1219.001) - IDE C2 Tunneling
// Devtunnel Connection Alert - You should already have these blocked on the network-level. This is just a verification check!
// Further Reading: https://www.syonsecurity.com/post/devtunnels-for-c2
union DeviceNetworkEvents, DeviceProcessEvents
| where RemoteUrl has_any ("devtunnels", 
    "uks1.devtunnels.ms", 
    "tunnels.api.visualstudio.com", 
    "TunnelsCliDownload")
    or InitiatingProcessFileName contains "devtunnel.exe"
    or FileName has_any ("devtunnel.dll", "devtunnel.exe")
| project Timestamp, Device=DeviceName, User=InitiatingProcessAccountName, LocalIP, RemoteIP, URL=RemoteUrl, RemotePort, ActionType, DeviceId, ReportId
```
