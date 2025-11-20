```kql
// Flags on API connections from AzureHound's default User-Agent
// MITRE ~S0521
AADSignInEventsBeta
| where UserAgent contains "azurehound"
// (Output) Did it successfully connect? (ErrorCode=0, yes; ErrorCode!=0, no)
// (Output) Blocked by CAP Policies?: (If ErrorCode == '530036', yes.)
```
